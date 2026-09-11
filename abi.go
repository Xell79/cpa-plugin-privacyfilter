package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef struct {
	void* ptr;
	size_t len;
} cliproxy_buffer;

typedef int (*cliproxy_host_call_fn)(void*, const char*, const uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_host_free_fn)(void*, size_t);

typedef struct {
	uint32_t abi_version;
	void* host_ctx;
	cliproxy_host_call_fn call;
	cliproxy_host_free_fn free_buffer;
} cliproxy_host_api;

typedef int (*cliproxy_plugin_call_fn)(char*, uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_plugin_free_fn)(void*, size_t);
typedef void (*cliproxy_plugin_shutdown_fn)(void);

typedef struct {
	uint32_t abi_version;
	cliproxy_plugin_call_fn call;
	cliproxy_plugin_free_fn free_buffer;
	cliproxy_plugin_shutdown_fn shutdown;
} cliproxy_plugin_api;

extern int PrivacyFilterPluginCall(char*, uint8_t*, size_t, cliproxy_buffer*);
extern void PrivacyFilterPluginFree(void*, size_t);
extern void PrivacyFilterPluginShutdown(void);

static int privacyfilter_call_host(cliproxy_host_api* api, const char* method, const uint8_t* request, size_t request_len, cliproxy_buffer* response) {
	return api->call(api->host_ctx, method, request, request_len, response);
}

static void privacyfilter_free_host_buffer(cliproxy_host_api* api, void* ptr, size_t len) {
	api->free_buffer(ptr, len);
}
*/
import "C"

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"sync"
	"unsafe"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

var privacyFilterABIState = struct {
	sync.RWMutex
	host         *C.cliproxy_host_api
	plugin       *privacyFilterPlugin
	runtime      *runtimeState
	shuttingDown bool
	inFlight     sync.WaitGroup
}{}

const (
	// implementedSchemaVersion is the newest RPC contract this plugin uses.
	// Schema 2 adds active request termination and request.complete lifecycle
	// notifications while keeping later response-stream omission semantics out
	// of this request-only implementation.
	implementedSchemaVersion uint32 = 2
	legacySchemaVersion      uint32 = 1

	// maxABIRequestBytes is checked before C.GoBytes duplicates the host payload.
	// Request bodies have their own tighter configurable limit at the walker.
	maxABIRequestBytes = C.size_t(64 << 20)
)

type abiEnvelope struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *abiError       `json:"error,omitempty"`
}

type abiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type abiLifecycleRequest struct {
	ConfigYAML    []byte `json:"config_yaml"`
	SchemaVersion uint32 `json:"schema_version"`
	// PluginDir was never part of the v7.2.157 host payload. Keep accepting it
	// for test harnesses and legacy hosts; production falls back to dladdr.
	PluginDir string `json:"plugin_dir,omitempty"`
}

type abiRequestInterceptRequest struct {
	pluginapi.RequestInterceptRequest
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

type abiRegistration struct {
	SchemaVersion uint32             `json:"schema_version"`
	Metadata      pluginapi.Metadata `json:"metadata"`
	Capabilities  abiCapabilities    `json:"capabilities"`
}

type abiCapabilities struct {
	RequestInterceptor     bool `json:"request_interceptor"`
	RequestLifecyclePlugin bool `json:"request_lifecycle_plugin"`
}

func main() {}

func inferPluginDir() string {
	sharedObjectPath := sharedLibraryPath()
	if sharedObjectPath == "" {
		return ""
	}
	return filepath.Dir(sharedObjectPath)
}

//export cliproxy_plugin_init
func cliproxy_plugin_init(host *C.cliproxy_host_api, plugin *C.cliproxy_plugin_api) C.int {
	if host == nil || plugin == nil {
		return 1
	}
	privacyFilterABIState.Lock()
	privacyFilterABIState.host = host
	privacyFilterABIState.shuttingDown = false
	privacyFilterABIState.Unlock()

	plugin.abi_version = C.uint32_t(pluginabi.ABIVersion)
	plugin.call = C.cliproxy_plugin_call_fn(C.PrivacyFilterPluginCall)
	plugin.free_buffer = C.cliproxy_plugin_free_fn(C.PrivacyFilterPluginFree)
	plugin.shutdown = C.cliproxy_plugin_shutdown_fn(C.PrivacyFilterPluginShutdown)
	return 0
}

//export PrivacyFilterPluginCall
func PrivacyFilterPluginCall(method *C.char, request *C.uint8_t, requestLen C.size_t, response *C.cliproxy_buffer) (result C.int) {
	if response != nil {
		response.ptr = nil
		response.len = 0
	}
	methodName := ""
	if method != nil {
		methodName = C.GoString(method)
	}
	defer func() {
		if recover() == nil {
			return
		}
		writeABIResponse(response, abiPanicEnvelope(methodName))
		result = 0
	}()

	if method == nil {
		writeABIResponse(response, abiErrorEnvelope("invalid_method", "method is required"))
		return 0
	}
	var requestBytes []byte
	if request != nil && requestLen > 0 {
		if requestLen > maxABIRequestBytes {
			writeABIResponse(response, abiFailureEnvelope(
				methodName,
				http.StatusRequestEntityTooLarge,
				"request_too_large",
				"privacy filter request payload exceeds the native plugin limit",
			))
			return 0
		}
		requestBytes = C.GoBytes(unsafe.Pointer(request), C.int(requestLen))
	}
	raw, errHandle := handlePrivacyFilterABIMethod(context.Background(), methodName, requestBytes)
	if errHandle != nil {
		message := "privacy filter could not safely inspect the request"
		if methodName == pluginabi.MethodPluginRegister || methodName == pluginabi.MethodPluginReconfigure {
			// Lifecycle errors contain only configuration/rule diagnostics and are
			// needed by operators to correct a plugin that cannot start. Request
			// interceptor failures stay generic because they may be input-derived.
			message = errHandle.Error()
		}
		writeABIResponse(response, abiFailureEnvelope(
			methodName,
			http.StatusServiceUnavailable,
			"plugin_error",
			message,
		))
		return 0
	}
	writeABIResponse(response, raw)
	return 0
}

//export PrivacyFilterPluginFree
func PrivacyFilterPluginFree(ptr unsafe.Pointer, _ C.size_t) {
	if ptr != nil {
		C.free(ptr)
	}
}

//export PrivacyFilterPluginShutdown
func PrivacyFilterPluginShutdown() {
	privacyFilterABIState.Lock()
	privacyFilterABIState.shuttingDown = true
	privacyFilterABIState.plugin = nil
	privacyFilterABIState.host = nil
	runtime := privacyFilterABIState.runtime
	privacyFilterABIState.Unlock()
	privacyFilterABIState.inFlight.Wait()
	if runtime != nil && runtime.cache != nil {
		runtime.cache.Clear()
	}
	privacyFilterABIState.Lock()
	if privacyFilterABIState.runtime == runtime {
		privacyFilterABIState.runtime = nil
	}
	privacyFilterABIState.Unlock()
}

func handlePrivacyFilterABIMethod(ctx context.Context, method string, request []byte) ([]byte, error) {
	switch method {
	case pluginabi.MethodPluginRegister, pluginabi.MethodPluginReconfigure:
		return handlePrivacyFilterRegister(request)
	case pluginabi.MethodPluginQuiesce:
		return handlePrivacyFilterQuiesce()
	case pluginabi.MethodRequestComplete:
		return handlePrivacyFilterRequestComplete(ctx, request)
	}

	p, done, errPlugin := beginPrivacyFilterPluginCall()
	if errPlugin != nil {
		return nil, errPlugin
	}
	defer done()

	switch method {
	case pluginabi.MethodRequestInterceptBefore:
		var req abiRequestInterceptRequest
		if errDecode := json.Unmarshal(request, &req); errDecode != nil {
			return nil, errDecode
		}
		resp, errCall := p.InterceptRequestBeforeAuth(ctx, req.RequestInterceptRequest)
		return abiOKEnvelopeWithError(resp, errCall)
	case pluginabi.MethodRequestInterceptAfter:
		var req abiRequestInterceptRequest
		if errDecode := json.Unmarshal(request, &req); errDecode != nil {
			return nil, errDecode
		}
		resp, errCall := p.InterceptRequestAfterAuth(ctx, req.RequestInterceptRequest)
		return abiOKEnvelopeWithError(resp, errCall)
	default:
		return abiErrorEnvelope("unknown_method", "unknown method: "+method), nil
	}
}

// request.complete remains accepted while quiesced. It only touches the
// concurrency-safe runtime cache, so it cannot start new interceptor work or
// race plugin teardown, and late lifecycle notifications still release state.
func handlePrivacyFilterRequestComplete(_ context.Context, request []byte) ([]byte, error) {
	var req pluginapi.RequestCompletion
	if errDecode := json.Unmarshal(request, &req); errDecode != nil {
		return nil, errDecode
	}
	privacyFilterABIState.RLock()
	runtime := privacyFilterABIState.runtime
	privacyFilterABIState.RUnlock()
	if runtime != nil {
		releaseRequestScanState(runtime.cache, req)
	}
	return abiOKEnvelope(struct{}{})
}

func handlePrivacyFilterRegister(request []byte) ([]byte, error) {
	var req abiLifecycleRequest
	if errDecode := json.Unmarshal(request, &req); errDecode != nil {
		return nil, errDecode
	}
	privacyFilterABIState.Lock()
	if privacyFilterABIState.runtime == nil {
		privacyFilterABIState.runtime = newRuntimeState()
	}
	runtime := privacyFilterABIState.runtime
	privacyFilterABIState.Unlock()

	plugin, errBuild := buildPluginWithRuntime(req.ConfigYAML, req.PluginDir, runtime)
	if errBuild != nil {
		return nil, errBuild
	}
	p, ok := plugin.Capabilities.RequestInterceptor.(*privacyFilterPlugin)
	if !ok || p == nil {
		return nil, fmt.Errorf("privacyfilter plugin registration returned invalid interceptor")
	}
	negotiatedSchema := negotiateSchemaVersion(req.SchemaVersion)
	if negotiatedSchema < implementedSchemaVersion &&
		(p.cfg.OnError == onErrorBlock || len(p.blockRuleIDs) > 0) {
		return nil, fmt.Errorf("privacyfilter: fail-closed mode requires host schema %d or newer", implementedSchemaVersion)
	}
	plugin.SchemaVersion = negotiatedSchema
	if negotiatedSchema < implementedSchemaVersion {
		plugin.Capabilities.RequestLifecyclePlugin = nil
	}
	privacyFilterABIState.Lock()
	privacyFilterABIState.plugin = p
	privacyFilterABIState.shuttingDown = false
	privacyFilterABIState.Unlock()
	return abiOKEnvelope(abiRegistration{
		SchemaVersion: negotiatedSchema,
		Metadata:      plugin.Metadata,
		Capabilities: abiCapabilities{
			RequestInterceptor:     plugin.Capabilities.RequestInterceptor != nil,
			RequestLifecyclePlugin: plugin.Capabilities.RequestLifecyclePlugin != nil,
		},
	})
}

func negotiateSchemaVersion(hostSchema uint32) uint32 {
	if hostSchema == 0 {
		hostSchema = legacySchemaVersion
	}
	if hostSchema < implementedSchemaVersion {
		return hostSchema
	}
	return implementedSchemaVersion
}

func handlePrivacyFilterQuiesce() ([]byte, error) {
	privacyFilterABIState.Lock()
	privacyFilterABIState.shuttingDown = true
	privacyFilterABIState.Unlock()
	privacyFilterABIState.inFlight.Wait()
	return abiOKEnvelope(struct{}{})
}

func beginPrivacyFilterPluginCall() (*privacyFilterPlugin, func(), error) {
	privacyFilterABIState.Lock()
	defer privacyFilterABIState.Unlock()
	if privacyFilterABIState.shuttingDown {
		return nil, nil, fmt.Errorf("privacyfilter plugin is shutting down")
	}
	if privacyFilterABIState.plugin == nil {
		return nil, nil, fmt.Errorf("privacyfilter plugin is not registered")
	}
	privacyFilterABIState.inFlight.Add(1)
	return privacyFilterABIState.plugin, privacyFilterABIState.inFlight.Done, nil
}

func abiOKEnvelopeWithError(v any, err error) ([]byte, error) {
	if err != nil {
		return nil, err
	}
	return abiOKEnvelope(v)
}

func abiOKEnvelope(v any) ([]byte, error) {
	raw, errMarshal := json.Marshal(v)
	if errMarshal != nil {
		return nil, errMarshal
	}
	return json.Marshal(abiEnvelope{OK: true, Result: raw})
}

func abiErrorEnvelope(code, message string) []byte {
	raw, _ := json.Marshal(abiEnvelope{OK: false, Error: &abiError{Code: code, Message: message}})
	return raw
}

func abiPanicEnvelope(method string) []byte {
	return abiFailureEnvelope(
		method,
		http.StatusServiceUnavailable,
		"plugin_panic",
		"privacy filter recovered an internal panic and failed closed",
	)
}

func abiFailureEnvelope(method string, status int, code, message string) []byte {
	if method == pluginabi.MethodRequestInterceptBefore || method == pluginabi.MethodRequestInterceptAfter {
		body, _ := json.Marshal(map[string]any{
			"error": map[string]string{
				"type":    code,
				"message": message,
			},
		})
		raw, err := abiOKEnvelope(pluginapi.RequestInterceptResponse{
			Terminate:       true,
			StatusCode:      status,
			ResponseHeaders: http.Header{"Content-Type": []string{"application/json"}},
			ResponseBody:    body,
		})
		if err == nil {
			return raw
		}
	}
	return abiErrorEnvelope(code, message)
}

func writeABIResponse(response *C.cliproxy_buffer, raw []byte) {
	if response == nil || len(raw) == 0 {
		return
	}
	ptr := C.CBytes(raw)
	if ptr == nil {
		return
	}
	response.ptr = ptr
	response.len = C.size_t(len(raw))
}
