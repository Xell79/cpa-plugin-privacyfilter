package main

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func resetABIStateForTest(t *testing.T) {
	t.Helper()
	privacyFilterABIState.Lock()
	privacyFilterABIState.plugin = nil
	privacyFilterABIState.shuttingDown = false
	privacyFilterABIState.host = nil
	privacyFilterABIState.Unlock()
	t.Cleanup(func() {
		privacyFilterABIState.inFlight.Wait()
		privacyFilterABIState.Lock()
		privacyFilterABIState.plugin = nil
		privacyFilterABIState.shuttingDown = false
		privacyFilterABIState.host = nil
		privacyFilterABIState.Unlock()
	})
}

func registerForTest(t *testing.T, hostSchema uint32) abiRegistration {
	t.Helper()
	req, err := json.Marshal(abiLifecycleRequest{
		SchemaVersion: hostSchema,
		PluginDir:     t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := handlePrivacyFilterRegister(req)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	var env abiEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if !env.OK {
		t.Fatalf("registration envelope not OK: %s", raw)
	}
	var reg abiRegistration
	if err := json.Unmarshal(env.Result, &reg); err != nil {
		t.Fatalf("decode registration: %v", err)
	}
	return reg
}

func TestNegotiateSchemaVersion(t *testing.T) {
	tests := []struct {
		name string
		host uint32
		want uint32
	}{
		{name: "legacy omitted", host: 0, want: 1},
		{name: "legacy explicit", host: 1, want: 1},
		{name: "minimum active termination", host: 2, want: 2},
		{name: "newer host capped", host: pluginabi.SchemaVersion, want: 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := negotiateSchemaVersion(tc.host); got != tc.want {
				t.Fatalf("negotiateSchemaVersion(%d) = %d, want %d", tc.host, got, tc.want)
			}
		})
	}
}

func TestRegistrationNegotiatesLifecycleCapability(t *testing.T) {
	for _, tc := range []struct {
		name          string
		hostSchema    uint32
		wantSchema    uint32
		wantLifecycle bool
	}{
		{name: "legacy", hostSchema: 1, wantSchema: 1, wantLifecycle: false},
		{name: "schema two", hostSchema: 2, wantSchema: 2, wantLifecycle: true},
		{name: "current host", hostSchema: pluginabi.SchemaVersion, wantSchema: 2, wantLifecycle: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetABIStateForTest(t)
			reg := registerForTest(t, tc.hostSchema)
			if reg.SchemaVersion != tc.wantSchema {
				t.Fatalf("schema = %d, want %d", reg.SchemaVersion, tc.wantSchema)
			}
			if !reg.Capabilities.RequestInterceptor {
				t.Fatal("request interceptor capability missing")
			}
			if reg.Capabilities.RequestLifecyclePlugin != tc.wantLifecycle {
				t.Fatalf("lifecycle capability = %v, want %v", reg.Capabilities.RequestLifecyclePlugin, tc.wantLifecycle)
			}
		})
	}
}

func TestRequestCompleteDispatch(t *testing.T) {
	resetABIStateForTest(t)
	registerForTest(t, 2)
	req, err := json.Marshal(pluginapi.RequestCompletion{
		RequestID: "request-1",
		Outcome:   pluginapi.RequestCompletionSucceeded,
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := handlePrivacyFilterABIMethod(context.Background(), pluginabi.MethodRequestComplete, req)
	if err != nil {
		t.Fatalf("request.complete: %v", err)
	}
	var env abiEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	if !env.OK {
		t.Fatalf("request.complete envelope not OK: %s", raw)
	}
}

func TestQuiesceStopsNewCallsUntilRegister(t *testing.T) {
	resetABIStateForTest(t)
	registerForTest(t, 2)
	if _, err := handlePrivacyFilterQuiesce(); err != nil {
		t.Fatalf("quiesce: %v", err)
	}
	if _, _, err := beginPrivacyFilterPluginCall(); err == nil {
		t.Fatal("begin call succeeded while quiesced")
	}

	registerForTest(t, 2)
	_, done, err := beginPrivacyFilterPluginCall()
	if err != nil {
		t.Fatalf("begin call after re-register: %v", err)
	}
	done()
}

func TestABIPanicEnvelopeFailsClosedForRequestInterceptors(t *testing.T) {
	for _, method := range []string{
		pluginabi.MethodRequestInterceptBefore,
		pluginabi.MethodRequestInterceptAfter,
	} {
		raw := abiPanicEnvelope(method)
		var env abiEnvelope
		if err := json.Unmarshal(raw, &env); err != nil {
			t.Fatal(err)
		}
		if !env.OK {
			t.Fatalf("panic envelope is not an OK response: %s", raw)
		}
		var resp pluginapi.RequestInterceptResponse
		if err := json.Unmarshal(env.Result, &resp); err != nil {
			t.Fatal(err)
		}
		if !resp.Terminate || resp.StatusCode != 503 {
			t.Fatalf("panic response = %+v, want terminate 503", resp)
		}
		if got := resp.ResponseHeaders.Get("Content-Type"); got != "application/json" {
			t.Fatalf("Content-Type = %q", got)
		}
	}
}

func TestABIFailureEnvelopeTerminatesRequest(t *testing.T) {
	raw := abiFailureEnvelope(
		pluginabi.MethodRequestInterceptBefore,
		413,
		"request_too_large",
		"privacy filter request payload exceeds the native plugin limit",
	)
	var env abiEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	if !env.OK {
		t.Fatalf("failure envelope is not an OK response: %s", raw)
	}
	var resp pluginapi.RequestInterceptResponse
	if err := json.Unmarshal(env.Result, &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Terminate || resp.StatusCode != 413 {
		t.Fatalf("response = %+v, want terminate 413", resp)
	}
	if got := string(resp.ResponseBody); got == "" || !json.Valid(resp.ResponseBody) {
		t.Fatalf("response body is not valid JSON: %q", got)
	}
}

func TestABIFailureEnvelopeUsesPluginErrorOutsideRequest(t *testing.T) {
	raw := abiFailureEnvelope(pluginabi.MethodPluginRegister, 503, "plugin_error", "safe message")
	var env abiEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	if env.OK || env.Error == nil || env.Error.Code != "plugin_error" {
		t.Fatalf("unexpected envelope: %s", raw)
	}
}

func TestBuildPluginDeclaresImplementedSchema(t *testing.T) {
	plugin, err := buildPlugin(nil, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if plugin.SchemaVersion != implementedSchemaVersion {
		t.Fatalf("schema = %d, want %d", plugin.SchemaVersion, implementedSchemaVersion)
	}
	if plugin.Capabilities.RequestLifecyclePlugin == nil {
		t.Fatal("lifecycle capability missing")
	}
}
