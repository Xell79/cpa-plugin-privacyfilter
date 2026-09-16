// SPDX-License-Identifier: MIT
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifndef PROBE_ID
#define PROBE_ID "order-probe"
#endif

#ifndef PROBE_KIND
#define PROBE_KIND 0
#endif

typedef struct {
    void *ptr;
    size_t len;
} cliproxy_buffer;

typedef int (*cliproxy_host_call_fn)(void *, const char *, const uint8_t *, size_t,
                                     cliproxy_buffer *);
typedef void (*cliproxy_host_free_fn)(void *, size_t);

typedef struct {
    uint32_t abi_version;
    void *host_ctx;
    cliproxy_host_call_fn call;
    cliproxy_host_free_fn free_buffer;
} cliproxy_host_api;

typedef int (*cliproxy_plugin_call_fn)(char *, uint8_t *, size_t,
                                       cliproxy_buffer *);
typedef void (*cliproxy_plugin_free_fn)(void *, size_t);
typedef void (*cliproxy_plugin_shutdown_fn)(void);

typedef struct {
    uint32_t abi_version;
    cliproxy_plugin_call_fn call;
    cliproxy_plugin_free_fn free_buffer;
    cliproxy_plugin_shutdown_fn shutdown;
} cliproxy_plugin_api;

static const char registration_response[] =
    "{\"ok\":true,\"result\":{\"schema_version\":2,\"metadata\":{"
    "\"Name\":\"" PROBE_ID "\",\"Version\":\"1.0.0\","
    "\"Author\":\"privacyfilter integration fixture\","
    "\"GitHubRepository\":\"https://github.com/ahoo/cpa-plugin-privacyfilter\"},"
    "\"capabilities\":{\"request_interceptor\":true}}}";

static const char empty_response[] = "{\"ok\":true,\"result\":{}}";
#if PROBE_KIND == 1
static const char high_before_response[] =
    "{\"ok\":true,\"result\":{\"Headers\":{\"X-Order-Before\":[\"high\"]}}}";
static const char high_after_response[] =
    "{\"ok\":true,\"result\":{\"Headers\":{\"X-Order-After\":[\"high\"]}}}";
#elif PROBE_KIND == 2
static const char low_before_response[] =
    "{\"ok\":true,\"result\":{\"Headers\":{\"X-Order-Before\":[\"high,low\"]},"
    "\"Body\":\"eyJtb2RlbCI6Im1vY2stbW9kZWwiLCJtZXNzYWdlcyI6W3sicm9sZSI6ImFzc2lzdGFudCIsInRvb2xfY2FsbHMiOlt7ImlkIjoiYmVmb3JlLXByb2JlIiwidHlwZSI6ImZ1bmN0aW9uIiwiZnVuY3Rpb24iOnsibmFtZSI6InByb2JlIiwiYXJndW1lbnRzIjoie1wiYXBpX2tleVwiOlwicTd6XCJ9In19XX1dfQ==\"}}";
static const char low_after_response[] =
    "{\"ok\":true,\"result\":{\"Headers\":{\"X-Order-After\":[\"high,low\"]},"
    "\"Body\":\"eyJtb2RlbCI6Im1vY2stbW9kZWwiLCJtZXNzYWdlcyI6W3sicm9sZSI6ImFzc2lzdGFudCIsInRvb2xfY2FsbHMiOlt7ImlkIjoiYWZ0ZXItcHJvYmUiLCJ0eXBlIjoiZnVuY3Rpb24iLCJmdW5jdGlvbiI6eyJuYW1lIjoicHJvYmUiLCJhcmd1bWVudHMiOiJ7XCJhcGlfa2V5XCI6XCJxN3pcIn0ifX1dfV19\"}}";
// This exact serialized body is intentionally pinned to the exact official Host
// identity in run.sh. A serialization change must fail closed and be reviewed.
static const char redacted_before_body[] =
    "eyJtb2RlbCI6Im1vY2stbW9kZWwiLCJtZXNzYWdlcyI6W3sicm9sZSI6ImFzc2lzdGFudCIsInRvb2xfY2FsbHMiOlt7ImlkIjoiYmVmb3JlLXByb2JlIiwidHlwZSI6ImZ1bmN0aW9uIiwiZnVuY3Rpb24iOnsibmFtZSI6InByb2JlIiwiYXJndW1lbnRzIjoie1wiYXBpX2tleVwiOlwiW+WvhumSpV1cIn0ifX1dfV19";
static const char low_before_block_response[] =
    "{\"ok\":true,\"result\":{\"Headers\":{\"X-Order-Before\":[\"high,low\"]}}}";
static const char low_after_block_response[] =
    "{\"ok\":true,\"result\":{\"Headers\":{\"X-Order-After\":[\"high,low\"]}}}";
static const char order_failure_response[] =
    "{\"ok\":true,\"result\":{\"Terminate\":true,\"StatusCode\":503,"
    "\"ResponseHeaders\":{\"Content-Type\":[\"application/json\"]},"
    "\"ResponseBody\":\"e30=\"}}";
#else
#error "PROBE_KIND must be 1 or 2"
#endif
static const char unknown_response[] =
    "{\"ok\":false,\"error\":{\"code\":\"unknown_method\","
    "\"message\":\"unsupported integration fixture method\"}}";

#if PROBE_KIND == 2
static int contains_bytes(const uint8_t *haystack, size_t haystack_len,
                          const char *needle) {
    size_t needle_len = strlen(needle);
    if (haystack == NULL || needle_len == 0 || needle_len > haystack_len) {
        return 0;
    }
    for (size_t offset = 0; offset <= haystack_len - needle_len; offset++) {
        if (memcmp(haystack + offset, needle, needle_len) == 0) {
            return 1;
        }
    }
    return 0;
}
#endif

static int write_response(const char *text, cliproxy_buffer *response) {
    if (text == NULL || response == NULL) {
        return 1;
    }
    size_t length = strlen(text);
    void *copy = malloc(length);
    if (copy == NULL) {
        response->ptr = NULL;
        response->len = 0;
        return 1;
    }
    memcpy(copy, text, length);
    response->ptr = copy;
    response->len = length;
    return 0;
}

static int probe_call(char *method, uint8_t *request, size_t request_len,
                      cliproxy_buffer *response) {
    // The native ABI defines method as a NUL-terminated C string.
    if (method == NULL || response == NULL) {
        return 1;
    }
    if (strcmp(method, "plugin.register") == 0 ||
        strcmp(method, "plugin.reconfigure") == 0) {
        return write_response(registration_response, response);
    }
    if (strcmp(method, "plugin.quiesce") == 0 ||
        strcmp(method, "request.complete") == 0) {
        return write_response(empty_response, response);
    }
    if (strcmp(method, "request.intercept_before") == 0) {
#if PROBE_KIND == 1
        (void)request;
        (void)request_len;
        return write_response(high_before_response, response);
#elif PROBE_KIND == 2
        if (!contains_bytes(request, request_len, "X-Order-Before") ||
            !contains_bytes(request, request_len, "high")) {
            return write_response(order_failure_response, response);
        }
        if (contains_bytes(request, request_len, "X-Harness-Block")) {
            return write_response(low_before_block_response, response);
        }
        return write_response(low_before_response, response);
#endif
    }
    if (strcmp(method, "request.intercept_after") == 0) {
#if PROBE_KIND == 1
        (void)request;
        (void)request_len;
        return write_response(high_after_response, response);
#elif PROBE_KIND == 2
        if (!contains_bytes(request, request_len, "X-Order-After") ||
            !contains_bytes(request, request_len, "high")) {
            return write_response(order_failure_response, response);
        }
        // Non-Chat protocol canaries preserve their original body while still
        // proving that the high-priority interceptor ran before this probe.
        if (contains_bytes(request, request_len, "X-Harness-Block")) {
            return write_response(low_after_block_response, response);
        }
        if (!contains_bytes(request, request_len, redacted_before_body)) {
            return write_response(order_failure_response, response);
        }
        return write_response(low_after_response, response);
#endif
    }
    return write_response(unknown_response, response);
}

static void probe_free(void *pointer, size_t length) {
    (void)length;
    free(pointer);
}

static void probe_shutdown(void) {}

#if defined(_WIN32)
__declspec(dllexport)
#endif
int cliproxy_plugin_init(cliproxy_host_api *host, cliproxy_plugin_api *plugin) {
    if (host == NULL || plugin == NULL || host->abi_version != 1 ||
        host->call == NULL || host->free_buffer == NULL) {
        return 1;
    }
    plugin->abi_version = 1;
    plugin->call = probe_call;
    plugin->free_buffer = probe_free;
    plugin->shutdown = probe_shutdown;
    return 0;
}
