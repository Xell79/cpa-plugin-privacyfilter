#define _POSIX_C_SOURCE 200809L

#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "privacyfilter.h"

typedef int (*plugin_init_fn)(cliproxy_host_api *, cliproxy_plugin_api *);

static void fail(const char *check) {
    fprintf(stderr, "native ABI check failed: %s\n", check);
    exit(1);
}

static void require_true(int condition, const char *check) {
    if (!condition) {
        fail(check);
    }
}

static int host_call(void *host_ctx, const char *method, const uint8_t *request,
                     size_t request_len, cliproxy_buffer *response) {
    (void)host_ctx;
    (void)method;
    (void)request;
    (void)request_len;
    if (response != NULL) {
        response->ptr = NULL;
        response->len = 0;
    }
    return 1;
}

static void host_free(void *ptr, size_t len) {
    (void)len;
    free(ptr);
}

static char *take_response(cliproxy_plugin_api *plugin, cliproxy_buffer *response) {
    require_true(response->ptr != NULL, "response pointer");
    require_true(response->len > 0 && response->len <= (8U << 20), "response length");
    char *text = malloc(response->len + 1);
    require_true(text != NULL, "response copy allocation");
    memcpy(text, response->ptr, response->len);
    text[response->len] = '\0';
    plugin->free_buffer(response->ptr, response->len);
    response->ptr = NULL;
    response->len = 0;
    return text;
}

static char *call_with(cliproxy_plugin_api *plugin, const char *method,
                       const uint8_t *request, size_t request_len) {
    cliproxy_buffer response = {0};
    int status = plugin->call((char *)method, (uint8_t *)request, request_len, &response);
    require_true(status == 0, "plugin call status");
    return take_response(plugin, &response);
}

static void require_contains(const char *response, const char *needle,
                             const char *check) {
    require_true(strstr(response, needle) != NULL, check);
}

int main(int argc, char **argv) {
    require_true(argc == 3, "library and version arguments");
    char version_needle[256];
    int version_length = snprintf(version_needle, sizeof(version_needle),
                                  "\"Version\":\"%s\"", argv[2]);
    require_true(version_length > 0 && (size_t)version_length < sizeof(version_needle),
                 "version argument length");
    void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (library == NULL) {
        fail("dlopen");
    }

    void *symbol = dlsym(library, "cliproxy_plugin_init");
    require_true(symbol != NULL, "init symbol");
    plugin_init_fn initialize = NULL;
    memcpy(&initialize, &symbol, sizeof(initialize));

    cliproxy_host_api host = {
        .abi_version = 1,
        .host_ctx = NULL,
        .call = host_call,
        .free_buffer = host_free,
    };
    cliproxy_plugin_api plugin = {0};
    require_true(initialize(&host, &plugin) == 0, "plugin init");
    require_true(plugin.abi_version == 1, "ABI version");
    require_true(plugin.call != NULL, "call table entry");
    require_true(plugin.free_buffer != NULL, "free table entry");
    require_true(plugin.shutdown != NULL, "shutdown table entry");

    const char register_request[] =
        "{\"config_yaml\":null,\"schema_version\":2,\"plugin_dir\":\"\"}";
    char *response = call_with(&plugin, "plugin.register",
                               (const uint8_t *)register_request,
                               strlen(register_request));
    require_contains(response, "\"ok\":true", "registration envelope");
    require_contains(response, "\"schema_version\":2", "schema negotiation");
    require_contains(response, "\"Name\":\"privacyfilter\"", "plugin name");
    require_contains(response, version_needle, "plugin version");
    require_contains(response, "\"request_interceptor\":true", "interceptor capability");
    require_contains(response, "\"request_lifecycle_plugin\":true", "lifecycle capability");
    free(response);

    uint8_t one_byte = 0;
    response = call_with(&plugin, "request.intercept_before", &one_byte,
                         (size_t)(64U << 20) + 1U);
    require_contains(response, "\"Terminate\":true", "oversize termination");
    require_contains(response, "\"StatusCode\":413", "oversize status");
    free(response);

    response = call_with(&plugin, "request.intercept_before", NULL, 1);
    require_contains(response, "\"Terminate\":true", "nil-buffer termination");
    require_contains(response, "\"StatusCode\":503", "nil-buffer status");
    free(response);

    const char empty_body_request[] =
        "{\"RequestID\":\"native-check\",\"SourceFormat\":\"openai\",\"Body\":null}";
    response = call_with(&plugin, "request.intercept_before",
                         (const uint8_t *)empty_body_request,
                         strlen(empty_body_request));
    require_contains(response, "\"Terminate\":true", "empty-body termination");
    require_contains(response, "\"StatusCode\":400", "empty-body status");
    free(response);

    const char completion_request[] =
        "{\"RequestID\":\"native-check\",\"Outcome\":\"rejected\"}";
    response = call_with(&plugin, "request.complete",
                         (const uint8_t *)completion_request,
                         strlen(completion_request));
    require_contains(response, "\"ok\":true", "completion envelope");
    free(response);

    for (int iteration = 0; iteration < 128; iteration++) {
        response = call_with(&plugin, "unknown.method", NULL, 0);
        require_contains(response, "\"code\":\"unknown_method\"", "unknown method envelope");
        free(response);
    }

    cliproxy_buffer ignored = {0};
    require_true(plugin.call(NULL, NULL, 0, &ignored) == 0, "nil-method call status");
    response = take_response(&plugin, &ignored);
    require_contains(response, "\"code\":\"invalid_method\"", "nil-method envelope");
    free(response);
    require_true(plugin.call(NULL, NULL, 0, NULL) != 0, "nil-response call status");

    response = call_with(&plugin, "plugin.quiesce", NULL, 0);
    require_contains(response, "\"ok\":true", "quiesce envelope");
    free(response);

    response = call_with(&plugin, "request.intercept_after",
                         (const uint8_t *)empty_body_request,
                         strlen(empty_body_request));
    require_contains(response, "\"Terminate\":true", "quiesced termination");
    require_contains(response, "\"StatusCode\":503", "quiesced status");
    free(response);

    plugin.shutdown();
    require_true(dlclose(library) == 0, "dlclose");
    return 0;
}
