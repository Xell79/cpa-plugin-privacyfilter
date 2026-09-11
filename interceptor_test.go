package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/internal/privacyengine"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func newTestPlugin(t *testing.T) *privacyFilterPlugin {
	t.Helper()
	cfg := defaultConfig()
	engine, report, err := privacyengine.New(privacyengine.Config{
		EmbeddedTOML:          embeddedGitleaks,
		EmbeddedCompatibility: privacyengine.CompatibilitySkipUnsupported,
		DefaultLimits:         cfg.engineLimits(),
	})
	if err != nil {
		t.Fatalf("privacyengine.New() error = %v (report=%+v)", err, report)
	}
	renderer, err := cfg.renderer()
	if err != nil {
		t.Fatal(err)
	}
	return &privacyFilterPlugin{
		cfg:          cfg,
		engine:       engine,
		renderer:     renderer,
		blockRuleIDs: cfg.blockRuleSet(),
		cache: NewRequestScanCache(RequestScanCacheOptions{
			TTL:        defaultRequestCacheTTL,
			MaxEntries: 32,
		}),
		revision: 1,
	}
}

func redactForTest(t *testing.T, p *privacyFilterPlugin, sourceFormat, body string) ([]byte, int, error) {
	t.Helper()
	result, err := p.sanitizeRequest(context.Background(), sourceFormat, []byte(body))
	if err != nil {
		return nil, 0, err
	}
	if !result.changed {
		return nil, result.findings, nil
	}
	return result.body, result.findings, nil
}

func TestRedactRequestBody_EmailInContent(t *testing.T) {
	p := newTestPlugin(t)
	body := `{"model":"gpt-4","messages":[{"role":"user","content":"my email is test@example.com"}]}`
	modified, findings, err := redactForTest(t, p, "openai", body)
	if err != nil {
		t.Fatalf("redactRequestBody() error = %v", err)
	}
	if findings != 1 || modified == nil {
		t.Fatalf("findings=%d modified=%v, want one redaction", findings, modified != nil)
	}
	if !strings.Contains(string(modified), "[邮箱]") || strings.Contains(string(modified), "test@example.com") {
		t.Fatalf("email was not safely redacted: %s", modified)
	}
}

func TestRedactRequestBody_NoPII(t *testing.T) {
	p := newTestPlugin(t)
	body := `{"model":"gpt-4","messages":[{"role":"user","content":"hello world"}]}`
	modified, findings, err := redactForTest(t, p, "openai", body)
	if err != nil {
		t.Fatalf("redactRequestBody() error = %v", err)
	}
	if findings != 0 || modified != nil {
		t.Fatalf("findings=%d modified=%s, want unchanged", findings, modified)
	}
}

func TestRedactRequestBody_MultiPartContent(t *testing.T) {
	p := newTestPlugin(t)
	body := `{"model":"gpt-4","messages":[{"role":"user","content":[{"type":"text","text":"my phone is 13800138000"}]}]}`
	modified, findings, err := redactForTest(t, p, "openai", body)
	if err != nil {
		t.Fatalf("redactRequestBody() error = %v", err)
	}
	if findings != 1 || modified == nil || strings.Contains(string(modified), "13800138000") {
		t.Fatalf("phone was not safely redacted: findings=%d body=%s", findings, modified)
	}
}

func TestRedactRequestBody_ResponsesStringInput(t *testing.T) {
	p := newTestPlugin(t)
	body := `{"model":"gpt-4","input":"my email is test@example.com"}`
	modified, findings, err := redactForTest(t, p, "openai-response", body)
	if err != nil {
		t.Fatalf("redactRequestBody() error = %v", err)
	}
	if findings != 1 || modified == nil || strings.Contains(string(modified), "test@example.com") {
		t.Fatalf("email was not safely redacted: findings=%d body=%s", findings, modified)
	}
}

func TestRedactRequestBody_PreservesLargeInteger(t *testing.T) {
	p := newTestPlugin(t)
	body := `{"id":9007199254740993,"messages":[{"role":"user","content":"test@example.com"}]}`
	modified, _, err := redactForTest(t, p, "openai", body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(modified), `"id":9007199254740993`) {
		t.Fatalf("large integer changed: %s", modified)
	}
}

func TestInterceptRequest_SkippedModel(t *testing.T) {
	p := newTestPlugin(t)
	p.cfg.SkipModels = []string{"gpt-4"}
	body := `{"model":"gpt-4","messages":[{"role":"user","content":"test@example.com"}]}`
	resp, err := p.interceptRequest(context.Background(), pluginapi.RequestInterceptRequest{
		Model: "gpt-4",
		Body:  []byte(body),
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Body != nil || resp.Terminate {
		t.Fatalf("skipped model did not pass through: %+v", resp)
	}
}

func TestInterceptRequest_SkippedRequestedModel(t *testing.T) {
	p := newTestPlugin(t)
	p.cfg.SkipModels = []string{"gpt-4"}
	body := `{"model":"upstream-model","messages":[{"role":"user","content":"test@example.com"}]}`
	resp, err := p.interceptRequest(context.Background(), pluginapi.RequestInterceptRequest{
		Model:          "upstream-model",
		RequestedModel: "gpt-4",
		Body:           []byte(body),
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Body != nil || resp.Terminate {
		t.Fatalf("skipped requested model did not pass through: %+v", resp)
	}
}

func TestInterceptRequestAfterAuth_RedactsFinalRequest(t *testing.T) {
	p := newTestPlugin(t)
	body := `{"model":"gpt-4","messages":[{"role":"user","content":"test@example.com"}]}`
	resp, err := p.InterceptRequestAfterAuth(context.Background(), pluginapi.RequestInterceptRequest{
		SourceFormat: "openai",
		Model:        "gpt-4",
		Body:         []byte(body),
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Body == nil || resp.Terminate || strings.Contains(string(resp.Body), "test@example.com") {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestInterceptRequestBeforeAuth_Passthrough(t *testing.T) {
	p := newTestPlugin(t)
	body := `{"model":"gpt-4","messages":[{"role":"user","content":"normal text"}]}`
	resp, err := p.InterceptRequestBeforeAuth(context.Background(), pluginapi.RequestInterceptRequest{
		SourceFormat: "openai",
		Body:         []byte(body),
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Body != nil || resp.Terminate {
		t.Fatalf("normal request changed: %+v", resp)
	}
}

func TestRedactRequestBody_SecretDetectionUsesEmbeddedRules(t *testing.T) {
	p := newTestPlugin(t)
	const key = "LTAIABCDEFGHIJKLMNOPQRST"
	body := `{"model":"gpt-4","messages":[{"role":"user","content":"` + key + `"}]}`
	modified, findings, err := redactForTest(t, p, "openai", body)
	if err != nil {
		t.Fatal(err)
	}
	if findings != 1 || modified == nil || strings.Contains(string(modified), key) {
		t.Fatalf("Alibaba key was not redacted: findings=%d body=%s", findings, modified)
	}
}

func TestInterceptRequest_InvalidJSONFailsClosed(t *testing.T) {
	p := newTestPlugin(t)
	for _, body := range [][]byte{
		nil,
		[]byte(`not valid json with email test@example.com`),
	} {
		resp, err := p.InterceptRequestBeforeAuth(context.Background(), pluginapi.RequestInterceptRequest{
			SourceFormat: "openai",
			Body:         body,
		})
		if err != nil {
			t.Fatal(err)
		}
		if !resp.Terminate || resp.StatusCode != 400 {
			t.Fatalf("invalid JSON response = %+v, want terminate 400", resp)
		}
	}
}

func TestInterceptRequest_InvalidJSONCanExplicitlyPassThrough(t *testing.T) {
	p := newTestPlugin(t)
	p.cfg.OnError = onErrorPassthrough
	resp, err := p.InterceptRequestBeforeAuth(context.Background(), pluginapi.RequestInterceptRequest{
		SourceFormat: "openai",
		Body:         []byte(`not valid json`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Terminate || resp.Body != nil {
		t.Fatalf("passthrough response = %+v", resp)
	}
}

func TestBlockingRuleTerminatesWithoutReturningBody(t *testing.T) {
	p := newTestPlugin(t)
	p.blockRuleIDs = map[string]struct{}{"alibaba-access-key-id": {}}
	resp, err := p.InterceptRequestBeforeAuth(context.Background(), pluginapi.RequestInterceptRequest{
		SourceFormat: "openai",
		Body:         []byte(`{"model":"gpt-4","messages":[{"role":"user","content":"LTAIABCDEFGHIJKLMNOPQRST"}]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Terminate || resp.StatusCode != 422 || resp.Body != nil {
		t.Fatalf("block response = %+v", resp)
	}
}

func TestBlockingRuleWinsWhenItsSpanOverlapsPII(t *testing.T) {
	p := newTestPlugin(t)
	engine, report, err := privacyengine.New(privacyengine.Config{
		CustomTOML: []byte(`
[[rules]]
id = "block-email"
regex = '''[a-z]+@example\.com'''
keywords = ["@example."]
`),
		CustomMode: privacyengine.CustomRulesReplace,
	})
	if err != nil {
		t.Fatalf("privacyengine.New(): %v (report=%+v)", err, report)
	}
	p.engine = engine
	p.blockRuleIDs = map[string]struct{}{"block-email": {}}

	resp, err := p.InterceptRequestBeforeAuth(context.Background(), pluginapi.RequestInterceptRequest{
		SourceFormat: "openai",
		Body:         []byte(`{"messages":[{"role":"user","content":"test@example.com"}]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Terminate || resp.StatusCode != 422 || resp.Body != nil {
		t.Fatalf("overlapping block response = %+v", resp)
	}
}

func TestAuditModeDetectsWithoutMutation(t *testing.T) {
	p := newTestPlugin(t)
	p.cfg.Mode = modeAudit
	resp, err := p.InterceptRequestBeforeAuth(context.Background(), pluginapi.RequestInterceptRequest{
		SourceFormat: "openai",
		Body:         []byte(`{"model":"gpt-4","messages":[{"role":"user","content":"test@example.com"}]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Terminate || resp.Body != nil {
		t.Fatalf("audit response = %+v", resp)
	}
}

func TestConfigShouldSkip(t *testing.T) {
	cfg := defaultConfig()
	cfg.SkipModels = []string{"gpt-4", "claude-3"}
	cfg.SkipFormats = []string{"openai"}
	if !cfg.shouldSkip("gpt-4", "", "") {
		t.Fatal("should skip gpt-4")
	}
	if !cfg.shouldSkip("upstream-model", "claude-3", "") {
		t.Fatal("should skip requested claude-3")
	}
	if !cfg.shouldSkip("", "", "openai") {
		t.Fatal("should skip openai format")
	}
	if cfg.shouldSkip("gemini-pro", "", "claude") {
		t.Fatal("should not skip unknown model/format")
	}
}

func TestProtocolRedactionEndToEnd(t *testing.T) {
	const secret = "LTAIABCDEFGHIJKLMNOPQRST"
	tests := []struct {
		name   string
		format string
		body   string
	}{
		{
			name:   "openai chat",
			format: "openai",
			body: `{"model":"m","messages":[` +
				`{"role":"system","content":"` + secret + `"},` +
				`{"role":"assistant","content":"ok","tool_calls":[{"id":"c1","type":"function","function":{"name":"f","arguments":"{\"ak\":\"` + secret + `\",\"n\":9007199254740993}"}}]},` +
				`{"role":"tool","tool_call_id":"c1","content":"` + secret + `"}]}`,
		},
		{
			name:   "openai responses",
			format: "openai-response",
			body: `{"model":"m","instructions":"` + secret + `","input":[` +
				`{"type":"message","role":"user","content":"` + secret + `"},` +
				`{"type":"function_call","name":"f","arguments":"{\"ak\":\"` + secret + `\"}"},` +
				`{"type":"function_call_output","output":"{\"ak\":\"` + secret + `\"}"}]}`,
		},
		{
			name:   "anthropic",
			format: "claude",
			body: `{"model":"m","system":[{"type":"text","text":"` + secret + `"}],"messages":[` +
				`{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"f","input":{"ak":"` + secret + `"}}]},` +
				`{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":{"ak":"` + secret + `","id":"` + secret + `","name":"` + secret + `","signature":"` + secret + `","tool_use_id":"` + secret + `"}}]}]}`,
		},
		{
			name:   "gemini",
			format: "gemini",
			body: `{"systemInstruction":{"parts":[{"text":"` + secret + `"}]},"contents":[` +
				`{"role":"model","parts":[{"functionCall":{"name":"f","args":{"ak":"` + secret + `"}}}]},` +
				`{"role":"user","parts":[{"functionResponse":{"name":"f","response":{"ak":"` + secret + `"}}}]}]}`,
		},
		{
			name:   "interactions",
			format: "interactions",
			body: `{"system_instruction":"` + secret + `","input":[` +
				`{"type":"function_call","name":"f","arguments":{"ak":"` + secret + `"}},` +
				`{"type":"function_result","name":"f","result":{"ak":"` + secret + `"}},` +
				`{"type":"user_input","content":"` + secret + `"}]}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := newTestPlugin(t)
			result, err := p.sanitizeRequest(context.Background(), tc.format, []byte(tc.body))
			if err != nil {
				t.Fatalf("sanitizeRequest: %v", err)
			}
			if !result.changed || result.findings == 0 {
				t.Fatalf("result = %+v, want changed findings", result)
			}
			if strings.Contains(string(result.body), secret) {
				t.Fatalf("secret leaked after sanitization: %s", result.body)
			}
			if !json.Valid(result.body) {
				t.Fatalf("sanitized body is invalid JSON: %s", result.body)
			}
		})
	}
}

func TestEncodedToolJSONPreservesLargeInteger(t *testing.T) {
	p := newTestPlugin(t)
	const body = `{"model":"m","messages":[{"role":"assistant","tool_calls":[{"id":"c1","type":"function","function":{"name":"f","arguments":"{\"id\":9007199254740993,\"email\":\"test@example.com\"}"}}]}]}`
	result, err := p.sanitizeRequest(context.Background(), "openai", []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if !result.changed || strings.Contains(string(result.body), "test@example.com") {
		t.Fatalf("tool JSON not sanitized: %s", result.body)
	}
	if !strings.Contains(string(result.body), `9007199254740993`) {
		t.Fatalf("tool JSON integer changed: %s", result.body)
	}
}

func TestEmptyReplacementStaysEmptyForMultipleValues(t *testing.T) {
	if got := numberedPlaceholder("", 2); got != "" {
		t.Fatalf("numbered empty replacement = %q", got)
	}
}

func TestRequestRendererKeepsEqualityAndDistinguishesValues(t *testing.T) {
	p := newTestPlugin(t)
	const body = `{"model":"m","messages":[{"role":"user","content":"a@example.com b@example.com a@example.com"}]}`
	result, err := p.sanitizeRequest(context.Background(), "openai", []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	got := string(result.body)
	if strings.Count(got, "[邮箱]") != 2 || strings.Count(got, "[邮箱#2]") != 1 {
		t.Fatalf("unexpected request-local placeholders: %s", got)
	}
}

func TestNoFindingLeavesOriginalBytesUntouched(t *testing.T) {
	p := newTestPlugin(t)
	body := []byte(" \n{\"model\" : \"m\", \"messages\" : [{\"role\":\"user\",\"content\":\"hello\"}], \"n\":9007199254740993}\t")
	result, err := p.sanitizeRequest(context.Background(), "openai", body)
	if err != nil {
		t.Fatal(err)
	}
	if result.changed || &result.body[0] != &body[0] || string(result.body) != string(body) {
		t.Fatalf("no-hit body was copied or changed: %+v", result)
	}
}

func TestUnsupportedFormatAndShapeFailClosed(t *testing.T) {
	p := newTestPlugin(t)
	for _, req := range []pluginapi.RequestInterceptRequest{
		{SourceFormat: "codex", Body: []byte(`{"input":"test@example.com"}`)},
		{SourceFormat: "openai", Body: []byte(`{"messages":[{"role":"user","content":[{"type":"future_block","text":"test@example.com"}]}]}`)},
	} {
		resp, err := p.InterceptRequestBeforeAuth(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if !resp.Terminate || resp.StatusCode != 422 {
			t.Fatalf("response = %+v, want terminate 422", resp)
		}
	}
}

func TestMalformedEncodedToolArgumentsFailClosed(t *testing.T) {
	p := newTestPlugin(t)
	resp, err := p.InterceptRequestBeforeAuth(context.Background(), pluginapi.RequestInterceptRequest{
		SourceFormat: "openai",
		Body:         []byte(`{"messages":[{"role":"assistant","tool_calls":[{"type":"function","function":{"name":"f","arguments":"{not-json"}}]}]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Terminate || resp.StatusCode != 422 {
		t.Fatalf("response = %+v, want terminate 422", resp)
	}
}

func TestBeforeAndUnchangedAfterScanOnlyOnce(t *testing.T) {
	p := newTestPlugin(t)
	req := pluginapi.RequestInterceptRequest{
		RequestID:      "request-cache-1",
		SourceFormat:   "openai",
		Model:          "upstream-model",
		RequestedModel: "alias",
		Body:           []byte(`{"model":"m","messages":[{"role":"user","content":"test@example.com"}]}`),
	}
	before, err := p.InterceptRequestBeforeAuth(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if before.Body == nil {
		t.Fatal("before-auth did not redact")
	}
	req.Body = before.Body
	after, err := p.InterceptRequestAfterAuth(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if after.Body != nil || after.Terminate {
		t.Fatalf("unchanged after-auth body was rescanned: %+v", after)
	}
	stats := p.cache.Stats()
	if stats.Records != 1 || stats.SeenHits != 1 {
		t.Fatalf("cache stats = %+v, want one scan and one hit", stats)
	}

	if err := p.HandleRequestComplete(context.Background(), pluginapi.RequestCompletion{
		RequestID: "request-cache-1",
		Outcome:   pluginapi.RequestCompletionSucceeded,
	}); err != nil {
		t.Fatal(err)
	}
	if p.cache.Len() != 0 {
		t.Fatalf("cache retained %d entries after completion", p.cache.Len())
	}
}

func TestChangedAfterAuthBodyIsRescanned(t *testing.T) {
	p := newTestPlugin(t)
	req := pluginapi.RequestInterceptRequest{
		RequestID:    "request-cache-2",
		SourceFormat: "openai",
		Model:        "m",
		Body:         []byte(`{"model":"m","messages":[{"role":"user","content":"hello"}]}`),
	}
	before, err := p.InterceptRequestBeforeAuth(context.Background(), req)
	if err != nil || before.Body != nil || before.Terminate {
		t.Fatalf("before = %+v err=%v", before, err)
	}
	req.Body = []byte(`{"model":"m","messages":[{"role":"user","content":"hello"},{"role":"user","content":"second@example.com"}]}`)
	after, err := p.InterceptRequestAfterAuth(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if after.Body == nil || strings.Contains(string(after.Body), "second@example.com") {
		t.Fatalf("changed after body was not sanitized: %+v", after)
	}
	stats := p.cache.Stats()
	if stats.Records != 2 || stats.SeenMisses < 2 {
		t.Fatalf("cache stats = %+v", stats)
	}
}

func TestRegistrationCapabilityJSON(t *testing.T) {
	caps := abiCapabilities{RequestInterceptor: true, RequestLifecyclePlugin: true}
	raw, err := json.Marshal(caps)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"request_interceptor":true`, `"request_lifecycle_plugin":true`} {
		if !strings.Contains(string(raw), field) {
			t.Fatalf("expected %s in JSON: %s", field, raw)
		}
	}
}
