package walker_test

import (
	"context"
	"errors"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/payload"
	"github.com/rheodev/cpa-plugin-privacyfilter/walker"
)

func TestUnknownContentShapesAreRecordedNotGuessed(t *testing.T) {
	cases := []struct {
		name       string
		format     string
		body       string
		wantPath   string
		skippedVal string
	}{
		{
			name:       "openai chat block",
			format:     "openai",
			body:       `{"messages":[{"role":"user","content":[{"type":"future_text","text":"do not guess"}]}]}`,
			wantPath:   `$["messages"][0]["content"][0]`,
			skippedVal: "do not guess",
		},
		{
			name:       "responses block",
			format:     "openai-response",
			body:       `{"input":[{"type":"message","role":"user","content":[{"type":"future_text","text":"do not guess"}]}]}`,
			wantPath:   `$["input"][0]["content"][0]`,
			skippedVal: "do not guess",
		},
		{
			name:       "anthropic block",
			format:     "claude",
			body:       `{"messages":[{"role":"user","content":[{"type":"future_text","text":"do not guess"}]}]}`,
			wantPath:   `$["messages"][0]["content"][0]`,
			skippedVal: "do not guess",
		},
		{
			name:       "gemini part",
			format:     "gemini",
			body:       `{"contents":[{"role":"user","parts":[{"futureText":"do not guess"}]}]}`,
			wantPath:   `$["contents"][0]["parts"][0]`,
			skippedVal: "do not guess",
		},
		{
			name:       "interactions block",
			format:     "interactions",
			body:       `{"input":[{"type":"model_output","content":[{"type":"future_text","text":"do not guess"}]}]}`,
			wantPath:   `$["input"][0]["content"][0]`,
			skippedVal: "do not guess",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := mustWalk(t, tc.format, tc.body)
			if result.UnsupportedCount != 1 || len(result.Unsupported) != 1 {
				t.Fatalf("unsupported = count %d details %#v", result.UnsupportedCount, result.Unsupported)
			}
			issue := result.Unsupported[0]
			if issue.Path.String() != tc.wantPath || !errors.Is(issue, walker.ErrUnsupportedShape) {
				t.Fatalf("issue = %v at %s", issue, issue.Path)
			}
			assertValuesNotTargeted(t, result, tc.skippedVal)
		})
	}
}

func TestInteractionsNestedStepsRequireSupportedEnvelope(t *testing.T) {
	cases := []struct {
		name            string
		body            string
		wantUnsupported int
	}{
		{
			name:            "unknown type",
			body:            `{"input":[{"type":"future_block","steps":["must remain skipped"]}]}`,
			wantUnsupported: 1,
		},
		{
			name:            "unknown role",
			body:            `{"input":[{"role":"future_role","steps":["must remain skipped"]}]}`,
			wantUnsupported: 1,
		},
		{
			name:            "thought",
			body:            `{"input":[{"type":"thought","steps":["must remain skipped"],"content":"private reasoning"}]}`,
			wantUnsupported: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := mustWalk(t, "interactions", tc.body)
			if len(result.Targets) != 0 {
				t.Fatalf("opaque/unsupported nested steps yielded targets: %#v", result.Targets)
			}
			if result.UnsupportedCount != tc.wantUnsupported {
				t.Fatalf("UnsupportedCount = %d, want %d", result.UnsupportedCount, tc.wantUnsupported)
			}
			assertValuesNotTargeted(t, result, "must remain skipped", "private reasoning")
		})
	}
}

func TestClaudeToolResultProtectsReasoningIntegrityButScansGenericSignature(t *testing.T) {
	const body = `{
  "messages":[{"role":"user","content":[{
    "type":"tool_result",
    "tool_use_id":"toolu_1",
    "thoughtSignature":"outer signature",
    "encrypted_content":"outer encrypted",
    "content":[{
      "safe":"selected output",
      "thoughtSignature":"camel signature",
      "thought_signature":"snake signature",
      "encrypted_content":"encrypted output",
      "signature":"generic signature"
    }]
  }]}]
}`
	result := mustWalk(t, "claude", body)
	checkTargets(t, result, []wantTarget{
		{`$["messages"][0]["content"][0]["content"][0]["safe"]`, "selected output", walker.ScopeToolOutput, walker.TargetKindJSONValue, walker.MutabilityDirect},
		{`$["messages"][0]["content"][0]["content"][0]["signature"]`, "generic signature", walker.ScopeToolOutput, walker.TargetKindJSONValue, walker.MutabilityDirect},
	})
	assertValuesNotTargeted(t, result,
		"toolu_1", "outer signature", "outer encrypted", "camel signature", "snake signature", "encrypted output")
	if result.Opaque < 6 {
		t.Fatalf("Opaque = %d, want at least 6 protected values", result.Opaque)
	}
}

func TestInvalidRootsAndFieldTypes(t *testing.T) {
	cases := []struct {
		name   string
		format string
		body   string
		want   error
	}{
		{"invalid JSON", "openai", `{"messages":[}`, payload.ErrInvalidJSON},
		{"array root", "openai", `[]`, payload.ErrRootNotObject},
		{"openai messages object", "openai", `{"messages":{}}`, walker.ErrInvalidShape},
		{"openai message scalar", "openai", `{"messages":["text"]}`, walker.ErrInvalidShape},
		{"openai role number", "openai", `{"messages":[{"role":7,"content":"text"}]}`, walker.ErrInvalidShape},
		{"openai content number", "openai", `{"messages":[{"role":"user","content":7}]}`, walker.ErrInvalidShape},
		{"openai arguments object", "openai", `{"messages":[{"role":"assistant","content":null,"tool_calls":[{"type":"function","function":{"arguments":{}}}]}]}`, walker.ErrInvalidShape},
		{"responses instructions array", "openai-response", `{"instructions":[],"input":"text"}`, walker.ErrInvalidShape},
		{"responses input object", "openai-response", `{"input":{}}`, walker.ErrInvalidShape},
		{"responses output number", "openai-response", `{"input":[{"type":"function_call_output","output":7}]}`, walker.ErrInvalidShape},
		{"anthropic system object", "claude", `{"system":{},"messages":[]}`, walker.ErrInvalidShape},
		{"anthropic messages object", "claude", `{"messages":{}}`, walker.ErrInvalidShape},
		{"anthropic content number", "claude", `{"messages":[{"role":"user","content":7}]}`, walker.ErrInvalidShape},
		{"gemini system string", "gemini", `{"systemInstruction":"text","contents":[]}`, walker.ErrInvalidShape},
		{"gemini contents object", "gemini", `{"contents":{}}`, walker.ErrInvalidShape},
		{"gemini parts string", "gemini", `{"contents":[{"role":"user","parts":"text"}]}`, walker.ErrInvalidShape},
		{"gemini text number", "gemini", `{"contents":[{"role":"user","parts":[{"text":7}]}]}`, walker.ErrInvalidShape},
		{"gemini thought string", "gemini", `{"contents":[{"role":"model","parts":[{"thought":"true","text":"hidden"}]}]}`, walker.ErrInvalidShape},
		{"interactions input number", "interactions", `{"input":7}`, walker.ErrInvalidShape},
		{"interactions nested steps object", "interactions", `{"input":{"steps":{}}}`, walker.ErrInvalidShape},
		{"interactions text number", "interactions", `{"input":[{"type":"user_input","text":7}]}`, walker.ErrInvalidShape},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := walker.Walk(context.Background(), tc.format, []byte(tc.body))
			if result != nil {
				t.Fatalf("result = %#v on fatal shape error", result)
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want errors.Is(_, %v)", err, tc.want)
			}
			if errors.Is(tc.want, walker.ErrInvalidShape) {
				var typed *walker.ShapeError
				if !errors.As(err, &typed) {
					t.Fatalf("error %T is not *ShapeError: %v", err, err)
				}
			}
		})
	}
}

func TestDuplicateControlPathsAreAmbiguous(t *testing.T) {
	cases := []struct {
		name   string
		format string
		body   string
	}{
		{"duplicate root model", "openai", `{"model":"a","model":"b","messages":[]}`},
		{"openai duplicate content", "openai", `{"messages":[{"role":"user","content":"a","content":"b"}]}`},
		{"openai duplicate block type", "openai", `{"messages":[{"role":"user","content":[{"type":"text","type":"image_url","text":"a"}]}]}`},
		{"responses duplicate item type", "openai-response", `{"input":[{"type":"message","type":"function_call","role":"user","content":"a","arguments":"{}"}]}`},
		{"responses duplicate prompt variables", "openai-response", `{"input":"a","prompt":{"variables":{"x":"one"},"variables":{"x":"two"}}}`},
		{"anthropic duplicate role", "claude", `{"messages":[{"role":"user","role":"assistant","content":"a"}]}`},
		{"anthropic duplicate tool input", "claude", `{"messages":[{"role":"assistant","content":[{"type":"tool_use","input":{"x":"one"},"input":{"x":"two"}}]}]}`},
		{"gemini system aliases", "gemini", `{"systemInstruction":{"parts":[]},"system_instruction":{"parts":[]},"contents":[]}`},
		{"gemini duplicate args", "gemini", `{"contents":[{"parts":[{"functionCall":{"args":{"x":"one"},"args":{"x":"two"}}}]}]}`},
		{"interactions system aliases", "interactions", `{"system_instruction":"a","systemInstruction":"b","input":"c"}`},
		{"interactions duplicate nested content", "interactions", `{"input":[{"type":"user_input","content":"a","content":"b"}]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := walker.Walk(context.Background(), tc.format, []byte(tc.body))
			if result != nil || !errors.Is(err, walker.ErrAmbiguousPath) {
				t.Fatalf("result %#v, error %v; want ErrAmbiguousPath", result, err)
			}
			var typed *walker.AmbiguityError
			if !errors.As(err, &typed) || len(typed.Keys) == 0 {
				t.Fatalf("typed ambiguity = %#v", typed)
			}
		})
	}
}

func TestNoBlanketStringWalkingAndPluginCallbacksStillNatural(t *testing.T) {
	const openAI = `{
  "messages":[{"role":"user","content":"<plugin_callback>callback secret</plugin_callback>"}],
  "random":{"natural":"must stay","nested":["also stay"]},
  "secret-key-only":7
}`
	result := mustWalk(t, "openai", openAI)
	checkTargets(t, result, []wantTarget{
		{`$["messages"][0]["content"]`, "<plugin_callback>callback secret</plugin_callback>", walker.ScopeUser, walker.TargetKindNaturalText, walker.MutabilityDirect},
	})
	assertValuesNotTargeted(t, result, "must stay", "also stay")

	const toolKeys = `{"messages":[{"role":"assistant","content":[{"type":"tool_use","input":{"secret-key-only":17,"value":"selected"}}]}]}`
	result = mustWalk(t, "claude", toolKeys)
	checkTargets(t, result, []wantTarget{
		{`$["messages"][0]["content"][0]["input"]["value"]`, "selected", walker.ScopeToolInput, walker.TargetKindJSONValue, walker.MutabilityDirect},
	})
}
