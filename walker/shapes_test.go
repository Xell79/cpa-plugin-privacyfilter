package walker_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ahoo/cpa-plugin-privacyfilter/payload"
	"github.com/ahoo/cpa-plugin-privacyfilter/walker"
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
		wantTargets     int
	}{
		{
			name:            "unknown type",
			body:            `{"input":[{"type":"future_block","steps":["must remain skipped"]}]}`,
			wantUnsupported: 1,
		},
		{
			name:            "unknown role",
			body:            `{"input":[{"role":"future_role","steps":["must remain skipped"]}]}`,
			wantUnsupported: 2,
		},
		{
			name:            "thought",
			body:            `{"input":[{"type":"thought","steps":["must remain skipped"],"content":"private reasoning"}]}`,
			wantUnsupported: 1,
			wantTargets:     1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := mustWalk(t, "interactions", tc.body)
			if len(result.Targets) != tc.wantTargets {
				t.Fatalf("target count = %d, want %d", len(result.Targets), tc.wantTargets)
			}
			if result.UnsupportedCount != tc.wantUnsupported {
				t.Fatalf("UnsupportedCount = %d, want %d", result.UnsupportedCount, tc.wantUnsupported)
			}
			assertValuesNotTargeted(t, result, "must remain skipped")
		})
	}
}

func TestClaudeToolResultUsesObjectScopedIntegrityDisposition(t *testing.T) {
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
		{`$["messages"][0]["content"][0]["content"][0]["safe"]`, "selected output", walker.ScopeToolOutput, walker.TargetKindJSONValue, walker.MutabilityJSONOrPlain},
		{`$["messages"][0]["content"][0]["content"][0]["thoughtSignature"]`, "camel signature", walker.ScopeToolOutput, walker.TargetKindJSONValue, walker.MutabilityJSONOrPlain},
		{`$["messages"][0]["content"][0]["content"][0]["thought_signature"]`, "snake signature", walker.ScopeToolOutput, walker.TargetKindJSONValue, walker.MutabilityJSONOrPlain},
		{`$["messages"][0]["content"][0]["content"][0]["encrypted_content"]`, "encrypted output", walker.ScopeToolOutput, walker.TargetKindJSONValue, walker.MutabilityJSONOrPlain},
		{`$["messages"][0]["content"][0]["content"][0]["signature"]`, "generic signature", walker.ScopeToolOutput, walker.TargetKindJSONValue, walker.MutabilityJSONOrPlain},
	})
	assertValuesNotTargeted(t, result, "toolu_1", "outer signature", "outer encrypted")
	if result.UnsupportedCount != 2 {
		t.Fatalf("UnsupportedCount = %d, want 2 unknown tool-result siblings", result.UnsupportedCount)
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
		{"openai function name object", "openai", `{"messages":[],"tools":[{"type":"function","function":{"name":{"nested":"lookup"}}}]}`, walker.ErrInvalidShape},
		{"openai content ID object", "openai", `{"messages":[{"role":"user","content":[{"type":"text","text":"ok","id":{"nested":"cloak"}}]}]}`, walker.ErrInvalidShape},
		{"responses instructions array", "openai-response", `{"instructions":[],"input":"text"}`, walker.ErrInvalidShape},
		{"responses input object", "openai-response", `{"input":{}}`, walker.ErrInvalidShape},
		{"responses output number", "openai-response", `{"input":[{"type":"function_call_output","output":7}]}`, walker.ErrInvalidShape},
		{"responses function callers object", "openai-response", `{"input":"ok","tools":[{"type":"function","name":"lookup","parameters":{},"allowed_callers":[{"nested":"direct"}]}]}`, walker.ErrInvalidShape},
		{"responses root model object", "openai-response", `{"model":{"future":"cloak"},"input":"ok"}`, walker.ErrInvalidShape},
		{"responses input image file ID object", "openai-response", `{"input":[{"type":"message","role":"assistant","content":[{"type":"input_image","detail":"auto","file_id":{"future":"cloak"}}]}]}`, walker.ErrInvalidShape},
		{"responses function call ID object", "openai-response", `{"input":[{"type":"function_call","arguments":"{}","id":{"future":"cloak"}}]}`, walker.ErrInvalidShape},
		{"responses computer click button object", "openai-response", `{"input":[{"type":"computer_call","pending_safety_checks":[],"action":{"type":"click","button":{"future":"cloak"},"x":1,"y":2}}]}`, walker.ErrInvalidShape},
		{"responses computer keypress keys string", "openai-response", `{"input":[{"type":"computer_call","pending_safety_checks":[],"action":{"type":"keypress","keys":"cloak"}}]}`, walker.ErrInvalidShape},
		{"responses computer drag coordinate string", "openai-response", `{"input":[{"type":"computer_call","pending_safety_checks":[],"action":{"type":"drag","path":[{"x":"cloak","y":2}]}}]}`, walker.ErrInvalidShape},
		{"responses MCP ID object", "openai-response", `{"input":[{"type":"mcp_call","id":{"future":"cloak"},"arguments":"{}"}]}`, walker.ErrInvalidShape},
		{"anthropic system object", "claude", `{"system":{},"messages":[]}`, walker.ErrInvalidShape},
		{"anthropic messages object", "claude", `{"messages":{}}`, walker.ErrInvalidShape},
		{"anthropic content number", "claude", `{"messages":[{"role":"user","content":7}]}`, walker.ErrInvalidShape},
		{"anthropic tool description object", "claude", `{"messages":[],"tools":[{"name":"lookup","description":{"nested":"interface"},"input_schema":{}}]}`, walker.ErrInvalidShape},
		{"anthropic message ID object", "claude", `{"messages":[{"role":"user","id":{"nested":"cloak"},"content":"ok"}]}`, walker.ErrInvalidShape},
		{"anthropic media data object", "claude", `{"messages":[{"role":"user","content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":{"nested":"cloak"}}}]}]}`, walker.ErrInvalidShape},
		{"anthropic thinking signature object", "claude", `{"messages":[{"role":"assistant","content":[{"type":"thinking","thinking":"private","signature":{"nested":"cloak"}}]}]}`, walker.ErrInvalidShape},
		{"gemini system string", "gemini", `{"systemInstruction":"text","contents":[]}`, walker.ErrInvalidShape},
		{"gemini contents object", "gemini", `{"contents":{}}`, walker.ErrInvalidShape},
		{"gemini parts string", "gemini", `{"contents":[{"role":"user","parts":"text"}]}`, walker.ErrInvalidShape},
		{"gemini text number", "gemini", `{"contents":[{"role":"user","parts":[{"text":7}]}]}`, walker.ErrInvalidShape},
		{"gemini thought string", "gemini", `{"contents":[{"role":"model","parts":[{"thought":"true","text":"hidden"}]}]}`, walker.ErrInvalidShape},
		{"gemini inline data string", "gemini", `{"contents":[{"parts":[{"inlineData":"bytes"}]}]}`, walker.ErrInvalidShape},
		{"gemini file URI number", "gemini", `{"contents":[{"parts":[{"fileData":{"fileUri":7}}]}]}`, walker.ErrInvalidShape},
		{"gemini Google Search string", "gemini", `{"contents":[],"tools":[{"googleSearch":"enabled"}]}`, walker.ErrInvalidShape},
		{"gemini function name object", "gemini", `{"contents":[],"tools":[{"functionDeclarations":[{"name":{"nested":"lookup"}}]}]}`, walker.ErrInvalidShape},
		{"gemini content ID object", "gemini", `{"contents":[{"id":{"nested":"cloak"},"parts":[{"text":"ok"}]}]}`, walker.ErrInvalidShape},
		{"gemini function call ID object", "gemini", `{"contents":[{"parts":[{"functionCall":{"id":{"nested":"cloak"},"name":"lookup","args":{}}}]}]}`, walker.ErrInvalidShape},
		{"gemini media resolution level object", "gemini", `{"contents":[{"parts":[{"text":"ok","mediaResolution":{"level":{"nested":"cloak"}}}]}]}`, walker.ErrInvalidShape},
		{"interactions input number", "interactions", `{"input":7}`, walker.ErrInvalidShape},
		{"interactions nested steps object", "interactions", `{"input":{"steps":{}}}`, walker.ErrInvalidShape},
		{"interactions text number", "interactions", `{"input":[{"type":"user_input","text":7}]}`, walker.ErrInvalidShape},
		{"interactions tool parameters string", "interactions", `{"input":"ok","tools":[{"type":"function","name":"lookup","parameters":"schema"}]}`, walker.ErrInvalidShape},
		{"interactions item ID object", "interactions", `{"input":[{"type":"user_input","id":{"nested":"cloak"},"content":"ok"}]}`, walker.ErrInvalidShape},
		{"interactions text part name object", "interactions", `{"input":[{"type":"user_input","content":[{"type":"text","name":{"nested":"cloak"},"text":"ok"}]}]}`, walker.ErrInvalidShape},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := walker.Walk(context.Background(), tc.format, []byte(tc.body))
			if result != nil {
				t.Fatal("fatal shape error returned a non-nil result")
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
		{"gemini duplicate root tools", "gemini", `{"contents":[],"tools":[],"tools":[]}`},
		{"gemini function declaration aliases", "gemini", `{"contents":[],"tools":[{"functionDeclarations":[],"function_declarations":[]}]}`},
		{"gemini function schema variants", "gemini", `{"contents":[],"tools":[{"functionDeclarations":[{"name":"lookup","parameters":{},"parametersJsonSchema":{}}]}]}`},
		{"gemini media outer aliases", "gemini", `{"contents":[{"parts":[{"inlineData":{"data":"one"},"inline_data":{"data":"two"}}]}]}`},
		{"gemini media MIME aliases", "gemini", `{"contents":[{"parts":[{"inlineData":{"data":"bytes","mimeType":"image/png","mime_type":"image/png"}}]}]}`},
		{"interactions system aliases", "interactions", `{"system_instruction":"a","systemInstruction":"b","input":"c"}`},
		{"interactions duplicate nested content", "interactions", `{"input":[{"type":"user_input","content":"a","content":"b"}]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := walker.Walk(context.Background(), tc.format, []byte(tc.body))
			if result != nil || !errors.Is(err, walker.ErrAmbiguousPath) {
				t.Fatalf("result_non_nil=%t, error %v; want ErrAmbiguousPath", result != nil, err)
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
		{`$["messages"][0]["content"][0]["input"]["value"]`, "selected", walker.ScopeToolInput, walker.TargetKindJSONValue, walker.MutabilityJSONOrPlain},
	})
}
