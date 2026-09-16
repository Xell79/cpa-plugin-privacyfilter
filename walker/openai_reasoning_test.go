package walker_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ahoo/cpa-plugin-privacyfilter/walker"
)

func TestOpenAIReasoningReplayIsValidatedAndOpaque(t *testing.T) {
	const body = `{
	  "messages":[
	    {"role":"user","content":"visible user text"},
	    {
	      "role":"assistant",
	      "content":"visible assistant text",
	      "reasoning":"legacy reasoning",
	      "reasoning_content":"provider reasoning",
	      "reasoning_details":[
	        {"type":"reasoning.text","text":"signed reasoning","signature":"signature","id":"rd_1","format":"unknown","index":0},
	        {"type":"reasoning.summary","summary":"reasoning summary","id":null,"format":"openai-responses-v1","index":1},
	        {"type":"reasoning.encrypted","data":"encrypted reasoning","format":"anthropic-claude-v1","index":2}
	      ]
	    }
	  ]
	}`
	result := mustWalk(t, "openai", body)
	checkTargets(t, result, []wantTarget{
		{`$["messages"][0]["content"]`, "visible user text", walker.ScopeUser, walker.TargetKindNaturalText, walker.MutabilityDirect},
		{`$["messages"][1]["content"]`, "visible assistant text", walker.ScopeAssistant, walker.TargetKindNaturalText, walker.MutabilityDirect},
	})
	assertValuesNotTargeted(
		t,
		result,
		"legacy reasoning",
		"provider reasoning",
		"reasoning.text",
		"signed reasoning",
		"signature",
		"rd_1",
		"unknown",
		"reasoning.summary",
		"reasoning summary",
		"openai-responses-v1",
		"reasoning.encrypted",
		"encrypted reasoning",
		"anthropic-claude-v1",
	)
	if result.UnsupportedCount != 0 {
		t.Fatalf("unsupported = %d", result.UnsupportedCount)
	}
}

func TestOpenAIReasoningReplayRejectsUnknownVariant(t *testing.T) {
	result := mustWalk(
		t,
		"openai",
		`{"messages":[{"role":"assistant","reasoning_details":[{"type":"reasoning.future","text":"opaque only after admission"}]}]}`,
	)
	if result.UnsupportedCount != 1 || len(result.Unsupported) != 1 {
		t.Fatalf("unsupported = count %d details %d", result.UnsupportedCount, len(result.Unsupported))
	}
	if got := result.Unsupported[0].Path.String(); got != `$["messages"][0]["reasoning_details"][0]` {
		t.Fatalf("unsupported path = %s", got)
	}
}

func TestOpenAIReasoningReplayRejectsDuplicateControlKey(t *testing.T) {
	_, err := walker.Walk(
		context.Background(),
		"openai",
		[]byte(`{"messages":[{"role":"assistant","reasoning_details":[{"type":"reasoning.text","type":"reasoning.summary","text":"x"}]}]}`),
	)
	var ambiguity *walker.AmbiguityError
	if !errors.As(err, &ambiguity) {
		t.Fatal("duplicate reasoning detail discriminator was not rejected as ambiguous")
	}
	if got := ambiguity.Path.String(); got != `$["messages"][0]["reasoning_details"][0]["type"]` {
		t.Fatalf("ambiguity path = %s", got)
	}
}

func TestOpenAIReasoningReplayRequiresAssistantRole(t *testing.T) {
	for _, role := range []string{"user", "tool"} {
		t.Run(role, func(t *testing.T) {
			result := mustWalk(
				t,
				"openai",
				`{"messages":[{"role":"`+role+`","reasoning":"legacy","reasoning_content":"provider","reasoning_details":[{"type":"reasoning.text","text":"detail"}]}]}`,
			)
			if result.UnsupportedCount == 0 {
				t.Fatal("non-assistant reasoning replay was accepted")
			}
			assertValuesNotTargeted(t, result, "legacy", "provider", "detail")
		})
	}
}

func TestOpenAIReasoningReplayRejectsInvalidShapes(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"reasoning number", `{"messages":[{"role":"assistant","reasoning":123}]}`},
		{"details object", `{"messages":[{"role":"assistant","reasoning_details":{}}]}`},
		{"detail number", `{"messages":[{"role":"assistant","reasoning_details":[123]}]}`},
		{"index string", `{"messages":[{"role":"assistant","reasoning_details":[{"type":"reasoning.text","index":"0"}]}]}`},
		{"missing type", `{"messages":[{"role":"assistant","reasoning_details":[{}]}]}`},
		{"missing summary", `{"messages":[{"role":"assistant","reasoning_details":[{"type":"reasoning.summary"}]}]}`},
		{"missing encrypted data", `{"messages":[{"role":"assistant","reasoning_details":[{"type":"reasoning.encrypted"}]}]}`},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			result, err := walker.Walk(context.Background(), "openai", []byte(test.body))
			if result != nil || !errors.Is(err, walker.ErrInvalidShape) {
				t.Fatalf("result_non_nil=%t error=%v; want ErrInvalidShape", result != nil, err)
			}
			var shape *walker.ShapeError
			if !errors.As(err, &shape) {
				t.Fatalf("error %T is not *ShapeError", err)
			}
		})
	}
}

func TestOpenAIReasoningReplayRejectsUnknownStringField(t *testing.T) {
	result := mustWalk(
		t,
		"openai",
		`{"messages":[{"role":"assistant","reasoning_details":[{"type":"reasoning.text","text":"replay","future_payload":"must not pass opaquely"}]}]}`,
	)
	if result.UnsupportedCount != 1 || len(result.Unsupported) != 1 {
		t.Fatalf("unsupported = count %d details %d", result.UnsupportedCount, len(result.Unsupported))
	}
	if got := result.Unsupported[0].Path.String(); got != `$["messages"][0]["reasoning_details"][0]["future_payload"]` {
		t.Fatalf("unsupported path = %s", got)
	}
	assertValuesNotTargeted(t, result, "must not pass opaquely")
}

func TestOpenAIReasoningReplayAcceptsDocumentedNulls(t *testing.T) {
	result := mustWalk(
		t,
		"openai",
		`{"messages":[{"role":"assistant","reasoning":null,"reasoning_content":null,"reasoning_details":null},{"role":"assistant","reasoning_details":[{"type":"reasoning.text","text":null,"signature":null,"id":null,"format":null,"index":null}]}]}`,
	)
	if len(result.Targets) != 0 || result.UnsupportedCount != 0 {
		t.Fatalf("targets=%d unsupported=%d", len(result.Targets), result.UnsupportedCount)
	}
}
