package walker_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/ahoo/cpa-plugin-privacyfilter/walker"
)

type wantTarget struct {
	path    string
	value   string
	scope   walker.Scope
	kind    walker.TargetKind
	mutable walker.Mutability
}

func mustWalk(t *testing.T, format, body string) *walker.Result {
	t.Helper()
	result, err := walker.Walk(context.Background(), format, []byte(body))
	if err != nil {
		t.Fatalf("Walk(%q): %v", format, err)
	}
	return result
}

func checkTargets(t *testing.T, result *walker.Result, want []wantTarget) {
	t.Helper()
	if len(result.Targets) != len(want) {
		t.Fatalf("target count=%d want=%d", len(result.Targets), len(want))
	}
	for i, expected := range want {
		got := result.Targets[i]
		if got.Path.String() != expected.path || got.Token.Value != expected.value || got.Scope != expected.scope || got.Kind != expected.kind || got.Mutable != expected.mutable {
			t.Errorf(
				"target[%d] mismatch path=%t value=%t scope=%t kind=%t mutable=%t value_len=%d want_value_len=%d",
				i,
				got.Path.String() == expected.path,
				got.Token.Value == expected.value,
				got.Scope == expected.scope,
				got.Kind == expected.kind,
				got.Mutable == expected.mutable,
				len(got.Token.Value),
				len(expected.value),
			)
		}
		if !got.Token.Path.Equal(got.Path) {
			t.Errorf("target[%d] token path %s differs from target path %s", i, got.Token.Path, got.Path)
		}
	}
}

func assertValuesNotTargeted(t *testing.T, result *walker.Result, values ...string) {
	t.Helper()
	for targetIndex, target := range result.Targets {
		for valueIndex, value := range values {
			if target.Token.Value == value {
				t.Errorf("protected/control value unexpectedly targeted target=%d value=%d path=%s", targetIndex, valueIndex, target.Path)
			}
		}
	}
}

func TestRegistryFormatsAndExactResolution(t *testing.T) {
	wantFormats := []string{"claude", "gemini", "gemini-cli", "interactions", "openai", "openai-response"}
	if got := walker.Formats(); !reflect.DeepEqual(got, wantFormats) {
		t.Fatalf("Formats() = %#v, want %#v", got, wantFormats)
	}
	cases := []struct {
		format   string
		protocol walker.Protocol
		alias    bool
	}{
		{"openai", walker.ProtocolOpenAI, false},
		{"openai-response", walker.ProtocolOpenAIResponse, false},
		{"claude", walker.ProtocolClaude, false},
		{"gemini", walker.ProtocolGemini, false},
		{"interactions", walker.ProtocolInteractions, false},
		{"gemini-cli", walker.ProtocolInteractions, true},
	}
	registry := walker.NewRegistry()
	for _, tc := range cases {
		t.Run(tc.format, func(t *testing.T) {
			got, err := registry.Resolve(tc.format)
			if err != nil || got != tc.protocol {
				t.Fatalf("Resolve(%q) = %q, %v", tc.format, got, err)
			}
			if registry.IsAlias(tc.format) != tc.alias {
				t.Fatalf("IsAlias(%q) = %v, want %v", tc.format, registry.IsAlias(tc.format), tc.alias)
			}
		})
	}

	for _, format := range []string{"", "OpenAI", " openai", "openai ", "responses", "codex", "antigravity"} {
		t.Run("unsupported/"+format, func(t *testing.T) {
			_, err := walker.Walk(context.Background(), format, []byte(`not even JSON`))
			if !errors.Is(err, walker.ErrUnsupportedFormat) {
				t.Fatalf("error = %v, want ErrUnsupportedFormat", err)
			}
			var typed *walker.UnsupportedFormatError
			if !errors.As(err, &typed) || typed.SourceFormat != format {
				t.Fatalf("typed error = %#v", typed)
			}
		})
	}
}

func TestGeminiCLIAliasUsesInteractionsWalker(t *testing.T) {
	const body = `{"model":"gemini","system_instruction":"system","input":"user"}`
	result := mustWalk(t, "gemini-cli", body)
	if result.Protocol != walker.ProtocolInteractions || result.SourceFormat != "gemini-cli" {
		t.Fatalf("alias result = protocol %q source %q", result.Protocol, result.SourceFormat)
	}
	checkTargets(t, result, []wantTarget{
		{`$["system_instruction"]`, "system", walker.ScopeSystem, walker.TargetKindNaturalText, walker.MutabilityDirect},
		{`$["input"]`, "user", walker.ScopeUser, walker.TargetKindNaturalText, walker.MutabilityDirect},
	})
}
