package privacyengine

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
)

func customEngine(t testing.TB, rules string) *Engine {
	t.Helper()
	engine, report, err := New(Config{
		CustomTOML: []byte(rules),
		CustomMode: CustomRulesReplace,
	})
	if err != nil {
		t.Fatalf("New(custom): %v (report=%+v)", err, report)
	}
	return engine
}

func embeddedEngine(t testing.TB) (*Engine, CompatibilityReport) {
	t.Helper()
	rules, err := os.ReadFile("../../rules/gitleaks.toml")
	if err != nil {
		t.Fatalf("read embedded snapshot: %v", err)
	}
	engine, report, err := New(Config{
		EmbeddedTOML:          rules,
		EmbeddedCompatibility: CompatibilitySkipUnsupported,
	})
	if err != nil {
		t.Fatalf("New(embedded): %v (report=%+v)", err, report)
	}
	return engine, report
}

func TestEmbeddedSnapshotAndCaptureSelection(t *testing.T) {
	engine, report := embeddedEngine(t)
	if report.RulesSeen != 222 || report.RulesLoaded != 217 || report.RulesSkipped != 5 {
		t.Fatalf("unexpected compatibility counts: %+v", report)
	}

	input := "alibaba=LTAIABCDEFGHIJKLMNOPQRST "
	result, err := engine.Redact(context.Background(), input, RequestOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Redacted != "alibaba=[密钥] " {
		t.Fatalf("automatic first capture was not used: %q", result.Redacted)
	}
	if len(result.Findings) != 1 || result.Findings[0].RuleID != "alibaba-access-key-id" {
		t.Fatalf("unexpected finding: %+v", result.Findings)
	}

	// The pinned AWS rule's per-rule allowlist must suppress documented
	// EXAMPLE credentials, while a same-shape non-example remains detectable.
	allowed, err := engine.Detect(context.Background(), "AKIA"+"IOSFODNN7EXAMPLE", RequestOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(allowed) != 0 {
		t.Fatalf("AWS EXAMPLE credential was not allowlisted: %+v", allowed)
	}
	detected, err := engine.Detect(context.Background(), "AKIA"+"IOSFODNN7EXAMPLF", RequestOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(detected) != 1 || detected[0].RuleID != "aws-access-token" {
		t.Fatalf("AWS non-example not detected by pinned rule: %+v", detected)
	}
}

func TestIssue3OverlapRegression(t *testing.T) {
	engine, _ := embeddedEngine(t)
	const input = "api keyABCDEFGHIJKLMNOPQRSTUVWXYZ"
	result, err := engine.Redact(context.Background(), input, RequestOptions{})
	if err != nil {
		t.Fatalf("Redact overlap input: %v", err)
	}
	if !result.Hit() || !strings.Contains(result.Redacted, "[密钥]") {
		t.Fatalf("overlap input was not safely redacted: %+v", result)
	}
}

func TestPreferredRuleMetadataSurvivesOverlappingPII(t *testing.T) {
	engine := customEngine(t, `
[[rules]]
id = "block-email"
regex = '''[a-z]+@example\.com'''
keywords = ["@example."]
`)
	const input = "test@example.com"

	baseline, err := engine.Detect(context.Background(), input, RequestOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(baseline) != 1 || baseline[0].RuleID != rulePIIEmail {
		t.Fatalf("baseline overlap metadata = %+v", baseline)
	}

	preferred, err := engine.Detect(context.Background(), input, RequestOptions{
		PreferredRuleIDs: map[string]struct{}{"block-email": {}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(preferred) != 1 || preferred[0].RuleID != "block-email" {
		t.Fatalf("preferred overlap metadata = %+v", preferred)
	}
}

func TestStrongContextLookbackBoundaries(t *testing.T) {
	candidate := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	atBoundary := strings.Repeat("x", contextLookback-len("token = ")) + "token = " + candidate
	start := strings.Index(atBoundary, candidate)
	if start != contextLookback || !hasStrongSecretContext(atBoundary, start, len(atBoundary)) {
		t.Fatalf("context at exact %d-byte boundary was missed", contextLookback)
	}

	outside := "token=" + strings.Repeat("x", contextLookback) + candidate
	start = strings.Index(outside, candidate)
	if hasStrongSecretContext(outside, start, len(outside)) {
		t.Fatal("context outside lookback unexpectedly matched")
	}
	for _, bounds := range [][2]int{{-1, 1}, {2, 1}, {0, len(candidate) + 1}} {
		if hasStrongSecretContext(candidate, bounds[0], bounds[1]) {
			t.Fatalf("invalid bounds %v unexpectedly matched", bounds)
		}
	}
}

func TestLargeIssue3Regression(t *testing.T) {
	if testing.Short() {
		t.Skip("large regression")
	}
	engine, _ := embeddedEngine(t)
	const size = 490 * 1024
	input := strings.Repeat("ordinary prose line\n", size/len("ordinary prose line\n")+1)
	input = input[:size-len("api keyABCDEFGHIJKLMNOPQRSTUVWXYZ")] + "api keyABCDEFGHIJKLMNOPQRSTUVWXYZ"
	result, err := engine.Redact(context.Background(), input, RequestOptions{})
	if err != nil {
		t.Fatalf("Redact(%d bytes): %v", len(input), err)
	}
	if len(result.Redacted) == 0 || !result.Hit() {
		t.Fatal("large regression input produced no redaction")
	}
}

func TestFindingIsSpanOnlyUTF8AndRedactionIsIdempotent(t *testing.T) {
	engine := customEngine(t, `
[[rules]]
id = "never"
regex = '''NEVER_MATCH_THIS_VALUE'''
keywords = ["NEVER_MATCH"]
`)
	input := "前alice@example.com后 13812345678 192.168.1.1 卡4111111111111111"
	findings, err := engine.Detect(context.Background(), input, RequestOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 4 {
		t.Fatalf("got %d findings: %+v", len(findings), findings)
	}
	if findings[0].Start != len("前") || input[findings[0].Start:findings[0].End] != "alice@example.com" {
		t.Fatalf("offset is not a UTF-8 byte span: %+v", findings[0])
	}
	findingType := reflect.TypeOf(Finding{})
	if _, ok := findingType.FieldByName("Text"); ok {
		t.Fatal("Finding must not retain plaintext Text")
	}

	first, err := engine.Redact(context.Background(), input, RequestOptions{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := engine.Redact(context.Background(), first.Redacted, RequestOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if second.Redacted != first.Redacted || second.Hit() {
		t.Fatalf("redaction is not idempotent: first=%q second=%+v", first.Redacted, second)
	}
}

func TestCustomAllowlistsAndStrictCaptureValidation(t *testing.T) {
	engine := customEngine(t, `
[allowlist]
regexes = ['''^GLOBALALLOW$''']
stopwords = ["stopme"]

[[rules]]
id = "token-rule"
regex = '''token=([A-Z]{10,12})'''
keywords = ["token="]

[[rules.allowlists]]
regexTarget = "match"
regexes = ['''^token=LOCALALLOW$''']

[[rules.allowlists]]
condition = "AND"
regexTarget = "line"
regexes = ['''SAFE-LINE''']
stopwords = ["permit"]
`)
	for _, input := range []string{
		"token=GLOBALALLOW",
		"token=STOPMESTOPME",
		"token=LOCALALLOW",
		"SAFE-LINE token=PERMITAAAA",
	} {
		findings, err := engine.Detect(context.Background(), input, RequestOptions{})
		if err != nil {
			t.Fatalf("Detect(%q): %v", input, err)
		}
		if len(findings) != 0 {
			t.Errorf("allowlist failed for %q: %+v", input, findings)
		}
	}

	_, report, err := New(Config{
		CustomMode: CustomRulesReplace,
		CustomTOML: []byte(`
[[rules]]
id = "bad-group"
regex = '''(x)'''
secretGroup = 2
`),
	})
	if !errors.Is(err, ErrIncompatibleRules) || report.Compatible() {
		t.Fatalf("invalid capture group accepted: err=%v report=%+v", err, report)
	}

	_, _, err = New(Config{
		CustomMode: CustomRulesReplace,
		CustomTOML: []byte(`
[[rules]]
id = "unknown"
regex = '''x'''
mystery = true
`),
	})
	if !errors.Is(err, ErrIncompatibleRules) {
		t.Fatalf("unknown custom semantic accepted: %v", err)
	}
}

func TestCustomExtendAndReplace(t *testing.T) {
	embedded := []byte(`
[[rules]]
id = "embedded"
regex = '''EMBEDDED_SECRET'''
`)
	custom := []byte(`
[[rules]]
id = "custom"
regex = '''CUSTOM_SECRET'''
`)
	extended, _, err := New(Config{EmbeddedTOML: embedded, CustomTOML: custom, CustomMode: CustomRulesExtend})
	if err != nil {
		t.Fatal(err)
	}
	findings, err := extended.Detect(context.Background(), "EMBEDDED_SECRET CUSTOM_SECRET", RequestOptions{})
	if err != nil || len(findings) != 2 {
		t.Fatalf("extend mode: findings=%+v err=%v", findings, err)
	}
	replaced, _, err := New(Config{EmbeddedTOML: embedded, CustomTOML: custom, CustomMode: CustomRulesReplace})
	if err != nil {
		t.Fatal(err)
	}
	findings, err = replaced.Detect(context.Background(), "EMBEDDED_SECRET CUSTOM_SECRET", RequestOptions{})
	if err != nil || len(findings) != 1 || findings[0].RuleID != "custom" {
		t.Fatalf("replace mode: findings=%+v err=%v", findings, err)
	}
}

func TestBudgetCancellationAndRequestRenderer(t *testing.T) {
	engine := customEngine(t, `
[[rules]]
id = "never"
regex = '''NEVER_MATCH'''
`)

	bytesBudget, _ := NewBudget(Limits{MaxBytes: 3, MaxFindings: 10, MaxNodes: 10})
	if _, err := engine.Detect(context.Background(), "four", RequestOptions{Budget: bytesBudget}); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("byte limit: %v", err)
	}

	nodeBudget, _ := NewBudget(Limits{MaxBytes: 100, MaxFindings: 10, MaxNodes: 1})
	if _, err := engine.Detect(context.Background(), "clean", RequestOptions{Budget: nodeBudget}); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Detect(context.Background(), "clean", RequestOptions{Budget: nodeBudget}); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("node limit: %v", err)
	}

	findingBudget, _ := NewBudget(Limits{MaxBytes: 1000, MaxFindings: 1, MaxNodes: 10})
	if _, err := engine.Detect(context.Background(), "a@example.com b@example.com", RequestOptions{Budget: findingBudget}); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("finding limit: %v", err)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := engine.Detect(cancelled, "a@example.com", RequestOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}

	seenPlaintext := ""
	renderer := RendererFunc(func(_ context.Context, finding Finding, plaintext string) (string, error) {
		seenPlaintext = plaintext
		return "<" + string(finding.Kind) + ">", nil
	})
	result, err := engine.Redact(context.Background(), "mail a@example.com", RequestOptions{Renderer: renderer})
	if err != nil {
		t.Fatal(err)
	}
	if seenPlaintext != "a@example.com" || result.Redacted != "mail <email>" {
		t.Fatalf("request renderer: plaintext=%q result=%+v", seenPlaintext, result)
	}
}
