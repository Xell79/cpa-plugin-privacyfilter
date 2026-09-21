package main

import (
	"context"
	"encoding/json"
	"math"
	"os"
	"strings"
	"testing"

	"github.com/ahoo/cpa-plugin-privacyfilter/internal/privacyengine"
)

// TestMLParity checks the Go scorer against probabilities produced by the
// Python training script on held-out eval cases.
func TestMLParity(t *testing.T) {
	raw, err := os.ReadFile("testdata/ml_parity.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var fixture map[string]struct {
		Text  string  `json:"text"`
		Score float64 `json:"score"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	for id, want := range fixture {
		got, err := mlScore(want.Text)
		if err != nil {
			t.Fatalf("%s: score error: %v", id, err)
		}
		if math.Abs(got-want.Score) > 1e-9 {
			t.Fatalf("%s: score = %.9f, want %.9f", id, got, want.Score)
		}
	}
}

// TestMLThresholdSeparation guards the validated gap on representative
// short texts: model positives score above 0.5, negatives below. The known
// email-in-Chinese-context FN (inj5, 0.34) is tracked in the offline eval,
// not here.
func TestMLThresholdSeparation(t *testing.T) {
	positives := []string{
		"我的电话是13800138000，尽快联系",
		`{"api_key": "sk-live-abc123XYZ789qwer"}`,
		"password=P@ssw0rd!2026",
		"ghp_1234567890abcdefghij1234567890ab",
	}
	negatives := []string{
		"hi",
		"the monkey ate a banana token_id=42",
		`api_key_name = "production"`,
		"sk-test placeholder, replace before use",
		"AK is fine, SK is fine, nothing here",
	}
	minPos := 1.0
	maxNeg := 0.0
	for _, text := range positives {
		score, err := mlScore("请帮我看下这段配置有没有问题：\n" + text)
		if err != nil {
			t.Fatalf("score error: %v", err)
		}
		if score < minPos {
			minPos = score
		}
	}
	for _, text := range negatives {
		score, err := mlScore("请帮我看下这段配置有没有问题：\n" + text)
		if err != nil {
			t.Fatalf("score error: %v", err)
		}
		if score > maxNeg {
			maxNeg = score
		}
	}
	if minPos <= maxNeg {
		t.Fatalf("no separation gap: min positive %.4f <= max negative %.4f", minPos, maxNeg)
	}
	if minPos < 0.5 || maxNeg > 0.5 {
		t.Fatalf("0.5 threshold violated: min positive %.4f, max negative %.4f", minPos, maxNeg)
	}
}

// TestMLAssistConfigDefaults ensures the assist stays off unless enabled.
func TestMLAssistConfigDefaults(t *testing.T) {
	cfg, err := parseConfig(nil)
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if cfg.MLAssist.Enabled {
		t.Fatal("ml_assist must default to disabled")
	}
	if cfg.MLAssist.effectiveThreshold() != 0.5 {
		t.Fatalf("default threshold = %v, want 0.5", cfg.MLAssist.effectiveThreshold())
	}
	if cfg.MLAssist.enforce() {
		t.Fatal("default mode must not enforce")
	}
	cfg2, err := parseConfig([]byte("ml_assist:\n  enabled: true\n  threshold: 0.7\n  mode: enforce\n"))
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if !cfg2.MLAssist.Enabled || cfg2.MLAssist.effectiveThreshold() != 0.7 || !cfg2.MLAssist.enforce() {
		t.Fatalf("ml_assist not parsed: %+v", cfg2.MLAssist)
	}
	if _, err := parseConfig([]byte("ml_assist:\n  enabled: true\n  mode: destroy\n")); err == nil {
		t.Fatal("expected error for invalid ml mode")
	}
}

// TestMLSeamAudit verifies the second opinion counts engine-clean sensitive
// text without changing it.
func TestMLSeamAudit(t *testing.T) {
	plugin := newTestPlugin(t)
	plugin.cfg.MLAssist = mlAssistConfig{Enabled: true, Mode: mlAssistAudit}
	renderer := newRequestRenderer(plugin.renderer)
	budget, err := newBudgetForTest(plugin, t)
	if err != nil {
		t.Fatalf("budget: %v", err)
	}
	mlHits := 0
	out, findings, changed, err := plugin.sanitizeText(context.Background(), "请帮我看下这段配置有没有问题：\nghp_1234567890abcdefghij1234567890ab", budget, renderer, privacyengine.FieldContext{}, &mlHits)
	if err != nil {
		t.Fatalf("sanitizeText: %v", err)
	}
	_ = out
	_ = findings
	_ = changed
	if mlHits != 1 {
		t.Fatalf("mlHits = %d, want 1 (findings=%d changed=%v)", mlHits, findings, changed)
	}
	if changed {
		t.Fatal("audit mode must not change text")
	}
}

// TestMLSeamSkipsCleanText ensures benign text is untouched and uncounted.
func TestMLSeamSkipsCleanText(t *testing.T) {
	plugin := newTestPlugin(t)
	plugin.cfg.MLAssist = mlAssistConfig{Enabled: true, Mode: mlAssistAudit}
	renderer := newRequestRenderer(plugin.renderer)
	budget, err := newBudgetForTest(plugin, t)
	if err != nil {
		t.Fatalf("budget: %v", err)
	}
	mlHits := 0
	_, findings, changed, err := plugin.sanitizeText(context.Background(), "hi, 继续观察", budget, renderer, privacyengine.FieldContext{}, &mlHits)
	if err != nil {
		t.Fatalf("sanitizeText: %v", err)
	}
	if changed || findings != 0 || mlHits != 0 {
		t.Fatalf("benign text touched: changed=%v findings=%d mlHits=%d", changed, findings, mlHits)
	}
}

// TestMLSeamEnforce verifies enforce mode redacts engine-clean sensitive text.
func TestMLSeamEnforce(t *testing.T) {
	plugin := newTestPlugin(t)
	plugin.cfg.MLAssist = mlAssistConfig{Enabled: true, Mode: mlAssistEnforce}
	renderer := newRequestRenderer(plugin.renderer)
	budget, err := newBudgetForTest(plugin, t)
	if err != nil {
		t.Fatalf("budget: %v", err)
	}
	mlHits := 0
	out, findings, changed, err := plugin.sanitizeText(context.Background(), "请帮我看下这段配置有没有问题：\nghp_1234567890abcdefghij1234567890ab", budget, renderer, privacyengine.FieldContext{}, &mlHits)
	if err != nil {
		t.Fatalf("sanitizeText: %v", err)
	}
	if !changed || findings != 1 || mlHits != 1 {
		t.Fatalf("enforce must redact: changed=%v findings=%d mlHits=%d out=%q", changed, findings, mlHits, out)
	}
	if strings.Contains(out, "ghp_") {
		t.Fatal("enforce must replace sensitive text")
	}
}

func newBudgetForTest(plugin *privacyFilterPlugin, t *testing.T) (*privacyengine.Budget, error) {
	t.Helper()
	return privacyengine.NewBudget(plugin.cfg.engineLimits())
}
