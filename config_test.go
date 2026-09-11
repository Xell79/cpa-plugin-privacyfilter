package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/internal/privacyengine"
)

func TestParseConfigDefaultsAreProtective(t *testing.T) {
	cfg, err := parseConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != modeRedact || cfg.OnError != onErrorBlock {
		t.Fatalf("defaults = mode %q on_error %q", cfg.Mode, cfg.OnError)
	}
	if cfg.Limits.MaxBodyBytes <= 0 || cfg.Limits.MaxTextBytes <= 0 || cfg.Limits.MaxFindings <= 0 {
		t.Fatalf("limits are not bounded: %+v", cfg.Limits)
	}
}

func TestParseConfigRejectsUnknownFieldAndMultipleDocuments(t *testing.T) {
	for _, raw := range []string{
		"typo_field: true\n",
		"mode: redact\n---\nmode: audit\n",
	} {
		if _, err := parseConfig([]byte(raw)); err == nil {
			t.Fatalf("parseConfig(%q) succeeded", raw)
		}
	}
}

func TestParseConfigPreservesLegacyFields(t *testing.T) {
	raw := []byte(`
gitleaks_toml: custom.toml
skip_models: [gpt-4]
skip_formats: [openai]
`)
	cfg, err := parseConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.GitleaksTOML != "custom.toml" || len(cfg.SkipModels) != 1 || len(cfg.SkipFormats) != 1 {
		t.Fatalf("legacy fields were not preserved: %+v", cfg)
	}
	if cfg.GitleaksMode != "" {
		t.Fatalf("legacy custom file should retain implicit replace mode, got %q", cfg.GitleaksMode)
	}
}

func TestParseConfigValidatesModesRulesReplacementsAndLimits(t *testing.T) {
	invalid := []string{
		"mode: remove\n",
		"on_error: ignore\n",
		"gitleaks_mode: extend\n",
		"gitleaks_toml: x\ngitleaks_mode: merge\n",
		"replacements:\n  unknown: x\n",
		"block_rule_ids: ['', x]\n",
		"block_rule_ids: [x, x]\n",
		"limits:\n  max_text_bytes: 0\n",
		"limits:\n  max_body_bytes: -1\n",
	}
	for _, raw := range invalid {
		if _, err := parseConfig([]byte(raw)); err == nil {
			t.Errorf("parseConfig accepted invalid config:\n%s", raw)
		}
	}
}

func TestReplacementRendererOverridesTypedLabel(t *testing.T) {
	cfg, err := parseConfig([]byte("replacements:\n  secret: '<SECRET>'\n"))
	if err != nil {
		t.Fatal(err)
	}
	renderer, err := cfg.renderer()
	if err != nil {
		t.Fatal(err)
	}
	got, err := renderer.Render(context.Background(), privacyengine.Finding{Kind: privacyengine.KindSecret}, "do-not-retain")
	if err != nil {
		t.Fatal(err)
	}
	if got != "<SECRET>" {
		t.Fatalf("replacement = %q", got)
	}
}

func TestBuildPluginRejectsSensitiveReplacement(t *testing.T) {
	_, err := buildPlugin([]byte("replacements:\n  email: test@example.com\n"), t.TempDir())
	if err == nil {
		t.Fatal("buildPlugin accepted a replacement that the engine redacts")
	}
}

func TestConventionalSidecarUsesReportedCompatibility(t *testing.T) {
	dir := t.TempDir()
	rulesDir := filepath.Join(dir, "rules")
	if err := os.MkdirAll(rulesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rulesDir, "gitleaks.toml"), embeddedGitleaks, 0o600); err != nil {
		t.Fatal(err)
	}
	engine, report, err := newEngine(dir, defaultConfig())
	if err != nil {
		t.Fatalf("newEngine(sidecar): %v (report=%+v)", err, report)
	}
	loaded, skipped := engine.Stats()
	if loaded != 217 || skipped != 5 {
		t.Fatalf("sidecar stats = %d/%d; report=%+v", loaded, skipped, report)
	}
}

func TestCustomRulesRequireExplicitCompatibleSemantics(t *testing.T) {
	dir := t.TempDir()
	rules := []byte(`
[[rules]]
id = "custom-token"
regex = '''CUSTOM_[A-Z]{12}'''
keywords = ["CUSTOM_"]
`)
	if err := os.WriteFile(filepath.Join(dir, "custom.toml"), rules, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := parseConfig([]byte("gitleaks_toml: custom.toml\ngitleaks_mode: extend\n"))
	if err != nil {
		t.Fatal(err)
	}
	engine, report, err := newEngine(dir, cfg)
	if err != nil {
		t.Fatalf("newEngine: %v (report=%+v)", err, report)
	}
	findings, err := engine.Detect(context.Background(), "CUSTOM_ABCDEFGHIJKL", privacyengine.RequestOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].RuleID != "custom-token" {
		t.Fatalf("custom finding = %+v", findings)
	}
	if report.RulesSeen != 223 {
		t.Fatalf("extend report = %+v", report)
	}
}

func TestConfiguredUnsupportedRuleRequiresExplicitOptIn(t *testing.T) {
	dir := t.TempDir()
	rules := []byte(`
[[rules]]
id = "path-only"
path = '''secret\\.pem$'''
`)
	if err := os.WriteFile(filepath.Join(dir, "custom.toml"), rules, 0o600); err != nil {
		t.Fatal(err)
	}
	strict, err := parseConfig([]byte("gitleaks_toml: custom.toml\ngitleaks_mode: extend\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := newEngine(dir, strict); err == nil {
		t.Fatal("strict custom rules accepted unsupported path semantics")
	}

	compatible, err := parseConfig([]byte("gitleaks_toml: custom.toml\ngitleaks_mode: extend\nallow_unsupported_rules: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	_, report, err := newEngine(dir, compatible)
	if err != nil {
		t.Fatalf("explicit compatibility opt-in failed: %v", err)
	}
	if report.RulesSkipped == 0 || report.Compatible() {
		t.Fatalf("compatibility concession was not reported: %+v", report)
	}
}

func TestLegacyCustomRulesReplaceEmbeddedSnapshot(t *testing.T) {
	dir := t.TempDir()
	rules := []byte(`
[[rules]]
id = "only-rule"
regex = '''ONLY_[A-Z]{12}'''
keywords = ["ONLY_"]
`)
	if err := os.WriteFile(filepath.Join(dir, "custom.toml"), rules, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := parseConfig([]byte("gitleaks_toml: custom.toml\n"))
	if err != nil {
		t.Fatal(err)
	}
	engine, report, err := newEngine(dir, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if report.RulesSeen != 1 || report.RulesLoaded != 1 {
		t.Fatalf("replace report = %+v", report)
	}
	findings, err := engine.Detect(context.Background(), "LTAIABCDEFGHIJKLMNOPQRST", privacyengine.RequestOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("embedded rule unexpectedly active in replace mode: %+v", findings)
	}
}
