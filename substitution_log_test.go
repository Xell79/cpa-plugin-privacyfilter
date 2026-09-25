package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSubstitutionLogDisabledByDefault(t *testing.T) {
	cfg, err := parseConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SubstitutionLog.Enabled {
		t.Fatal("substitution_log must default to disabled")
	}
	if cfg.SubstitutionLog.effectivePath() != "logs/privacyfilter-substitutions.jsonl" {
		t.Fatalf("path = %q", cfg.SubstitutionLog.effectivePath())
	}
	if _, err := parseConfig([]byte("substitution_log:\n  enabled: true\n  path: \"../secrets.jsonl\"\n")); err == nil {
		t.Fatal("expected path escape to be rejected")
	}
}

func TestSubstitutionLogAppendsJSONL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "privacyfilter-substitutions.jsonl")
	logger, err := newSubstitutionLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	when := time.Date(2026, 9, 25, 8, 0, 0, 0, time.UTC)
	logger.now = func() time.Time { return when }
	logger.Record("email", "pii.email", "[EMAIL]", "a@example.com")
	logger.Record("secret", "pii.secret", "[SECRET#2]", "token-value")
	if err := logger.Close(); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 2 {
		t.Fatalf("lines = %d", len(lines))
	}
	var first substitutionRecord
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatal(err)
	}
	if first.Original != "a@example.com" || first.Placeholder != "[EMAIL]" || !first.Time.Equal(when) {
		t.Fatalf("record = %+v", first)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != substitutionLogFileMode {
		t.Fatalf("mode = %o", info.Mode().Perm())
	}
}
