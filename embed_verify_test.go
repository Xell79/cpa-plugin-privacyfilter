package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestNewEngineUsesEmbeddedRules simulates a store install: an empty plugin
// directory with no sidecar. Rules must compile directly from embedded bytes;
// the plugin must not materialize sensitive policy state in a temporary file.
func TestNewEngineUsesEmbeddedRules(t *testing.T) {
	engine, report, err := newEngine(t.TempDir(), defaultConfig())
	if err != nil {
		t.Fatalf("newEngine() with embedded rules: %v", err)
	}
	loaded, skipped := engine.Stats()
	if loaded != 217 || skipped != 5 {
		t.Fatalf("stats = %d loaded, %d skipped; report=%+v", loaded, skipped, report)
	}
	if report.RulesSeen != 222 {
		t.Fatalf("rules seen = %d, want 222", report.RulesSeen)
	}

	matches, err := filepath.Glob(filepath.Join(os.TempDir(), "privacyfilter-gitleaks-*.toml"))
	if err != nil {
		t.Fatalf("glob temp rules: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("unexpected temporary rules file: %v", matches)
	}
}
