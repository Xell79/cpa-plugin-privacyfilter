package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/rheodev/cpa-plugin-privacyfilter/internal/privacyengine"
	"github.com/rheodev/cpa-plugin-privacyfilter/payload"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

const privacyFilterProvider = "privacyfilter"
const pluginName = "privacyfilter"

type filterMode string

const (
	modeRedact filterMode = "redact"
	modeAudit  filterMode = "audit"
)

type errorPolicy string

const (
	onErrorBlock       errorPolicy = "block"
	onErrorPassthrough errorPolicy = "passthrough"
)

type customRuleMode string

const (
	customRulesExtend  customRuleMode = "extend"
	customRulesReplace customRuleMode = "replace"
)

type limitsConfig struct {
	MaxBodyBytes        int `yaml:"max_body_bytes"`
	MaxDepth            int `yaml:"max_depth"`
	MaxJSONNodes        int `yaml:"max_json_nodes"`
	MaxStringBytes      int `yaml:"max_string_bytes"`
	MaxReplacements     int `yaml:"max_replacements"`
	MaxReplacementBytes int `yaml:"max_replacement_bytes"`
	MaxTextBytes        int `yaml:"max_text_bytes"`
	MaxTextNodes        int `yaml:"max_text_nodes"`
	MaxFindings         int `yaml:"max_findings"`
}

type privacyFilterConfig struct {
	// Existing v0.2 fields remain valid.
	GitleaksTOML string   `yaml:"gitleaks_toml"`
	SkipModels   []string `yaml:"skip_models"`
	SkipFormats  []string `yaml:"skip_formats"`

	Mode                  filterMode        `yaml:"mode"`
	OnError               errorPolicy       `yaml:"on_error"`
	GitleaksMode          customRuleMode    `yaml:"gitleaks_mode"`
	AllowUnsupportedRules bool              `yaml:"allow_unsupported_rules"`
	BlockRuleIDs          []string          `yaml:"block_rule_ids"`
	Replacements          map[string]string `yaml:"replacements"`
	Limits                limitsConfig      `yaml:"limits"`
}

func defaultConfig() privacyFilterConfig {
	jsonLimits := payload.DefaultLimits()
	return privacyFilterConfig{
		Mode:    modeRedact,
		OnError: onErrorBlock,
		Limits: limitsConfig{
			MaxBodyBytes:        jsonLimits.MaxBodyBytes,
			MaxDepth:            jsonLimits.MaxDepth,
			MaxJSONNodes:        jsonLimits.MaxNodes,
			MaxStringBytes:      jsonLimits.MaxStringBytes,
			MaxReplacements:     jsonLimits.MaxReplacements,
			MaxReplacementBytes: jsonLimits.MaxReplacementBytes,
			// The detector budget is cumulative across every selected text node.
			// Keep it aligned with the body ceiling rather than the engine's
			// conservative one-text default; the JSON walker enforces the body cap.
			MaxTextBytes: jsonLimits.MaxBodyBytes,
			MaxTextNodes: 100_000,
			MaxFindings:  4_096,
		},
	}
}

func parseConfig(raw []byte) (privacyFilterConfig, error) {
	cfg := defaultConfig()
	if len(bytes.TrimSpace(raw)) == 0 {
		return cfg, nil
	}

	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("invalid privacyfilter config: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return cfg, fmt.Errorf("invalid privacyfilter config: multiple YAML documents are not allowed")
		}
		return cfg, fmt.Errorf("invalid privacyfilter config: %w", err)
	}
	if err := cfg.validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func (cfg privacyFilterConfig) validate() error {
	switch cfg.Mode {
	case modeRedact, modeAudit:
	default:
		return fmt.Errorf("invalid privacyfilter config: mode must be %q or %q", modeRedact, modeAudit)
	}
	switch cfg.OnError {
	case onErrorBlock, onErrorPassthrough:
	default:
		return fmt.Errorf("invalid privacyfilter config: on_error must be %q or %q", onErrorBlock, onErrorPassthrough)
	}
	if cfg.GitleaksMode != "" && cfg.GitleaksMode != customRulesExtend && cfg.GitleaksMode != customRulesReplace {
		return fmt.Errorf("invalid privacyfilter config: gitleaks_mode must be %q or %q", customRulesExtend, customRulesReplace)
	}
	if strings.TrimSpace(cfg.GitleaksTOML) == "" && cfg.GitleaksMode != "" {
		return fmt.Errorf("invalid privacyfilter config: gitleaks_mode requires gitleaks_toml")
	}
	if _, err := cfg.payloadLimits().Normalized(); err != nil {
		return fmt.Errorf("invalid privacyfilter config: %w", err)
	}
	if cfg.Limits.MaxTextBytes <= 0 || cfg.Limits.MaxTextNodes <= 0 || cfg.Limits.MaxFindings <= 0 {
		return fmt.Errorf("invalid privacyfilter config: detector limits must be positive")
	}
	for kind := range cfg.Replacements {
		if _, ok := replacementKind(kind); !ok {
			return fmt.Errorf("invalid privacyfilter config: unknown replacement kind %q", kind)
		}
	}
	seenRules := make(map[string]struct{}, len(cfg.BlockRuleIDs))
	for _, ruleID := range cfg.BlockRuleIDs {
		ruleID = strings.TrimSpace(ruleID)
		if ruleID == "" {
			return fmt.Errorf("invalid privacyfilter config: block_rule_ids cannot contain an empty id")
		}
		if _, duplicate := seenRules[ruleID]; duplicate {
			return fmt.Errorf("invalid privacyfilter config: duplicate block rule id %q", ruleID)
		}
		seenRules[ruleID] = struct{}{}
	}
	return nil
}

func (cfg privacyFilterConfig) payloadLimits() payload.Limits {
	return payload.Limits{
		MaxBodyBytes:        cfg.Limits.MaxBodyBytes,
		MaxDepth:            cfg.Limits.MaxDepth,
		MaxNodes:            cfg.Limits.MaxJSONNodes,
		MaxStringBytes:      cfg.Limits.MaxStringBytes,
		MaxReplacements:     cfg.Limits.MaxReplacements,
		MaxReplacementBytes: cfg.Limits.MaxReplacementBytes,
	}
}

func (cfg privacyFilterConfig) engineLimits() privacyengine.Limits {
	return privacyengine.Limits{
		MaxBytes:    cfg.Limits.MaxTextBytes,
		MaxNodes:    cfg.Limits.MaxTextNodes,
		MaxFindings: cfg.Limits.MaxFindings,
	}
}

func (cfg privacyFilterConfig) renderer() (privacyengine.Renderer, error) {
	overrides := make(map[privacyengine.Kind]string, len(cfg.Replacements))
	for name, replacement := range cfg.Replacements {
		kind, ok := replacementKind(name)
		if !ok {
			return nil, fmt.Errorf("unknown replacement kind %q", name)
		}
		overrides[kind] = replacement
	}
	return privacyengine.NewPlaceholderRenderer(overrides), nil
}

func replacementKind(name string) (privacyengine.Kind, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case string(privacyengine.KindEmail):
		return privacyengine.KindEmail, true
	case string(privacyengine.KindPhone):
		return privacyengine.KindPhone, true
	case string(privacyengine.KindIDCard):
		return privacyengine.KindIDCard, true
	case string(privacyengine.KindBankCard):
		return privacyengine.KindBankCard, true
	case string(privacyengine.KindIP):
		return privacyengine.KindIP, true
	case string(privacyengine.KindSecret):
		return privacyengine.KindSecret, true
	default:
		return "", false
	}
}

func (cfg privacyFilterConfig) blockRuleSet() map[string]struct{} {
	out := make(map[string]struct{}, len(cfg.BlockRuleIDs))
	for _, ruleID := range cfg.BlockRuleIDs {
		out[strings.TrimSpace(ruleID)] = struct{}{}
	}
	return out
}

func (cfg privacyFilterConfig) shouldSkip(model, requestedModel, format string) bool {
	for _, m := range cfg.SkipModels {
		trimmed := strings.TrimSpace(m)
		if strings.EqualFold(trimmed, model) || strings.EqualFold(trimmed, requestedModel) {
			return true
		}
	}
	for _, f := range cfg.SkipFormats {
		if strings.EqualFold(strings.TrimSpace(f), format) {
			return true
		}
	}
	return false
}

type ruleMaterial struct {
	embedded            []byte
	custom              []byte
	mode                privacyengine.CustomRuleMode
	customCompatibility privacyengine.CompatibilityPolicy
	source              string
}

func (cfg privacyFilterConfig) loadRuleMaterial(pluginDir string) (ruleMaterial, error) {
	configured := strings.TrimSpace(cfg.GitleaksTOML)
	if configured == "" {
		sidecar := filepath.Join(pluginDir, "rules", "gitleaks.toml")
		if data, err := os.ReadFile(sidecar); err == nil {
			// Preserve the v0.2 sidecar precedence as an explicit replace source.
			// The conventional sidecar is the same Gitleaks snapshot as the
			// embedded rules, so its known path-only features receive the same
			// visible compatibility report rather than making startup fail.
			return ruleMaterial{
				custom:              data,
				mode:                privacyengine.CustomRulesReplace,
				customCompatibility: privacyengine.CompatibilitySkipUnsupported,
				source:              sidecar,
			}, nil
		} else if !os.IsNotExist(err) {
			return ruleMaterial{}, fmt.Errorf("read privacy rules sidecar: %w", err)
		}
		return ruleMaterial{embedded: embeddedGitleaks, source: "embedded"}, nil
	}

	path := configured
	if !filepath.IsAbs(path) {
		path = filepath.Join(pluginDir, path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ruleMaterial{}, fmt.Errorf("read configured privacy rules: %w", err)
	}
	mode := privacyengine.CustomRulesReplace
	if cfg.GitleaksMode == customRulesExtend {
		mode = privacyengine.CustomRulesExtend
	}
	compatibility := privacyengine.CompatibilityError
	if cfg.AllowUnsupportedRules {
		compatibility = privacyengine.CompatibilitySkipUnsupported
	}
	material := ruleMaterial{
		custom:              data,
		mode:                mode,
		customCompatibility: compatibility,
		source:              path,
	}
	if mode == privacyengine.CustomRulesExtend {
		material.embedded = embeddedGitleaks
	}
	return material, nil
}

func newEngine(pluginDir string, cfg privacyFilterConfig) (*privacyengine.Engine, privacyengine.CompatibilityReport, error) {
	material, err := cfg.loadRuleMaterial(pluginDir)
	if err != nil {
		return nil, privacyengine.CompatibilityReport{}, err
	}
	engine, report, err := privacyengine.New(privacyengine.Config{
		EmbeddedTOML:          material.embedded,
		CustomTOML:            material.custom,
		CustomMode:            material.mode,
		EmbeddedCompatibility: privacyengine.CompatibilitySkipUnsupported,
		CustomCompatibility:   material.customCompatibility,
		DefaultLimits:         cfg.engineLimits(),
	})
	if err != nil {
		return nil, report, fmt.Errorf("create privacy engine: %w", err)
	}
	log.WithFields(log.Fields{
		"rules_seen":    report.RulesSeen,
		"rules_loaded":  report.RulesLoaded,
		"rules_skipped": report.RulesSkipped,
		"rule_source":   material.source,
	}).Info("privacyfilter: privacy engine loaded")
	return engine, report, nil
}
