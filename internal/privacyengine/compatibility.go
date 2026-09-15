package privacyengine

import "fmt"

// RuleSource identifies which TOML input produced a compatibility item.
type RuleSource string

const (
	RuleSourceEmbedded RuleSource = "embedded"
	RuleSourceCustom   RuleSource = "custom"
)

// CompatibilityPolicy controls unsupported rule semantics. The zero value is
// strict and rejects them. CompatibilitySkipUnsupported must be selected
// explicitly, and is intended for a pinned embedded snapshot whose report is
// reviewed by the caller.
type CompatibilityPolicy uint8

const (
	CompatibilityError CompatibilityPolicy = iota
	CompatibilitySkipUnsupported
)

// CustomRuleMode says how custom TOML combines with the embedded snapshot.
// A non-empty custom ruleset requires an explicit non-zero mode.
type CustomRuleMode uint8

const (
	CustomRulesNone CustomRuleMode = iota
	CustomRulesExtend
	CustomRulesReplace
)

// CompatibilityAction records what the loader did with unsupported semantics.
type CompatibilityAction string

const (
	CompatibilityRejected CompatibilityAction = "rejected"
	CompatibilitySkipped  CompatibilityAction = "skipped"
	CompatibilityIgnored  CompatibilityAction = "ignored"
)

// CompatibilityIssue is safe to log: it identifies configuration metadata,
// never a match or request plaintext.
type CompatibilityIssue struct {
	Source  RuleSource          `json:"source"`
	RuleID  string              `json:"rule_id,omitempty"`
	Feature string              `json:"feature"`
	Action  CompatibilityAction `json:"action"`
	Detail  string              `json:"detail,omitempty"`
}

// CompatibilityReport makes every compatibility concession observable.
type CompatibilityReport struct {
	RulesSeen    int                  `json:"rules_seen"`
	RulesLoaded  int                  `json:"rules_loaded"`
	RulesSkipped int                  `json:"rules_skipped"`
	Issues       []CompatibilityIssue `json:"issues,omitempty"`
}

// Compatible reports whether the TOML required no compatibility concessions.
func (r CompatibilityReport) Compatible() bool { return len(r.Issues) == 0 }

func (r *CompatibilityReport) append(other CompatibilityReport) {
	r.RulesSeen += other.RulesSeen
	r.RulesLoaded += other.RulesLoaded
	r.RulesSkipped += other.RulesSkipped
	r.Issues = append(r.Issues, other.Issues...)
}

// RulesCompatibilityError carries the report produced before construction was
// refused. Use errors.Is(err, ErrIncompatibleRules) for classification.
type RulesCompatibilityError struct {
	Report CompatibilityReport
}

func (e *RulesCompatibilityError) Error() string {
	if e == nil {
		return ErrIncompatibleRules.Error()
	}
	return fmt.Sprintf("%s: %d issue(s)", ErrIncompatibleRules, len(e.Report.Issues))
}

func (e *RulesCompatibilityError) Unwrap() error { return ErrIncompatibleRules }
