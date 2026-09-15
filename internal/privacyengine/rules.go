package privacyengine

import (
	"fmt"
	"math"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
)

type rawTOMLConfig struct {
	Title      string         `toml:"title"`
	MinVersion string         `toml:"minVersion"`
	Allowlist  *rawAllowlist  `toml:"allowlist"`
	Allowlists []rawAllowlist `toml:"allowlists"`
	Rules      []rawRule      `toml:"rules"`
}

type rawRule struct {
	ID          string         `toml:"id"`
	Description string         `toml:"description"`
	Regex       string         `toml:"regex"`
	Path        string         `toml:"path"`
	Keywords    []string       `toml:"keywords"`
	Entropy     float64        `toml:"entropy"`
	SecretGroup *int           `toml:"secretGroup"`
	Allowlist   *rawAllowlist  `toml:"allowlist"`
	Allowlists  []rawAllowlist `toml:"allowlists"`
}

type rawAllowlist struct {
	Description string   `toml:"description"`
	Condition   string   `toml:"condition"`
	RegexTarget string   `toml:"regexTarget"`
	Commits     []string `toml:"commits"`
	Paths       []string `toml:"paths"`
	Regexes     []string `toml:"regexes"`
	Stopwords   []string `toml:"stopwords"`
}

type allowlistCondition uint8

const (
	allowlistOR allowlistCondition = iota
	allowlistAND
)

type allowlistRegexTarget uint8

const (
	allowlistSecret allowlistRegexTarget = iota
	allowlistMatch
	allowlistLine
)

type compiledAllowlist struct {
	condition allowlistCondition
	target    allowlistRegexTarget
	regexes   []*regexp.Regexp
	stopwords []string
}

type secretRule struct {
	id               string
	re               *regexp.Regexp
	keywords         []string
	entropy          float64
	secretGroup      int
	automaticCapture bool
	allowlists       []compiledAllowlist
}

type parsedRuleSet struct {
	rules            []secretRule
	globalAllowlists []compiledAllowlist
	report           CompatibilityReport
}

func parseRuleSet(data []byte, source RuleSource, policy CompatibilityPolicy) (parsedRuleSet, error) {
	var out parsedRuleSet
	if len(data) == 0 {
		return out, fmt.Errorf("privacyengine: %s TOML is empty", source)
	}

	var cfg rawTOMLConfig
	metadata, err := toml.Decode(string(data), &cfg)
	if err != nil {
		return out, fmt.Errorf("privacyengine: parse %s TOML: %w", source, err)
	}

	for _, key := range metadata.Undecoded() {
		out.addIssue(policy, CompatibilityIssue{
			Source: source, Feature: "toml." + key.String(),
			Detail: "unknown field or unsupported table",
		})
	}

	if cfg.Allowlist != nil && len(cfg.Allowlists) != 0 {
		out.addIssue(policy, CompatibilityIssue{
			Source: source, Feature: "global.allowlist",
			Detail: "singular and plural global allowlists cannot be mixed",
		})
	}
	if cfg.Allowlist != nil {
		if allowlist, ok := compileAllowlist(*cfg.Allowlist, source, "", "global.allowlist", policy, &out.report); ok {
			out.globalAllowlists = append(out.globalAllowlists, allowlist)
		}
	}
	for i, rawAllowlist := range cfg.Allowlists {
		feature := fmt.Sprintf("global.allowlists[%d]", i)
		if allowlist, ok := compileAllowlist(rawAllowlist, source, "", feature, policy, &out.report); ok {
			out.globalAllowlists = append(out.globalAllowlists, allowlist)
		}
	}

	out.report.RulesSeen = len(cfg.Rules)
	seenIDs := make(map[string]struct{}, len(cfg.Rules))
	for i := range cfg.Rules {
		raw := &cfg.Rules[i]
		ruleID := strings.TrimSpace(raw.ID)
		invalid := false
		invalidate := func(feature, detail string) {
			out.addRuleIssue(policy, ruleID, source, feature, detail, &invalid)
		}

		if ruleID == "" {
			invalidate("rule.id", "rule id is required")
		} else if _, exists := seenIDs[ruleID]; exists {
			invalidate("rule.id", "duplicate rule id")
		} else {
			seenIDs[ruleID] = struct{}{}
		}

		if raw.Path != "" {
			if _, pathErr := regexp.Compile(raw.Path); pathErr != nil {
				invalidate("rule.path", "path regular expression does not compile")
			} else if raw.Regex == "" {
				invalidate("rule.path-only", "path-only rules cannot produce a protocol-text span")
			} else {
				invalidate("rule.path", "path-constrained rules do not run for pathless protocol text")
			}
		}
		if raw.Regex == "" {
			if raw.Path == "" {
				invalidate("rule.regex", "content regular expression is required")
			}
			out.finishInvalidRule(policy, invalid)
			continue
		}

		re, compileErr := regexp.Compile(raw.Regex)
		if compileErr != nil {
			invalidate("rule.regex", "regular expression is not compatible with Go RE2")
		}
		if math.IsNaN(raw.Entropy) || math.IsInf(raw.Entropy, 0) || raw.Entropy < 0 {
			invalidate("rule.entropy", "entropy must be a finite non-negative number")
		}

		secretGroup := 0
		automaticCapture := raw.SecretGroup == nil
		if raw.SecretGroup != nil {
			secretGroup = *raw.SecretGroup
		}
		if re != nil && (secretGroup < 0 || secretGroup > re.NumSubexp()) {
			invalidate("rule.secretGroup", fmt.Sprintf("capture group %d is outside 0..%d", secretGroup, re.NumSubexp()))
		}

		keywords := make([]string, 0, len(raw.Keywords))
		for _, keyword := range raw.Keywords {
			if keyword == "" {
				invalidate("rule.keywords", "keywords must not contain an empty string")
				continue
			}
			keywords = append(keywords, strings.ToLower(keyword))
		}

		allowlists := make([]compiledAllowlist, 0, len(raw.Allowlists)+1)
		if raw.Allowlist != nil && len(raw.Allowlists) != 0 {
			out.addIssue(policy, CompatibilityIssue{
				Source: source, RuleID: ruleID, Feature: "rule.allowlist",
				Detail: "singular and plural rule allowlists cannot be mixed",
			})
		}
		if raw.Allowlist != nil {
			if allowlist, ok := compileAllowlist(*raw.Allowlist, source, ruleID, "rule.allowlist", policy, &out.report); ok {
				allowlists = append(allowlists, allowlist)
			}
		}
		for allowlistIndex, rawAllowlist := range raw.Allowlists {
			feature := fmt.Sprintf("rule.allowlists[%d]", allowlistIndex)
			if allowlist, ok := compileAllowlist(rawAllowlist, source, ruleID, feature, policy, &out.report); ok {
				allowlists = append(allowlists, allowlist)
			}
		}

		if invalid {
			out.finishInvalidRule(policy, true)
			continue
		}
		out.rules = append(out.rules, secretRule{
			id:               ruleID,
			re:               re,
			keywords:         keywords,
			entropy:          raw.Entropy,
			secretGroup:      secretGroup,
			automaticCapture: automaticCapture,
			allowlists:       allowlists,
		})
		out.report.RulesLoaded++
	}

	if len(cfg.Rules) == 0 {
		out.addIssue(policy, CompatibilityIssue{
			Source: source, Feature: "rules", Detail: "ruleset contains no rules",
		})
	}
	if hasRejected(out.report) {
		return out, &RulesCompatibilityError{Report: out.report}
	}
	return out, nil
}

func (p *parsedRuleSet) addIssue(policy CompatibilityPolicy, issue CompatibilityIssue) {
	if policy == CompatibilitySkipUnsupported {
		issue.Action = CompatibilityIgnored
	} else {
		issue.Action = CompatibilityRejected
	}
	p.report.Issues = append(p.report.Issues, issue)
}

func (p *parsedRuleSet) addRuleIssue(policy CompatibilityPolicy, ruleID string, source RuleSource, feature, detail string, invalid *bool) {
	issue := CompatibilityIssue{Source: source, RuleID: ruleID, Feature: feature, Detail: detail}
	if policy == CompatibilitySkipUnsupported {
		issue.Action = CompatibilitySkipped
	} else {
		issue.Action = CompatibilityRejected
	}
	p.report.Issues = append(p.report.Issues, issue)
	*invalid = true
}

func (p *parsedRuleSet) finishInvalidRule(policy CompatibilityPolicy, invalid bool) {
	if invalid && policy == CompatibilitySkipUnsupported {
		p.report.RulesSkipped++
	}
}

func hasRejected(report CompatibilityReport) bool {
	for _, issue := range report.Issues {
		if issue.Action == CompatibilityRejected {
			return true
		}
	}
	return false
}

func compileAllowlist(raw rawAllowlist, source RuleSource, ruleID, feature string, policy CompatibilityPolicy, report *CompatibilityReport) (compiledAllowlist, bool) {
	compiled := compiledAllowlist{condition: allowlistOR, target: allowlistSecret}
	invalid := false
	addIssue := func(suffix, detail string, unsupported bool) {
		action := CompatibilityRejected
		if policy == CompatibilitySkipUnsupported {
			action = CompatibilityIgnored
		}
		report.Issues = append(report.Issues, CompatibilityIssue{
			Source: source, RuleID: ruleID, Feature: feature + suffix,
			Action: action, Detail: detail,
		})
		if !unsupported || policy == CompatibilityError {
			invalid = true
		}
	}

	switch strings.ToUpper(raw.Condition) {
	case "", "OR", "||":
		compiled.condition = allowlistOR
	case "AND", "&&":
		compiled.condition = allowlistAND
	default:
		addIssue(".condition", "condition must be OR or AND", false)
	}

	switch raw.RegexTarget {
	case "", "secret":
		compiled.target = allowlistSecret
	case "match":
		compiled.target = allowlistMatch
	case "line":
		compiled.target = allowlistLine
	default:
		addIssue(".regexTarget", "regexTarget must be secret, match, or line", false)
	}

	for _, expression := range raw.Regexes {
		re, err := regexp.Compile(expression)
		if err != nil {
			addIssue(".regexes", "allowlist regular expression does not compile", false)
			continue
		}
		compiled.regexes = append(compiled.regexes, re)
	}
	for _, stopword := range raw.Stopwords {
		if stopword == "" {
			addIssue(".stopwords", "stopwords must not contain an empty string", false)
			continue
		}
		compiled.stopwords = append(compiled.stopwords, strings.ToLower(stopword))
	}

	// The protocol engine has no repository path or commit metadata. In skip
	// mode these criteria are explicitly reported and treated as never matching.
	// An AND block containing one is therefore inert; an OR block can still use
	// its supported regex/stopword criteria.
	unsupportedCriterion := false
	if len(raw.Paths) != 0 {
		addIssue(".paths", "path criteria are unavailable for protocol text", true)
		unsupportedCriterion = true
	}
	if len(raw.Commits) != 0 {
		addIssue(".commits", "commit criteria are unavailable for protocol text", true)
		unsupportedCriterion = true
	}
	if policy == CompatibilitySkipUnsupported && compiled.condition == allowlistAND && unsupportedCriterion {
		return compiledAllowlist{}, false
	}

	if invalid {
		return compiledAllowlist{}, false
	}
	if len(compiled.regexes) == 0 && len(compiled.stopwords) == 0 {
		if unsupportedCriterion && policy == CompatibilitySkipUnsupported {
			return compiledAllowlist{}, false
		}
		addIssue("", "allowlist has no supported criteria", false)
		return compiledAllowlist{}, false
	}
	return compiled, true
}
