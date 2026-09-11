package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/rheodev/cpa-plugin-privacyfilter/internal/privacyengine"
	"github.com/rheodev/cpa-plugin-privacyfilter/payload"
	"github.com/rheodev/cpa-plugin-privacyfilter/walker"
)

type sanitizeResult struct {
	body        []byte
	changed     bool
	findings    int
	targets     int
	skipped     int
	opaque      int
	unsupported int
}

type requestRenderer struct {
	mu   sync.Mutex
	base privacyengine.Renderer
	seen map[[sha256.Size]byte]string
	next map[privacyengine.Kind]int
}

func newRequestRenderer(base privacyengine.Renderer) *requestRenderer {
	return &requestRenderer{
		base: base,
		seen: make(map[[sha256.Size]byte]string),
		next: make(map[privacyengine.Kind]int),
	}
}

func (r *requestRenderer) Render(ctx context.Context, finding privacyengine.Finding, plaintext string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := sha256.Sum256([]byte(string(finding.Kind) + "\x00" + plaintext))
	if replacement, ok := r.seen[key]; ok {
		return replacement, nil
	}
	base, err := r.base.Render(ctx, finding, plaintext)
	if err != nil {
		return "", err
	}
	r.next[finding.Kind]++
	replacement := numberedPlaceholder(base, r.next[finding.Kind])
	r.seen[key] = replacement
	return replacement, nil
}

func numberedPlaceholder(base string, number int) string {
	if base == "" || number <= 1 {
		return base
	}
	suffix := "#" + strconv.Itoa(number)
	switch {
	case strings.HasSuffix(base, "]"):
		return strings.TrimSuffix(base, "]") + suffix + "]"
	case strings.HasSuffix(base, ">"):
		return strings.TrimSuffix(base, ">") + suffix + ">"
	default:
		return base + suffix
	}
}

func (p *privacyFilterPlugin) sanitizeRequest(ctx context.Context, sourceFormat string, body []byte) (sanitizeResult, error) {
	return p.sanitizeRequestWithRenderer(ctx, sourceFormat, body, newRequestRenderer(p.renderer))
}

func (p *privacyFilterPlugin) sanitizeRequestWithRenderer(
	ctx context.Context,
	sourceFormat string,
	body []byte,
	renderer privacyengine.Renderer,
) (sanitizeResult, error) {
	result := sanitizeResult{body: body}
	walked, err := walker.Walk(ctx, sourceFormat, body, walker.Options{
		ScanOptions: payload.ScanOptions{Limits: p.cfg.payloadLimits()},
	})
	if err != nil {
		return result, err
	}
	result.targets = len(walked.Targets)
	result.skipped = walked.Skipped
	result.opaque = walked.Opaque
	result.unsupported = walked.UnsupportedCount
	if walked.UnsupportedCount > 0 {
		return result, fmt.Errorf("%w: %d protocol block(s)", errUnsupportedRequestShape, walked.UnsupportedCount)
	}

	budget, err := privacyengine.NewBudget(p.cfg.engineLimits())
	if err != nil {
		return result, err
	}
	if renderer == nil {
		renderer = newRequestRenderer(p.renderer)
	}
	replacements := make([]payload.Replacement, 0, len(walked.Targets))
	for _, target := range walked.Targets {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		value, findings, changed, err := p.sanitizeTarget(ctx, target, budget, renderer)
		if err != nil {
			return result, err
		}
		result.findings += findings
		if changed && p.cfg.Mode != modeAudit {
			replacements = append(replacements, payload.Replacement{Token: target.Token, Value: value})
		}
	}
	if p.cfg.Mode == modeAudit || len(replacements) == 0 {
		return result, nil
	}
	out, changed, err := walked.Document.Replace(ctx, replacements)
	if err != nil {
		return result, err
	}
	if changed {
		result.body = out
		result.changed = true
	}
	return result, nil
}

func (p *privacyFilterPlugin) sanitizeTarget(
	ctx context.Context,
	target walker.Target,
	budget *privacyengine.Budget,
	renderer privacyengine.Renderer,
) (string, int, bool, error) {
	switch target.Mutable {
	case walker.MutabilityDirect:
		return p.sanitizeText(ctx, target.Token.Value, budget, renderer)
	case walker.MutabilityEncodedJSON:
		return p.sanitizeJSONText(ctx, target.Token.Value, budget, renderer, false)
	case walker.MutabilityJSONOrPlain:
		return p.sanitizeJSONText(ctx, target.Token.Value, budget, renderer, true)
	default:
		return target.Token.Value, 0, false, fmt.Errorf("%w: invalid target mutability", errUnsupportedRequestShape)
	}
}

func (p *privacyFilterPlugin) sanitizeJSONText(
	ctx context.Context,
	text string,
	budget *privacyengine.Budget,
	renderer privacyengine.Renderer,
	allowPlain bool,
) (string, int, bool, error) {
	document, err := payload.Scan(ctx, []byte(text), payload.ScanOptions{Limits: p.cfg.payloadLimits()})
	if err != nil {
		if allowPlain && errors.Is(err, payload.ErrInvalidJSON) {
			return p.sanitizeText(ctx, text, budget, renderer)
		}
		return text, 0, false, fmt.Errorf("%w: encoded tool JSON", errUnsupportedRequestShape)
	}
	replacements := make([]payload.Replacement, 0, len(document.Strings()))
	findingCount := 0
	for _, token := range document.Strings() {
		out, findings, changed, err := p.sanitizeText(ctx, token.Value, budget, renderer)
		if err != nil {
			return text, 0, false, err
		}
		findingCount += findings
		if changed && p.cfg.Mode != modeAudit {
			replacements = append(replacements, payload.Replacement{Token: token, Value: out})
		}
	}
	if p.cfg.Mode == modeAudit || len(replacements) == 0 {
		return text, findingCount, false, nil
	}
	out, changed, err := document.Replace(ctx, replacements)
	if err != nil {
		return text, 0, false, err
	}
	return string(out), findingCount, changed, nil
}

func (p *privacyFilterPlugin) sanitizeText(
	ctx context.Context,
	text string,
	budget *privacyengine.Budget,
	renderer privacyengine.Renderer,
) (string, int, bool, error) {
	result, err := p.engine.Redact(ctx, text, privacyengine.RequestOptions{
		Budget:           budget,
		Renderer:         renderer,
		PreferredRuleIDs: p.blockRuleIDs,
	})
	if err != nil {
		return text, 0, false, err
	}
	if p.cfg.Mode != modeAudit {
		for _, finding := range result.Findings {
			if _, blocked := p.blockRuleIDs[finding.RuleID]; blocked {
				return text, len(result.Findings), false, &blockedFindingError{ruleID: finding.RuleID}
			}
		}
	}
	return result.Redacted, len(result.Findings), result.Hit(), nil
}
