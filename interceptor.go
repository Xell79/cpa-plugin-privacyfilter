package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/rheodev/cpa-plugin-privacyfilter/internal/privacyengine"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	log "github.com/sirupsen/logrus"
)

type privacyFilterPlugin struct {
	cfg          privacyFilterConfig
	pluginDir    string
	engine       *privacyengine.Engine
	renderer     privacyengine.Renderer
	blockRuleIDs map[string]struct{}
}

var _ pluginapi.RequestInterceptor = (*privacyFilterPlugin)(nil)

var errUnsupportedRequestShape = errors.New("privacyfilter: unsupported request shape")

type blockedFindingError struct {
	ruleID string
}

func (e *blockedFindingError) Error() string {
	return "privacyfilter: request matched a blocking rule"
}

func (p *privacyFilterPlugin) Identifier() string {
	return privacyFilterProvider
}

func (p *privacyFilterPlugin) InterceptRequestBeforeAuth(ctx context.Context, req pluginapi.RequestInterceptRequest) (pluginapi.RequestInterceptResponse, error) {
	return p.interceptRequest(ctx, req)
}

func (p *privacyFilterPlugin) InterceptRequestAfterAuth(ctx context.Context, req pluginapi.RequestInterceptRequest) (pluginapi.RequestInterceptResponse, error) {
	return p.interceptRequest(ctx, req)
}

func (p *privacyFilterPlugin) interceptRequest(ctx context.Context, req pluginapi.RequestInterceptRequest) (pluginapi.RequestInterceptResponse, error) {
	if p.cfg.shouldSkip(req.Model, req.RequestedModel, req.SourceFormat) {
		log.WithFields(log.Fields{
			"source_format": safeLogValue(req.SourceFormat),
			"model":         safeLogValue(req.RequestedModel),
		}).Warn("privacyfilter: request bypassed by skip configuration")
		return pluginapi.RequestInterceptResponse{}, nil
	}
	if len(req.Body) == 0 {
		return pluginapi.RequestInterceptResponse{}, nil
	}

	budget, errBudget := privacyengine.NewBudget(p.cfg.engineLimits())
	if errBudget != nil {
		return p.handleFailure(req.SourceFormat, errBudget), nil
	}
	modified, findingCount, errRedact := p.redactRequestBody(ctx, req.Body, budget)
	if errRedact != nil {
		return p.handleFailure(req.SourceFormat, errRedact), nil
	}
	if findingCount > 0 {
		log.WithFields(log.Fields{
			"source_format": safeLogValue(req.SourceFormat),
			"model":         safeLogValue(req.RequestedModel),
			"findings":      findingCount,
			"mode":          string(p.cfg.Mode),
		}).Info("privacyfilter: sensitive values detected")
	}
	if p.cfg.Mode == modeAudit || modified == nil {
		return pluginapi.RequestInterceptResponse{}, nil
	}
	return pluginapi.RequestInterceptResponse{Body: modified}, nil
}

func (p *privacyFilterPlugin) handleFailure(sourceFormat string, err error) pluginapi.RequestInterceptResponse {
	var blocked *blockedFindingError
	if errors.As(err, &blocked) {
		return terminateRequest(
			sourceFormat,
			http.StatusUnprocessableEntity,
			"privacy_filter_rejected",
			"request blocked by privacy policy",
		)
	}
	if p.cfg.OnError == onErrorPassthrough {
		log.WithFields(log.Fields{
			"source_format": safeLogValue(sourceFormat),
			"reason":        failureReason(err),
		}).Warn("privacyfilter: inspection failed; request passed through by configuration")
		return pluginapi.RequestInterceptResponse{}
	}

	status := http.StatusServiceUnavailable
	code := "privacy_filter_internal_error"
	message := "privacy filter could not safely inspect the request"
	switch {
	case errors.Is(err, privacyengine.ErrBudgetExceeded):
		status = http.StatusRequestEntityTooLarge
		code = "privacy_filter_limit_exceeded"
		message = "request exceeds privacy inspection limits"
	case errors.Is(err, errUnsupportedRequestShape):
		status = http.StatusUnprocessableEntity
		code = "privacy_filter_unsupported_shape"
		message = "request shape is not safely inspectable"
	case errors.Is(err, io.ErrUnexpectedEOF), isJSONSyntaxError(err):
		status = http.StatusBadRequest
		code = "privacy_filter_invalid_json"
		message = "request body is not valid JSON"
	}
	return terminateRequest(sourceFormat, status, code, message)
}

func failureReason(err error) string {
	var blocked *blockedFindingError
	switch {
	case errors.As(err, &blocked):
		return "blocked_rule"
	case errors.Is(err, privacyengine.ErrBudgetExceeded):
		return "limit_exceeded"
	case errors.Is(err, errUnsupportedRequestShape):
		return "unsupported_shape"
	case isJSONSyntaxError(err):
		return "invalid_json"
	default:
		return "internal_error"
	}
}

func isJSONSyntaxError(err error) bool {
	var syntax *json.SyntaxError
	var typeErr *json.UnmarshalTypeError
	return errors.As(err, &syntax) || errors.As(err, &typeErr)
}

// redactRequestBody is retained only as a compatibility bridge while the
// protocol-specific byte-preserving walkers are integrated. It uses UseNumber
// so one redaction cannot corrupt unrelated integer identifiers.
func (p *privacyFilterPlugin) redactRequestBody(ctx context.Context, body []byte, budget *privacyengine.Budget) ([]byte, int, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var root map[string]any
	if err := decoder.Decode(&root); err != nil {
		return nil, 0, err
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return nil, 0, err
	}

	field := "messages"
	items, ok := root[field]
	if !ok {
		field = "input"
		items, ok = root[field]
	}
	if !ok {
		return nil, 0, errUnsupportedRequestShape
	}

	changed := false
	findingCount := 0
	switch value := items.(type) {
	case string:
		out, findings, didChange, err := p.editText(ctx, value, budget)
		if err != nil {
			return nil, 0, err
		}
		findingCount += findings
		if didChange {
			root[field] = out
			changed = true
		}
	case []any:
		for _, item := range value {
			itemMap, ok := item.(map[string]any)
			if !ok {
				continue
			}
			content, ok := itemMap["content"]
			if !ok {
				continue
			}
			didChange, findings, err := p.editContent(ctx, &content, budget)
			if err != nil {
				return nil, 0, err
			}
			findingCount += findings
			if didChange {
				itemMap["content"] = content
				changed = true
			}
		}
	default:
		return nil, 0, fmt.Errorf("%w: %s has unsupported type", errUnsupportedRequestShape, field)
	}
	if !changed {
		return nil, findingCount, nil
	}
	out, err := json.Marshal(root)
	if err != nil {
		return nil, 0, fmt.Errorf("marshal sanitized request: %w", err)
	}
	return out, findingCount, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("privacyfilter: multiple JSON documents")
		}
		return err
	}
	return nil
}

func (p *privacyFilterPlugin) editContent(ctx context.Context, content *any, budget *privacyengine.Budget) (bool, int, error) {
	changed := false
	findings := 0
	switch value := (*content).(type) {
	case string:
		out, count, didChange, err := p.editText(ctx, value, budget)
		if err != nil {
			return false, 0, err
		}
		findings += count
		if didChange {
			*content = out
			changed = true
		}
	case []any:
		for i, part := range value {
			partMap, ok := part.(map[string]any)
			if !ok {
				continue
			}
			text, ok := partMap["text"].(string)
			if !ok {
				continue
			}
			out, count, didChange, err := p.editText(ctx, text, budget)
			if err != nil {
				return false, 0, err
			}
			findings += count
			if didChange {
				partMap["text"] = out
				value[i] = partMap
				changed = true
			}
		}
	}
	return changed, findings, nil
}

func (p *privacyFilterPlugin) editText(ctx context.Context, text string, budget *privacyengine.Budget) (string, int, bool, error) {
	result, err := p.engine.Redact(ctx, text, privacyengine.RequestOptions{
		Budget:   budget,
		Renderer: p.renderer,
	})
	if err != nil {
		return text, 0, false, err
	}
	for _, finding := range result.Findings {
		if _, blocked := p.blockRuleIDs[finding.RuleID]; blocked {
			return text, len(result.Findings), false, &blockedFindingError{ruleID: finding.RuleID}
		}
	}
	if p.cfg.Mode == modeAudit {
		return text, len(result.Findings), false, nil
	}
	return result.Redacted, len(result.Findings), result.Hit(), nil
}

func safeLogValue(value string) string {
	value = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' || r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, value)
	const maxRunes = 128
	runes := []rune(value)
	if len(runes) > maxRunes {
		return string(runes[:maxRunes])
	}
	return value
}
