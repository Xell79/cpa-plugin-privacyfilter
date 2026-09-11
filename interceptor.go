package main

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/rheodev/cpa-plugin-privacyfilter/internal/privacyengine"
	"github.com/rheodev/cpa-plugin-privacyfilter/payload"
	"github.com/rheodev/cpa-plugin-privacyfilter/walker"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	log "github.com/sirupsen/logrus"
)

type privacyFilterPlugin struct {
	cfg          privacyFilterConfig
	engine       *privacyengine.Engine
	renderer     privacyengine.Renderer
	blockRuleIDs map[string]struct{}
	cache        *RequestScanCache
	revision     uint64
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
		return p.handleFailure(req.SourceFormat, payload.ErrInvalidJSON), nil
	}

	modelContext := req.RequestedModel
	if modelContext == "" {
		modelContext = req.Model
	}
	state := p.cache.Acquire(req.RequestID, RequestScanContext{
		Revision:     p.revision,
		SourceFormat: req.SourceFormat,
		Model:        modelContext,
	})
	if state.Seen(req.Body) {
		return pluginapi.RequestInterceptResponse{}, nil
	}
	rendererState := state.GetOrCreateRendererState(func() any {
		return newRequestRenderer(p.renderer)
	})
	renderer, ok := rendererState.(*requestRenderer)
	if !ok || renderer == nil {
		return p.handleFailure(req.SourceFormat, privacyengine.ErrInternalFailure), nil
	}

	result, errSanitize := p.sanitizeRequestWithRenderer(ctx, req.SourceFormat, req.Body, renderer)
	if errSanitize != nil {
		return p.handleFailure(req.SourceFormat, errSanitize), nil
	}
	if result.changed {
		state.Record(req.Body, result.body)
	} else {
		state.Record(req.Body, nil)
	}
	if result.findings > 0 || result.unsupported > 0 {
		log.WithFields(log.Fields{
			"source_format": safeLogValue(req.SourceFormat),
			"model":         safeLogValue(req.RequestedModel),
			"mode":          string(p.cfg.Mode),
			"findings":      result.findings,
			"targets":       result.targets,
			"opaque":        result.opaque,
			"unsupported":   result.unsupported,
		}).Info("privacyfilter: request inspection complete")
	}
	if !result.changed {
		return pluginapi.RequestInterceptResponse{}, nil
	}
	return pluginapi.RequestInterceptResponse{Body: result.body}, nil
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
	case isLimitError(err):
		status = http.StatusRequestEntityTooLarge
		code = "privacy_filter_limit_exceeded"
		message = "request exceeds privacy inspection limits"
	case isUnsupportedError(err):
		status = http.StatusUnprocessableEntity
		code = "privacy_filter_unsupported_shape"
		message = "request shape is not safely inspectable"
	case isJSONError(err):
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
	case isLimitError(err):
		return "limit_exceeded"
	case isUnsupportedError(err):
		return "unsupported_shape"
	case isJSONError(err):
		return "invalid_json"
	default:
		return "internal_error"
	}
}

func isLimitError(err error) bool {
	return errors.Is(err, privacyengine.ErrBudgetExceeded) ||
		errors.Is(err, payload.ErrBodyTooLarge) ||
		errors.Is(err, payload.ErrDepthLimit) ||
		errors.Is(err, payload.ErrNodeLimit) ||
		errors.Is(err, payload.ErrStringTooLarge) ||
		errors.Is(err, payload.ErrReplacementLimit)
}

func isUnsupportedError(err error) bool {
	return errors.Is(err, errUnsupportedRequestShape) ||
		errors.Is(err, walker.ErrUnsupportedFormat) ||
		errors.Is(err, walker.ErrInvalidShape) ||
		errors.Is(err, walker.ErrUnsupportedShape) ||
		errors.Is(err, walker.ErrAmbiguousPath) ||
		errors.Is(err, payload.ErrRootNotObject)
}

func isJSONError(err error) bool {
	return errors.Is(err, payload.ErrInvalidJSON)
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
