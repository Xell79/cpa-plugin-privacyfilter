package walker

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/rheodev/cpa-plugin-privacyfilter/payload"
)

type collector struct {
	ctx      context.Context
	protocol Protocol
	result   *Result
	targets  map[int]struct{}
	opaque   map[int]struct{}
}

func newCollector(ctx context.Context, protocol Protocol, sourceFormat string, document *payload.Document) *collector {
	if ctx == nil {
		ctx = context.Background()
	}
	return &collector{
		ctx:      ctx,
		protocol: protocol,
		result: &Result{
			Protocol:     protocol,
			SourceFormat: sourceFormat,
			Document:     document,
		},
		targets: make(map[int]struct{}),
		opaque:  make(map[int]struct{}),
	}
}

func (c *collector) finish() *Result {
	sort.SliceStable(c.result.Targets, func(i, j int) bool {
		return c.result.Targets[i].Token.Span.Start < c.result.Targets[j].Token.Span.Start
	})
	c.result.Skipped = len(c.result.Document.Strings()) - len(c.result.Targets)
	c.result.Opaque = len(c.opaque)
	c.result.UnsupportedCount = len(c.result.Unsupported)
	return c.result
}

func (c *collector) field(object *node, key string) (*node, bool, error) {
	if object.kind != payload.KindObject {
		return nil, false, c.shape(object, "object", "field lookup")
	}
	var found *node
	count := 0
	for _, item := range object.object {
		if item.key != key {
			continue
		}
		count++
		found = item.value
	}
	if count > 1 {
		return nil, false, &AmbiguityError{
			Protocol: c.protocol,
			Path:     append(object.path.Clone(), payload.Key(key)),
			Keys:     []string{key},
		}
	}
	return found, count == 1, nil
}

func (c *collector) oneOf(object *node, keys ...string) (*node, string, bool, error) {
	var found *node
	foundKey := ""
	for _, key := range keys {
		value, ok, err := c.field(object, key)
		if err != nil {
			return nil, "", false, err
		}
		if !ok {
			continue
		}
		if found != nil {
			return nil, "", false, &AmbiguityError{
				Protocol: c.protocol,
				Path:     object.path.Clone(),
				Keys:     append([]string(nil), keys...),
			}
		}
		found = value
		foundKey = key
	}
	return found, foundKey, found != nil, nil
}

func (c *collector) unique(object *node, keys ...string) error {
	for _, key := range keys {
		if _, _, err := c.field(object, key); err != nil {
			return err
		}
	}
	return nil
}

func (c *collector) shape(value *node, expected, detail string) error {
	actual := payload.KindInvalid
	path := payload.Path(nil)
	if value != nil {
		actual = value.kind
		path = value.path.Clone()
	}
	return &ShapeError{
		Protocol: c.protocol,
		Path:     path,
		Expected: expected,
		Actual:   actual,
		Detail:   detail,
	}
}

func (c *collector) missing(object *node, key, expected string) error {
	return &ShapeError{
		Protocol: c.protocol,
		Path:     append(object.path.Clone(), payload.Key(key)),
		Expected: expected,
		Actual:   payload.KindInvalid,
		Detail:   "required field",
	}
}

func (c *collector) unsupported(value *node, detail string) {
	path := payload.Path(nil)
	if value != nil {
		path = value.path.Clone()
	}
	c.result.Unsupported = append(c.result.Unsupported, UnsupportedShape{
		Protocol: c.protocol,
		Path:     path,
		Detail:   detail,
	})
}

func (c *collector) add(value *node, scope Scope, kind TargetKind, mutable Mutability) error {
	if err := c.ctx.Err(); err != nil {
		return err
	}
	if value == nil || value.kind != payload.KindString || value.token == nil {
		return c.shape(value, "string", "target")
	}
	start := value.token.Span.Start
	if _, exists := c.targets[start]; exists {
		return errorsInternal(fmt.Sprintf("string at %s selected twice", value.path))
	}
	if _, protected := c.opaque[start]; protected {
		return errorsInternal(fmt.Sprintf("opaque string at %s selected as target", value.path))
	}
	c.targets[start] = struct{}{}
	c.result.Targets = append(c.result.Targets, Target{
		Token:   *value.token,
		Path:    value.path.Clone(),
		Scope:   scope,
		Kind:    kind,
		Mutable: mutable,
	})
	return nil
}

func (c *collector) markOpaque(value *node) error {
	if value == nil {
		return nil
	}
	if err := c.ctx.Err(); err != nil {
		return err
	}
	switch value.kind {
	case payload.KindString:
		if value.token != nil {
			if _, target := c.targets[value.token.Span.Start]; target {
				return errorsInternal(fmt.Sprintf("target string at %s marked opaque", value.path))
			}
			c.opaque[value.token.Span.Start] = struct{}{}
		}
	case payload.KindObject:
		for _, item := range value.object {
			if err := c.markOpaque(item.value); err != nil {
				return err
			}
		}
	case payload.KindArray:
		for _, item := range value.array {
			if err := c.markOpaque(item); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *collector) markFields(object *node, keys ...string) error {
	for _, key := range keys {
		value, ok, err := c.field(object, key)
		if err != nil {
			return err
		}
		if ok {
			if err = c.markOpaque(value); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *collector) walkStringValues(value *node, scope Scope, kind TargetKind) error {
	if value == nil {
		return nil
	}
	if err := c.ctx.Err(); err != nil {
		return err
	}
	switch value.kind {
	case payload.KindString:
		return c.add(value, scope, kind, MutabilityDirect)
	case payload.KindObject:
		for _, item := range value.object {
			if err := c.walkStringValues(item.value, scope, kind); err != nil {
				return err
			}
		}
	case payload.KindArray:
		for _, item := range value.array {
			if err := c.walkStringValues(item, scope, kind); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *collector) stringField(object *node, key string, required bool) (*node, bool, error) {
	value, ok, err := c.field(object, key)
	if err != nil {
		return nil, false, err
	}
	if !ok {
		if required {
			return nil, false, c.missing(object, key, "string")
		}
		return nil, false, nil
	}
	if value.kind != payload.KindString {
		return nil, false, c.shape(value, "string", key)
	}
	return value, true, nil
}

func (c *collector) objectField(object *node, key string, required bool) (*node, bool, error) {
	value, ok, err := c.field(object, key)
	if err != nil {
		return nil, false, err
	}
	if !ok {
		if required {
			return nil, false, c.missing(object, key, "object")
		}
		return nil, false, nil
	}
	if value.kind != payload.KindObject {
		return nil, false, c.shape(value, "object", key)
	}
	return value, true, nil
}

func (c *collector) arrayField(object *node, key string, required bool) (*node, bool, error) {
	value, ok, err := c.field(object, key)
	if err != nil {
		return nil, false, err
	}
	if !ok {
		if required {
			return nil, false, c.missing(object, key, "array")
		}
		return nil, false, nil
	}
	if value.kind != payload.KindArray {
		return nil, false, c.shape(value, "array", key)
	}
	return value, true, nil
}

func scopeForRole(role string) (Scope, bool) {
	switch role {
	case "system", "developer":
		return ScopeSystem, true
	case "user":
		return ScopeUser, true
	case "assistant", "model":
		return ScopeAssistant, true
	case "tool", "function":
		return ScopeToolOutput, true
	default:
		return "", false
	}
}

var textBlockTypes = map[string]struct{}{
	"text":        {},
	"input_text":  {},
	"output_text": {},
}

var commonOpaqueContentTypes = map[string]struct{}{
	"image":        {},
	"input_image":  {},
	"output_image": {},
	"image_url":    {},
	"input_audio":  {},
	"output_audio": {},
	"audio":        {},
	"video":        {},
	"file":         {},
	"input_file":   {},
	"output_file":  {},
	"refusal":      {},
}

func (c *collector) walkTypedTextContent(content *node, scope Scope) error {
	switch content.kind {
	case payload.KindString:
		return c.add(content, scope, TargetKindNaturalText, MutabilityDirect)
	case payload.KindNull:
		return nil
	case payload.KindArray:
		for _, block := range content.array {
			if err := c.walkTypedTextBlock(block, scope); err != nil {
				return err
			}
		}
		return nil
	default:
		return c.shape(content, "string, array, or null", "content")
	}
}

func (c *collector) walkTypedTextBlock(block *node, scope Scope) error {
	if block.kind != payload.KindObject {
		c.unsupported(block, "content array element is not an object")
		return nil
	}
	if err := c.unique(block, "type", "text", "id", "name", "call_id", "signature"); err != nil {
		return err
	}
	typeNode, ok, err := c.stringField(block, "type", false)
	if err != nil {
		return err
	}
	if !ok {
		c.unsupported(block, "content block has no type")
		return nil
	}
	blockType := typeNode.token.Value
	if _, allowed := textBlockTypes[blockType]; allowed {
		text, present, textErr := c.stringField(block, "text", true)
		if textErr != nil {
			return textErr
		}
		if present {
			return c.add(text, scope, TargetKindNaturalText, MutabilityDirect)
		}
		return nil
	}
	if _, opaque := commonOpaqueContentTypes[blockType]; opaque {
		return c.markOpaque(block)
	}
	c.unsupported(block, fmt.Sprintf("unknown content block type %q", blockType))
	return nil
}

func (c *collector) validateRootControls(root *node) error {
	if err := c.unique(root, "model"); err != nil {
		return err
	}
	return c.markFields(root, "model")
}

func lowerType(value *node) string {
	if value == nil || value.token == nil {
		return ""
	}
	return strings.ToLower(value.token.Value)
}
