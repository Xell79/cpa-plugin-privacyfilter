package walker

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/ahoo/cpa-plugin-privacyfilter/payload"
)

type collector struct {
	ctx      context.Context
	protocol Protocol
	result   *Result
	budget   *treeStructuralBudget
	err      error
	targets  map[int]struct{}
	opaque   map[int]struct{}
	rejected map[int]struct{}
}

func newCollector(ctx context.Context, protocol Protocol, sourceFormat string, document *payload.Document, root *node) *collector {
	if ctx == nil {
		ctx = context.Background()
	}
	collector := &collector{
		ctx:      ctx,
		protocol: protocol,
		result: &Result{
			Protocol:     protocol,
			SourceFormat: sourceFormat,
			Document:     document,
		},
	}
	if root != nil && root.path.arena != nil {
		collector.budget = root.path.arena.budget
	}
	return collector
}

func (c *collector) finish() *Result {
	sort.SliceStable(c.result.Targets, func(i, j int) bool {
		return c.result.Targets[i].Token.Span.Start < c.result.Targets[j].Token.Span.Start
	})
	c.result.Skipped = c.result.Document.StringCount() - len(c.result.Targets)
	c.result.Opaque = len(c.opaque)
	c.result.UnsupportedCount = len(c.result.Unsupported)
	c.result.JSONNodes = c.result.Document.NodeCount()
	if c.budget != nil {
		c.result.StructuralBytes = c.budget.used
	}
	return c.result
}

func (c *collector) field(object *node, key string) (*node, bool, error) {
	if c.err != nil {
		return nil, false, c.err
	}
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
	if c.err != nil {
		return c.err
	}
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
	if c.err != nil {
		return c.err
	}
	return &ShapeError{
		Protocol: c.protocol,
		Path:     append(object.path.Clone(), payload.Key(key)),
		Expected: expected,
		Actual:   payload.KindInvalid,
		Detail:   "required field",
	}
}

func (c *collector) unsupported(value *node, detail string) {
	stringCount := c.countUndisposedStrings(value)
	if !c.reserveUnsupported(value, len(detail), stringCount) {
		return
	}
	c.markUnsupportedStrings(value)
	c.appendUnsupported(value, detail)
}

func (c *collector) unsupportedValue(value *node, prefix, untrusted string) {
	if c.err != nil {
		return
	}
	maxInt := int(^uint(0) >> 1)
	if len(prefix) > maxInt-2 || len(untrusted) > (maxInt-len(prefix)-2)/4 {
		c.err = fmt.Errorf("%w: unsupported diagnostic size overflow", payload.ErrStructuralLimit)
		return
	}
	// strconv.Quote emits at most four bytes per input byte plus the surrounding
	// quotes. Reserve that upper bound before formatting attacker-controlled text.
	stringCount := c.countUndisposedStrings(value)
	if !c.reserveUnsupported(value, len(prefix)+2+4*len(untrusted), stringCount) {
		return
	}
	c.markUnsupportedStrings(value)
	c.appendUnsupported(value, prefix+strconv.Quote(untrusted))
}

func (c *collector) reserveUnsupported(value *node, detailBytes, stringCount int) bool {
	if c.err != nil {
		return false
	}
	pathBytes := 0
	if value != nil && value.path.arena != nil && value.path.ref >= 0 {
		pathBytes = value.path.arena.nodes[value.path.ref].depth * retainedPathSegmentBytes
	}
	charge := detailBytes + pathBytes + stringCount*retainedTreeIndexEntryBytes
	newCap := cap(c.result.Unsupported)
	if len(c.result.Unsupported) == newCap {
		newCap = nextTreeCapacity(newCap, len(c.result.Unsupported)+1)
		charge += (newCap - cap(c.result.Unsupported)) * retainedTreeUnsupportedBytes
	}
	if c.budget == nil {
		c.err = errorsInternal("collector structural budget is unavailable")
		return false
	}
	if err := c.budget.retain(charge); err != nil {
		c.err = err
		return false
	}
	if newCap != cap(c.result.Unsupported) {
		grown := make([]UnsupportedShape, len(c.result.Unsupported), newCap)
		copy(grown, c.result.Unsupported)
		c.result.Unsupported = grown
	}
	return true
}

func (c *collector) appendUnsupported(value *node, detail string) {
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

func (c *collector) countUndisposedStrings(value *node) int {
	if value == nil {
		return 0
	}
	switch value.kind {
	case payload.KindString:
		if value.token == nil {
			return 0
		}
		start := value.token.Span.Start
		if _, ok := c.targets[start]; ok {
			return 0
		}
		if _, ok := c.opaque[start]; ok {
			return 0
		}
		if _, ok := c.rejected[start]; ok {
			return 0
		}
		return 1
	case payload.KindObject:
		count := 0
		for _, item := range value.object {
			count += c.countUndisposedStrings(item.value)
		}
		return count
	case payload.KindArray:
		count := 0
		for _, item := range value.array {
			count += c.countUndisposedStrings(item)
		}
		return count
	default:
		return 0
	}
}

func (c *collector) markUnsupportedStrings(value *node) {
	if value == nil {
		return
	}
	switch value.kind {
	case payload.KindString:
		if value.token == nil {
			return
		}
		start := value.token.Span.Start
		if _, ok := c.targets[start]; ok {
			return
		}
		if _, ok := c.opaque[start]; ok {
			return
		}
		if _, ok := c.rejected[start]; ok {
			return
		}
		if c.rejected == nil {
			c.rejected = make(map[int]struct{})
		}
		c.rejected[start] = struct{}{}
	case payload.KindObject:
		for _, item := range value.object {
			c.markUnsupportedStrings(item.value)
		}
	case payload.KindArray:
		for _, item := range value.array {
			c.markUnsupportedStrings(item)
		}
	}
}

func (c *collector) ensureStringDisposition(value *node) error {
	if c.err != nil {
		return c.err
	}
	if value == nil {
		return nil
	}
	if err := c.ctx.Err(); err != nil {
		return err
	}
	switch value.kind {
	case payload.KindString:
		if c.countUndisposedStrings(value) != 0 {
			c.unsupported(value, "string has no explicit protocol disposition")
		}
	case payload.KindObject:
		for _, item := range value.object {
			if err := c.ensureStringDisposition(item.value); err != nil {
				return err
			}
		}
	case payload.KindArray:
		for _, item := range value.array {
			if err := c.ensureStringDisposition(item); err != nil {
				return err
			}
		}
	}
	return c.err
}

func (c *collector) add(value *node, scope Scope, kind TargetKind, mutable Mutability) error {
	if c.err != nil {
		return c.err
	}
	encodedRepresentation := mutable == MutabilityEncodedJSON || mutable == MutabilityJSONOrPlain
	// A protocol may represent tool data as one scalar string, a typed text block,
	// or a string leaf inside native structured input/output. Treat all recognized
	// tool-data strings consistently: a JSON container is inspected recursively,
	// while any other value is inspected as plain text.
	if (scope == ScopeToolInput || scope == ScopeToolOutput) && mutable == MutabilityDirect {
		mutable = MutabilityJSONOrPlain
	}
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
	if _, rejected := c.rejected[start]; rejected {
		return errorsInternal(fmt.Sprintf("unsupported string at %s selected as target", value.path))
	}
	if c.budget == nil {
		return errorsInternal("collector structural budget is unavailable")
	}
	if err := c.budget.retain(retainedTreeIndexEntryBytes); err != nil {
		return err
	}
	targets, err := value.path.reserveTargetCapacity(c.result.Targets)
	if err != nil {
		return err
	}
	c.result.Targets = targets
	if err = value.path.reserveMaterialized(); err != nil {
		return err
	}
	if err = value.path.reserveMaterialized(); err != nil {
		return err
	}
	token, ok := c.result.Document.StringTokenAt(value.token.ordinal)
	if !ok || token.Value != value.token.Value || token.Span != value.token.Span {
		return errorsInternal("selected string no longer matches payload index")
	}
	if err = c.budget.retain(retainedFieldContextBytes); err != nil {
		return err
	}
	fields, ok := c.result.Document.StringKeyContextAt(value.token.ordinal)
	if !ok {
		return errorsInternal("selected string field context is unavailable")
	}
	toolScope := Scope("")
	if scope == ScopeToolInput || scope == ScopeToolOutput {
		toolScope = scope
	}
	if c.targets == nil {
		c.targets = make(map[int]struct{})
	}
	c.targets[start] = struct{}{}
	c.result.Targets = append(c.result.Targets, Target{
		Token:   token,
		Path:    token.Path.Clone(),
		Scope:   scope,
		Kind:    kind,
		Mutable: mutable,
		Context: TargetContext{
			Fields:     fields,
			ToolScope:  toolScope,
			Structured: kind == TargetKindJSONValue,
			Encoded:    encodedRepresentation,
		},
	})
	return nil
}

func (c *collector) markOpaque(value *node) error {
	if c.err != nil {
		return c.err
	}
	if value == nil {
		return nil
	}
	if err := c.ctx.Err(); err != nil {
		return err
	}
	switch value.kind {
	case payload.KindString:
		if value.token != nil {
			start := value.token.Span.Start
			if _, target := c.targets[start]; target {
				return errorsInternal(fmt.Sprintf("target string at %s marked opaque", value.path))
			}
			if _, rejected := c.rejected[start]; rejected {
				return errorsInternal(fmt.Sprintf("unsupported string at %s marked opaque", value.path))
			}
			if _, exists := c.opaque[start]; !exists {
				if c.budget == nil {
					return errorsInternal("collector structural budget is unavailable")
				}
				if err := c.budget.retain(retainedTreeIndexEntryBytes); err != nil {
					return err
				}
				if c.opaque == nil {
					c.opaque = make(map[int]struct{})
				}
				c.opaque[start] = struct{}{}
			}
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

func (c *collector) markOpaqueStringField(object *node, key string, required, nullable bool) error {
	value, present, err := c.field(object, key)
	if err != nil {
		return err
	}
	if !present {
		if required {
			return c.missing(object, key, "string")
		}
		return nil
	}
	if value.kind == payload.KindNull && nullable {
		return nil
	}
	if value.kind != payload.KindString {
		expected := "string"
		if nullable {
			expected += " or null"
		}
		return c.shape(value, expected, key)
	}
	return c.markOpaque(value)
}

func (c *collector) addStringField(object *node, key string, required, nullable bool, scope Scope, kind TargetKind) error {
	value, present, err := c.field(object, key)
	if err != nil {
		return err
	}
	if !present {
		if required {
			return c.missing(object, key, "string")
		}
		return nil
	}
	if value.kind == payload.KindNull && nullable {
		return nil
	}
	if value.kind != payload.KindString {
		expected := "string"
		if nullable {
			expected += " or null"
		}
		return c.shape(value, expected, key)
	}
	return c.add(value, scope, kind, MutabilityDirect)
}

func (c *collector) walkStringObjectField(object *node, key string, required, nullable bool, scope Scope) error {
	value, present, err := c.field(object, key)
	if err != nil {
		return err
	}
	if !present {
		if required {
			return c.missing(object, key, "object")
		}
		return nil
	}
	if value.kind == payload.KindNull && nullable {
		return nil
	}
	if value.kind != payload.KindObject {
		expected := "object"
		if nullable {
			expected += " or null"
		}
		return c.shape(value, expected, key)
	}
	return c.walkStringValues(value, scope, TargetKindJSONValue)
}

func (c *collector) markOpaqueObjectField(object *node, key string, required, nullable bool) error {
	value, present, err := c.field(object, key)
	if err != nil {
		return err
	}
	if !present {
		if required {
			return c.missing(object, key, "object")
		}
		return nil
	}
	if value.kind == payload.KindNull && nullable {
		return nil
	}
	if value.kind != payload.KindObject {
		expected := "object"
		if nullable {
			expected += " or null"
		}
		return c.shape(value, expected, key)
	}
	return c.markOpaque(value)
}

func (c *collector) markOpaqueStringArrayField(object *node, key string, required, nullable bool) error {
	value, present, err := c.field(object, key)
	if err != nil {
		return err
	}
	if !present {
		if required {
			return c.missing(object, key, "array")
		}
		return nil
	}
	if value.kind == payload.KindNull && nullable {
		return nil
	}
	if value.kind != payload.KindArray {
		expected := "array"
		if nullable {
			expected += " or null"
		}
		return c.shape(value, expected, key)
	}
	for _, item := range value.array {
		if item.kind != payload.KindString {
			return c.shape(item, "string", key+" element")
		}
		if err = c.markOpaque(item); err != nil {
			return err
		}
	}
	return nil
}

func (c *collector) walkStringValues(value *node, scope Scope, kind TargetKind) error {
	if c.err != nil {
		return c.err
	}
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
	"text":         {},
	"input_text":   {},
	"output_text":  {},
	"summary_text": {},
}

var commonOpaqueContentFields = map[string][]string{
	"image":        {"image_url", "url", "file_id", "detail", "data", "mime_type", "mimeType"},
	"input_image":  {"image_url", "url", "file_id", "detail"},
	"output_image": {"image_url", "url", "file_id", "data", "mime_type", "mimeType"},
	"image_url":    {"image_url", "url", "detail"},
	"input_audio":  {"input_audio", "audio", "data", "format"},
	"output_audio": {"audio", "data", "format", "id"},
	"audio":        {"audio", "data", "format", "id"},
	"video":        {"video", "data", "url", "file_id", "mime_type", "mimeType"},
	"file":         {"file", "file_id", "file_data", "filename", "url"},
	"input_file":   {"file", "file_id", "file_data", "filename", "url"},
	"output_file":  {"file", "file_id", "file_data", "filename", "url"},
}

var commonOpaqueNestedContentFields = map[string][]string{
	"image_url":   {"url", "file_id", "detail"},
	"input_audio": {"data", "format"},
	"audio":       {"data", "format", "id", "url", "file_id"},
	"video":       {"data", "url", "file_id", "mime_type", "mimeType"},
	"file":        {"file_id", "file_data", "filename", "url"},
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
	if err := c.unique(block, "type", "text", "refusal", "id", "name", "call_id", "signature", "prompt_cache_breakpoint"); err != nil {
		return err
	}
	for _, key := range []string{"id", "name", "call_id", "signature"} {
		if err := c.markOpaqueStringField(block, key, false, true); err != nil {
			return err
		}
	}
	if err := walkCommonCacheBreakpoint(c, block); err != nil {
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
	if err = c.markOpaque(typeNode); err != nil {
		return err
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
	if blockType == "refusal" {
		refusal, present, fieldErr := c.stringField(block, "refusal", true)
		if fieldErr != nil {
			return fieldErr
		}
		if present {
			return c.add(refusal, scope, TargetKindNaturalText, MutabilityDirect)
		}
		return nil
	}
	if fields, opaque := commonOpaqueContentFields[blockType]; opaque {
		return walkCommonOpaqueContentFields(c, block, fields)
	}
	c.unsupportedValue(block, "unknown content block type ", blockType)
	return nil
}

func walkCommonOpaqueContentFields(c *collector, block *node, fields []string) error {
	for _, key := range fields {
		value, present, err := c.field(block, key)
		if err != nil || !present || value.kind == payload.KindNull {
			if err != nil {
				return err
			}
			continue
		}
		if value.kind == payload.KindString {
			if err = c.markOpaque(value); err != nil {
				return err
			}
			continue
		}
		nestedFields, nested := commonOpaqueNestedContentFields[key]
		if !nested || value.kind != payload.KindObject {
			return c.shape(value, "string, object, or null", key)
		}
		if err = c.unique(value, nestedFields...); err != nil {
			return err
		}
		for _, nestedKey := range nestedFields {
			if err = c.markOpaqueStringField(value, nestedKey, false, true); err != nil {
				return err
			}
		}
	}
	return nil
}

func walkCommonCacheBreakpoint(c *collector, block *node) error {
	breakpoint, present, err := c.field(block, "prompt_cache_breakpoint")
	if err != nil || !present || breakpoint.kind == payload.KindNull {
		return err
	}
	if breakpoint.kind != payload.KindObject {
		return c.shape(breakpoint, "object or null", "prompt_cache_breakpoint")
	}
	if err = c.unique(breakpoint, "mode"); err != nil {
		return err
	}
	return c.markOpaqueStringField(breakpoint, "mode", true, false)
}

func (c *collector) validateRootControls(root *node) error {
	if err := c.unique(root, "model"); err != nil {
		return err
	}
	return c.markOpaqueStringField(root, "model", false, true)
}

func lowerType(value *node) string {
	if value == nil || value.token == nil {
		return ""
	}
	return strings.ToLower(value.token.Value)
}
