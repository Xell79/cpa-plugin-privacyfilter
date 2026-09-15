package payload

// Source attribution: the byte-span scanning and ordered-splice design is
// adapted from ToS0/cpa-plugin-privacyfilter payload/jsonscan.go, authored by
// ToS0 in commits c2b9f3a5f662f6f378007c3389af4385d1c89bc5 and
// 4947e0d9f2641493bf462c9d3bf44b8559bfb627, under this repository's MIT
// License. This version replaces the source's policy-coupled deep walk with a
// validating, value-only lexer and typed paths.

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"unicode/utf8"
)

const (
	contextCheckInterval = 1024
	rootPathRef          = int32(-1)

	// These logical charges conservatively include slice backing storage and
	// allocator overhead on supported 64-bit targets. Capacity growth is charged
	// before allocation, so the retained scanner index never grows unbounded.
	retainedPathNodeBytes    = 64
	retainedStringTokenBytes = 128
)

type jsonScanner struct {
	ctx             context.Context
	body            []byte
	limits          Limits
	pos             int
	nodes           int
	lastCheck       int
	path            int32
	paths           []pathNode
	strings         []StringToken
	structuralBytes int
}

func scanJSON(ctx context.Context, body []byte, limits Limits) (Kind, Span, []StringToken, []pathNode, int, int, error) {
	s := jsonScanner{ctx: ctx, body: body, limits: limits, path: rootPathRef}
	if err := s.skipWhitespace(); err != nil {
		return KindInvalid, Span{}, nil, nil, 0, 0, err
	}
	if s.pos == len(body) {
		return KindInvalid, Span{}, nil, nil, 0, 0, invalidJSON(s.pos, "empty input")
	}
	start := s.pos
	kind, err := s.value(1, KindInvalid)
	if err != nil {
		return KindInvalid, Span{}, nil, nil, 0, 0, err
	}
	end := s.pos
	if err := s.skipWhitespace(); err != nil {
		return KindInvalid, Span{}, nil, nil, 0, 0, err
	}
	if s.pos != len(body) {
		return KindInvalid, Span{}, nil, nil, 0, 0, invalidJSON(s.pos, "data after root value")
	}
	if err := s.ctx.Err(); err != nil {
		return KindInvalid, Span{}, nil, nil, 0, 0, err
	}
	return kind, Span{Start: start, End: end}, s.strings, s.paths, s.structuralBytes, s.nodes, nil
}

func (s *jsonScanner) value(depth int, parent Kind) (Kind, error) {
	if err := s.checkNow(); err != nil {
		return KindInvalid, err
	}
	if depth > s.limits.MaxDepth {
		return KindInvalid, fmt.Errorf("%w: depth %d, max %d", ErrDepthLimit, depth, s.limits.MaxDepth)
	}
	s.nodes++
	if s.nodes > s.limits.MaxNodes {
		return KindInvalid, fmt.Errorf("%w: nodes %d, max %d", ErrNodeLimit, s.nodes, s.limits.MaxNodes)
	}
	if s.pos >= len(s.body) {
		return KindInvalid, invalidJSON(s.pos, "expected value")
	}

	switch s.body[s.pos] {
	case '{':
		if err := s.object(depth); err != nil {
			return KindInvalid, err
		}
		return KindObject, nil
	case '[':
		if err := s.array(depth); err != nil {
			return KindInvalid, err
		}
		return KindArray, nil
	case '"':
		start := s.pos
		value, err := s.stringValue()
		if err != nil {
			return KindInvalid, err
		}
		if err := s.appendString(StringToken{
			Value:      value,
			Span:       Span{Start: start, End: s.pos},
			ParentKind: parent,
			Depth:      depth,
			pathRef:    s.path,
		}); err != nil {
			return KindInvalid, err
		}
		return KindString, nil
	case 't':
		if err := s.literal("true"); err != nil {
			return KindInvalid, err
		}
		return KindBoolean, nil
	case 'f':
		if err := s.literal("false"); err != nil {
			return KindInvalid, err
		}
		return KindBoolean, nil
	case 'n':
		if err := s.literal("null"); err != nil {
			return KindInvalid, err
		}
		return KindNull, nil
	default:
		if s.body[s.pos] == '-' || isDigit(s.body[s.pos]) {
			if err := s.number(); err != nil {
				return KindInvalid, err
			}
			return KindNumber, nil
		}
		return KindInvalid, invalidJSON(s.pos, "expected value")
	}
}

func (s *jsonScanner) object(depth int) error {
	s.pos++ // '{'
	if err := s.skipWhitespace(); err != nil {
		return err
	}
	if s.pos < len(s.body) && s.body[s.pos] == '}' {
		s.pos++
		return nil
	}

	for {
		if s.pos >= len(s.body) || s.body[s.pos] != '"' {
			return invalidJSON(s.pos, "expected object key string")
		}
		key, err := s.stringValue()
		if err != nil {
			return err
		}
		if err := s.skipWhitespace(); err != nil {
			return err
		}
		if s.pos >= len(s.body) || s.body[s.pos] != ':' {
			return invalidJSON(s.pos, "expected ':' after object key")
		}
		s.pos++
		if err := s.skipWhitespace(); err != nil {
			return err
		}

		previousPath := s.path
		childPath, pathErr := s.appendPath(Key(key), len(key))
		if pathErr != nil {
			return pathErr
		}
		s.path = childPath
		_, err = s.value(depth+1, KindObject)
		s.path = previousPath
		if err != nil {
			return err
		}
		if err := s.skipWhitespace(); err != nil {
			return err
		}
		if s.pos >= len(s.body) {
			return invalidJSON(s.pos, "unterminated object")
		}
		switch s.body[s.pos] {
		case '}':
			s.pos++
			return nil
		case ',':
			s.pos++
			if err := s.skipWhitespace(); err != nil {
				return err
			}
		default:
			return invalidJSON(s.pos, "expected ',' or '}' in object")
		}
	}
}

func (s *jsonScanner) array(depth int) error {
	s.pos++ // '['
	if err := s.skipWhitespace(); err != nil {
		return err
	}
	if s.pos < len(s.body) && s.body[s.pos] == ']' {
		s.pos++
		return nil
	}

	for index := 0; ; index++ {
		previousPath := s.path
		childPath, pathErr := s.appendPath(Index(index), 0)
		if pathErr != nil {
			return pathErr
		}
		s.path = childPath
		_, err := s.value(depth+1, KindArray)
		s.path = previousPath
		if err != nil {
			return err
		}
		if err := s.skipWhitespace(); err != nil {
			return err
		}
		if s.pos >= len(s.body) {
			return invalidJSON(s.pos, "unterminated array")
		}
		switch s.body[s.pos] {
		case ']':
			s.pos++
			return nil
		case ',':
			s.pos++
			if err := s.skipWhitespace(); err != nil {
				return err
			}
		default:
			return invalidJSON(s.pos, "expected ',' or ']' in array")
		}
	}
}

func (s *jsonScanner) appendPath(segment PathSegment, retainedStringBytes int) (int32, error) {
	charge := retainedStringBytes
	if len(s.paths) == cap(s.paths) {
		newCap := nextRetainedCapacity(cap(s.paths), len(s.paths)+1)
		charge += (newCap - cap(s.paths)) * retainedPathNodeBytes
		if err := s.retain(charge); err != nil {
			return rootPathRef, err
		}
		grown := make([]pathNode, len(s.paths), newCap)
		copy(grown, s.paths)
		s.paths = grown
	} else if err := s.retain(charge); err != nil {
		return rootPathRef, err
	}
	ref := int32(len(s.paths))
	s.paths = append(s.paths, pathNode{parent: s.path, segment: segment})
	return ref, nil
}

func (s *jsonScanner) appendString(token StringToken) error {
	charge := len(token.Value)
	if len(s.strings) == cap(s.strings) {
		newCap := nextRetainedCapacity(cap(s.strings), len(s.strings)+1)
		charge += (newCap - cap(s.strings)) * retainedStringTokenBytes
		if err := s.retain(charge); err != nil {
			return err
		}
		grown := make([]StringToken, len(s.strings), newCap)
		copy(grown, s.strings)
		s.strings = grown
	} else if err := s.retain(charge); err != nil {
		return err
	}
	s.strings = append(s.strings, token)
	return nil
}

func (s *jsonScanner) retain(bytes int) error {
	if bytes < 0 || bytes > s.limits.MaxStructuralBytes-s.structuralBytes {
		return fmt.Errorf("%w: retained %d bytes, requested %d, max %d", ErrStructuralLimit, s.structuralBytes, bytes, s.limits.MaxStructuralBytes)
	}
	s.structuralBytes += bytes
	return nil
}

func nextRetainedCapacity(current, required int) int {
	if current == 0 {
		current = 16
	}
	for current < required {
		current *= 2
	}
	return current
}

// stringValue consumes and decodes a JSON string. It is used for both keys
// and values, but only value() turns the result into a StringToken.
func (s *jsonScanner) stringValue() (string, error) {
	start := s.pos
	i := start + 1
	hasEscape := false
	for i < len(s.body) {
		if err := s.checkAt(i); err != nil {
			return "", err
		}
		switch c := s.body[i]; c {
		case '"':
			s.pos = i + 1
			raw := s.body[start:s.pos]
			var value string
			if !hasEscape && utf8.Valid(raw[1:len(raw)-1]) {
				value = string(raw[1 : len(raw)-1])
			} else if err := json.Unmarshal(raw, &value); err != nil {
				return "", invalidJSON(start, "invalid string")
			}
			if len(value) > s.limits.MaxStringBytes {
				return "", fmt.Errorf("%w: decoded bytes %d, max %d", ErrStringTooLarge, len(value), s.limits.MaxStringBytes)
			}
			if err := s.checkNow(); err != nil {
				return "", err
			}
			return value, nil
		case '\\':
			hasEscape = true
			i++
			if i >= len(s.body) {
				return "", invalidJSON(i, "unterminated string escape")
			}
			switch s.body[i] {
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
				i++
			case 'u':
				if i+4 >= len(s.body) {
					return "", invalidJSON(i, "short Unicode escape")
				}
				for j := i + 1; j <= i+4; j++ {
					if !isHex(s.body[j]) {
						return "", invalidJSON(j, "invalid Unicode escape")
					}
				}
				i += 5
			default:
				return "", invalidJSON(i, "invalid string escape")
			}
		default:
			if c < 0x20 {
				return "", invalidJSON(i, "unescaped control byte in string")
			}
			i++
		}
	}
	return "", invalidJSON(len(s.body), "unterminated string")
}

func (s *jsonScanner) literal(want string) error {
	if len(s.body)-s.pos < len(want) || string(s.body[s.pos:s.pos+len(want)]) != want {
		return invalidJSON(s.pos, "invalid literal")
	}
	s.pos += len(want)
	return nil
}

func (s *jsonScanner) number() error {
	start := s.pos
	if s.body[s.pos] == '-' {
		s.pos++
		if s.pos >= len(s.body) {
			return invalidJSON(s.pos, "digit required after '-'")
		}
	}

	switch {
	case s.body[s.pos] == '0':
		s.pos++
		if s.pos < len(s.body) && isDigit(s.body[s.pos]) {
			return invalidJSON(s.pos, "leading zero in number")
		}
	case s.body[s.pos] >= '1' && s.body[s.pos] <= '9':
		for s.pos < len(s.body) && isDigit(s.body[s.pos]) {
			s.pos++
			if err := s.checkAt(s.pos); err != nil {
				return err
			}
		}
	default:
		return invalidJSON(start, "invalid number")
	}

	if s.pos < len(s.body) && s.body[s.pos] == '.' {
		s.pos++
		fractionStart := s.pos
		for s.pos < len(s.body) && isDigit(s.body[s.pos]) {
			s.pos++
			if err := s.checkAt(s.pos); err != nil {
				return err
			}
		}
		if s.pos == fractionStart {
			return invalidJSON(s.pos, "fraction requires a digit")
		}
	}

	if s.pos < len(s.body) && (s.body[s.pos] == 'e' || s.body[s.pos] == 'E') {
		s.pos++
		if s.pos < len(s.body) && (s.body[s.pos] == '+' || s.body[s.pos] == '-') {
			s.pos++
		}
		exponentStart := s.pos
		for s.pos < len(s.body) && isDigit(s.body[s.pos]) {
			s.pos++
			if err := s.checkAt(s.pos); err != nil {
				return err
			}
		}
		if s.pos == exponentStart {
			return invalidJSON(s.pos, "exponent requires a digit")
		}
	}
	return nil
}

func (s *jsonScanner) skipWhitespace() error {
	for s.pos < len(s.body) {
		switch s.body[s.pos] {
		case ' ', '\t', '\n', '\r':
			s.pos++
			if err := s.checkAt(s.pos); err != nil {
				return err
			}
		default:
			return nil
		}
	}
	return nil
}

func (s *jsonScanner) checkAt(pos int) error {
	if pos-s.lastCheck < contextCheckInterval {
		return nil
	}
	s.lastCheck = pos
	return s.checkNow()
}

func (s *jsonScanner) checkNow() error {
	select {
	case <-s.ctx.Done():
		return s.ctx.Err()
	default:
		return nil
	}
}

func invalidJSON(offset int, reason string) error {
	return fmt.Errorf("%w at byte %d: %s", ErrInvalidJSON, offset, reason)
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isHex(c byte) bool {
	return isDigit(c) || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

type replacementCandidate struct {
	token StringToken
	value string
}

type stringEdit struct {
	span    Span
	encoded []byte
}

func (d *Document) replace(ctx context.Context, replacements []Replacement) ([]byte, bool, error) {
	if d == nil {
		return nil, false, ErrInvalidToken
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	if len(replacements) > d.limits.MaxReplacements {
		return nil, false, fmt.Errorf("%w: replacements %d, max %d", ErrReplacementLimit, len(replacements), d.limits.MaxReplacements)
	}
	if len(replacements) == 0 {
		return d.body, false, nil
	}

	candidates := make([]replacementCandidate, len(replacements))
	for i, replacement := range replacements {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		canonical, err := d.canonicalToken(replacement.Token)
		if err != nil {
			return nil, false, err
		}
		if len(replacement.Value) > d.limits.MaxStringBytes {
			return nil, false, fmt.Errorf("%w: replacement bytes %d, max %d", ErrStringTooLarge, len(replacement.Value), d.limits.MaxStringBytes)
		}
		candidates[i] = replacementCandidate{token: canonical, value: replacement.Value}
	}

	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].token.Span.Start == candidates[j].token.Span.Start {
			return candidates[i].token.Span.End < candidates[j].token.Span.End
		}
		return candidates[i].token.Span.Start < candidates[j].token.Span.Start
	})
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	previousEnd := -1
	for _, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		span := candidate.token.Span
		if span.Start < 0 || span.End <= span.Start || span.End > len(d.body) {
			return nil, false, ErrInvalidToken
		}
		if span.Start < previousEnd {
			return nil, false, ErrOverlappingReplacements
		}
		previousEnd = span.End
	}

	edits := make([]stringEdit, 0, len(candidates))
	encodedTotal := 0
	for _, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		if candidate.value == candidate.token.Value {
			continue
		}
		encoded, err := encodeStringContext(ctx, candidate.value)
		if err != nil {
			return nil, false, err
		}
		if len(encoded) > d.limits.MaxReplacementBytes-encodedTotal {
			return nil, false, fmt.Errorf("%w: encoded replacement bytes exceed max %d", ErrReplacementLimit, d.limits.MaxReplacementBytes)
		}
		encodedTotal += len(encoded)
		edits = append(edits, stringEdit{span: candidate.token.Span, encoded: encoded})
	}
	if len(edits) == 0 {
		return d.body, false, nil
	}

	out, err := splice(ctx, d.body, edits)
	if err != nil {
		return nil, false, err
	}
	return out, true, nil
}

// splice applies sorted, disjoint edits without mutating body. All validation
// is repeated here so this allocation boundary remains safe if its caller is
// changed later.
func splice(ctx context.Context, body []byte, edits []stringEdit) ([]byte, error) {
	size := len(body)
	previousEnd := 0
	maxInt := int(^uint(0) >> 1)
	for _, edit := range edits {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if edit.span.Start < previousEnd || edit.span.End <= edit.span.Start || edit.span.End > len(body) {
			return nil, ErrOverlappingReplacements
		}
		oldBytes := edit.span.End - edit.span.Start
		if len(edit.encoded) > oldBytes {
			growth := len(edit.encoded) - oldBytes
			if size > maxInt-growth {
				return nil, ErrReplacementLimit
			}
			size += growth
		} else {
			size -= oldBytes - len(edit.encoded)
		}
		previousEnd = edit.span.End
	}

	out := make([]byte, 0, size)
	previousEnd = 0
	for _, edit := range edits {
		var err error
		out, err = appendWithContext(ctx, out, body[previousEnd:edit.span.Start])
		if err != nil {
			return nil, err
		}
		out, err = appendWithContext(ctx, out, edit.encoded)
		if err != nil {
			return nil, err
		}
		previousEnd = edit.span.End
	}
	out, err := appendWithContext(ctx, out, body[previousEnd:])
	if err != nil {
		return nil, err
	}
	return out, nil
}

func appendWithContext(ctx context.Context, dst, src []byte) ([]byte, error) {
	const chunkBytes = 64 << 10
	for len(src) > 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n := len(src)
		if n > chunkBytes {
			n = chunkBytes
		}
		dst = append(dst, src[:n]...)
		src = src[n:]
	}
	return dst, nil
}

// encodeString emits one JSON string without HTML escaping. It mirrors the
// relevant encoding/json behavior, including replacing invalid UTF-8 and
// escaping U+2028/U+2029, but has a cancellable form for replacements.
func encodeString(value string) []byte {
	encoded, _ := encodeStringContext(nil, value)
	return encoded
}

func encodeStringContext(ctx context.Context, value string) ([]byte, error) {
	out := make([]byte, 0, len(value)+2)
	out = append(out, '"')
	nextCheck := contextCheckInterval
	const hex = "0123456789abcdef"

	for i := 0; i < len(value); {
		if ctx != nil && i >= nextCheck {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			nextCheck = i + contextCheckInterval
		}
		c := value[i]
		if c < utf8.RuneSelf {
			switch c {
			case '"', '\\':
				out = append(out, '\\', c)
			case '\b':
				out = append(out, '\\', 'b')
			case '\f':
				out = append(out, '\\', 'f')
			case '\n':
				out = append(out, '\\', 'n')
			case '\r':
				out = append(out, '\\', 'r')
			case '\t':
				out = append(out, '\\', 't')
			default:
				if c < 0x20 {
					out = append(out, '\\', 'u', '0', '0', hex[c>>4], hex[c&0x0f])
				} else {
					out = append(out, c)
				}
			}
			i++
			continue
		}

		r, size := utf8.DecodeRuneInString(value[i:])
		if r == utf8.RuneError && size == 1 {
			out = append(out, '\xef', '\xbf', '\xbd')
			i++
			continue
		}
		if r == rune(0x2028) || r == rune(0x2029) {
			out = append(out, '\\', 'u', '2', '0', '2', hex[byte(r)&0x0f])
		} else {
			out = append(out, value[i:i+size]...)
		}
		i += size
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	out = append(out, '"')
	return out, nil
}
