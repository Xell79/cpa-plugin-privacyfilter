// Package payload validates JSON bodies, locates string values, and applies
// byte-preserving replacements selected by a protocol-aware caller.
//
// The package deliberately has no policy about which strings are sensitive.
// Object keys are decoded only to construct paths; they are never returned as
// replaceable string tokens.
package payload

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

const (
	defaultMaxBodyBytes        = 32 << 20
	defaultMaxDepth            = 256
	defaultMaxNodes            = 1_000_000
	defaultMaxStringBytes      = 8 << 20
	defaultMaxReplacements     = 100_000
	defaultMaxReplacementBytes = 32 << 20
)

var (
	// ErrInvalidJSON means the input is not exactly one JSON document.
	ErrInvalidJSON = errors.New("payload: invalid JSON document")
	// ErrRootNotObject means ScanObject received a valid document whose root
	// value is not an object.
	ErrRootNotObject = errors.New("payload: JSON root is not an object")
	// ErrBodyTooLarge means MaxBodyBytes was exceeded.
	ErrBodyTooLarge = errors.New("payload: JSON body exceeds byte limit")
	// ErrDepthLimit means MaxDepth was exceeded.
	ErrDepthLimit = errors.New("payload: JSON depth limit exceeded")
	// ErrNodeLimit means MaxNodes was exceeded.
	ErrNodeLimit = errors.New("payload: JSON node limit exceeded")
	// ErrStringTooLarge means a decoded JSON string, including an object key,
	// exceeded MaxStringBytes.
	ErrStringTooLarge = errors.New("payload: JSON string exceeds byte limit")
	// ErrReplacementLimit means the replacement count or encoded-byte budget
	// was exceeded, or the resulting allocation would overflow.
	ErrReplacementLimit = errors.New("payload: replacement limit exceeded")
	// ErrOverlappingReplacements means two replacements selected the same or
	// overlapping raw span.
	ErrOverlappingReplacements = errors.New("payload: overlapping string replacements")
	// ErrInvalidToken means a replacement token did not come, unchanged, from
	// the Document on which Replace was called.
	ErrInvalidToken = errors.New("payload: string token does not belong to document")
	// ErrPathNotFound means no string value has the requested path.
	ErrPathNotFound = errors.New("payload: string path not found")
	// ErrPathAmbiguous means more than one string value has the requested path,
	// which is possible when a JSON object contains duplicate keys.
	ErrPathAmbiguous = errors.New("payload: string path is ambiguous")
	// ErrInvalidLimits means a limit was negative. Zero selects its safe
	// default and never disables a limit.
	ErrInvalidLimits = errors.New("payload: limits must not be negative")
)

// Kind is the JSON type of a value or container.
type Kind uint8

const (
	KindInvalid Kind = iota
	KindObject
	KindArray
	KindString
	KindNumber
	KindBoolean
	KindNull
)

func (k Kind) String() string {
	switch k {
	case KindObject:
		return "object"
	case KindArray:
		return "array"
	case KindString:
		return "string"
	case KindNumber:
		return "number"
	case KindBoolean:
		return "boolean"
	case KindNull:
		return "null"
	default:
		return "invalid"
	}
}

// Span is a half-open byte range [Start, End) in the original JSON body.
// StringToken spans include both quote bytes.
type Span struct {
	Start int
	End   int
}

// Len returns the number of bytes in the span. It returns zero for an invalid
// or empty span.
func (s Span) Len() int {
	if s.End <= s.Start {
		return 0
	}
	return s.End - s.Start
}

// PathSegmentKind distinguishes object members from array elements. This is
// intentionally typed: an object key "0" is not an array index 0.
type PathSegmentKind uint8

const (
	PathSegmentInvalid PathSegmentKind = iota
	PathSegmentObjectKey
	PathSegmentArrayIndex
)

// PathSegment is one typed step in a Path. Construct segments with Key and
// Index; its fields are private so numeric object keys cannot be confused with
// array indexes accidentally.
type PathSegment struct {
	kind  PathSegmentKind
	key   string
	index int
}

// Key constructs an object-key path segment. Every key string is permitted,
// including an empty string and strings containing dots, slashes, quotes, or
// brackets.
func Key(key string) PathSegment {
	return PathSegment{kind: PathSegmentObjectKey, key: key}
}

// Index constructs an array-index path segment. JSON array indexes are
// zero-based. A negative index is invalid and will not match any scanned path.
func Index(index int) PathSegment {
	return PathSegment{kind: PathSegmentArrayIndex, index: index}
}

// Kind reports whether the segment is an object key or array index.
func (s PathSegment) Kind() PathSegmentKind { return s.kind }

// KeyValue returns the object key and true for an object-key segment.
func (s PathSegment) KeyValue() (string, bool) {
	return s.key, s.kind == PathSegmentObjectKey
}

// IndexValue returns the zero-based index and true for a nonnegative array
// segment.
func (s PathSegment) IndexValue() (int, bool) {
	return s.index, s.kind == PathSegmentArrayIndex && s.index >= 0
}

// Path identifies a JSON value. The empty path is the root. Paths use typed
// segments, so Key("0") and Index(0) are distinct.
//
// String renders an unambiguous diagnostic form rooted at '$'. Object keys
// are JSON-string escaped and array indexes are canonical decimal integers:
//
//	Path{Key("a.b"), Key("x/y"), Index(2)} => $["a.b"]["x/y"][2]
//
// String is for diagnostics, not parsing; callers should construct paths with
// Key and Index and compare them with Equal.
type Path []PathSegment

// Clone returns an independent copy of p.
func (p Path) Clone() Path { return append(Path(nil), p...) }

// Equal reports whether p and other have identical typed segments.
func (p Path) Equal(other Path) bool {
	if len(p) != len(other) {
		return false
	}
	for i := range p {
		if p[i] != other[i] {
			return false
		}
	}
	return true
}

// HasPrefix reports whether prefix is a typed path prefix of p. It is useful
// for selecting all string leaves below a protocol-approved subtree.
func (p Path) HasPrefix(prefix Path) bool {
	return len(prefix) <= len(p) && Path(p[:len(prefix)]).Equal(prefix)
}

func (p Path) String() string {
	var b strings.Builder
	b.WriteByte('$')
	for _, segment := range p {
		switch segment.kind {
		case PathSegmentObjectKey:
			b.WriteByte('[')
			b.Write(encodeString(segment.key))
			b.WriteByte(']')
		case PathSegmentArrayIndex:
			fmt.Fprintf(&b, "[%d]", segment.index)
		default:
			b.WriteString("[invalid]")
		}
	}
	return b.String()
}

// Limits bounds scanning and replacement work. A zero field selects the
// corresponding value from DefaultLimits. Negative fields are rejected.
// Limits cannot be disabled.
type Limits struct {
	// MaxBodyBytes bounds the complete input, including surrounding whitespace.
	MaxBodyBytes int
	// MaxDepth bounds value nesting. The root value has depth 1.
	MaxDepth int
	// MaxNodes bounds JSON values, including the root and container values.
	// Object keys are structural and are not counted as nodes.
	MaxNodes int
	// MaxStringBytes bounds the decoded UTF-8 byte length of every JSON string,
	// including object keys, and of each requested replacement value.
	MaxStringBytes int
	// MaxReplacements bounds the number of Replacement entries in one call.
	MaxReplacements int
	// MaxReplacementBytes bounds the sum of encoded JSON string bytes (quotes
	// included) for replacements that would actually change a value.
	MaxReplacementBytes int
}

// DefaultLimits returns the limits used for zero-valued fields.
func DefaultLimits() Limits {
	return Limits{
		MaxBodyBytes:        defaultMaxBodyBytes,
		MaxDepth:            defaultMaxDepth,
		MaxNodes:            defaultMaxNodes,
		MaxStringBytes:      defaultMaxStringBytes,
		MaxReplacements:     defaultMaxReplacements,
		MaxReplacementBytes: defaultMaxReplacementBytes,
	}
}

// Normalized validates limits and fills zero fields with safe defaults.
func (l Limits) Normalized() (Limits, error) {
	return l.normalized()
}

func (l Limits) normalized() (Limits, error) {
	if l.MaxBodyBytes < 0 || l.MaxDepth < 0 || l.MaxNodes < 0 ||
		l.MaxStringBytes < 0 || l.MaxReplacements < 0 || l.MaxReplacementBytes < 0 {
		return Limits{}, ErrInvalidLimits
	}
	defaults := DefaultLimits()
	if l.MaxBodyBytes == 0 {
		l.MaxBodyBytes = defaults.MaxBodyBytes
	}
	if l.MaxDepth == 0 {
		l.MaxDepth = defaults.MaxDepth
	}
	if l.MaxNodes == 0 {
		l.MaxNodes = defaults.MaxNodes
	}
	if l.MaxStringBytes == 0 {
		l.MaxStringBytes = defaults.MaxStringBytes
	}
	if l.MaxReplacements == 0 {
		l.MaxReplacements = defaults.MaxReplacements
	}
	if l.MaxReplacementBytes == 0 {
		l.MaxReplacementBytes = defaults.MaxReplacementBytes
	}
	return l, nil
}

// ScanOptions configures Scan and ScanObject.
type ScanOptions struct {
	Limits Limits
}

// StringToken describes one JSON string value. Value is decoded; Span covers
// the original encoded bytes, including quotes. Path points to the value,
// ParentKind says whether the immediate container is an object or array (or
// KindInvalid for a root string), and Depth counts the root as depth 1.
//
// Tokens never represent object keys. Treat tokens and paths as immutable;
// Replace rejects a token whose exported metadata has been modified.
type StringToken struct {
	Value      string
	Span       Span
	Path       Path
	ParentKind Kind
	Depth      int

	document *Document
	ordinal  int
}

// Replacement changes exactly one scanned string value. Replacement order is
// irrelevant. Supplying the same token twice is an overlapping replacement
// error. A replacement whose Value equals Token.Value is a no-op and retains
// the token's original escaped bytes.
type Replacement struct {
	Token StringToken
	Value string
}

// Document is a validated, single-root JSON document and its string-value
// index. It retains the caller's body slice without copying it. The caller
// must not mutate that slice while using Document.
type Document struct {
	body     []byte
	rootKind Kind
	rootSpan Span
	limits   Limits
	strings  []StringToken
}

// Scan validates exactly one JSON document and indexes only its string
// values. Surrounding JSON whitespace is accepted and retained. Arrays and
// scalar roots are valid; use ScanObject when an API body requires an object.
func Scan(ctx context.Context, body []byte, opts ScanOptions) (*Document, error) {
	limits, err := opts.Limits.normalized()
	if err != nil {
		return nil, err
	}
	if len(body) > limits.MaxBodyBytes {
		return nil, fmt.Errorf("%w: got %d bytes, max %d", ErrBodyTooLarge, len(body), limits.MaxBodyBytes)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	rootKind, rootSpan, stringsFound, err := scanJSON(ctx, body, limits)
	if err != nil {
		return nil, err
	}
	doc := &Document{
		body:     body,
		rootKind: rootKind,
		rootSpan: rootSpan,
		limits:   limits,
		strings:  stringsFound,
	}
	for i := range doc.strings {
		doc.strings[i].document = doc
		doc.strings[i].ordinal = i
	}
	return doc, nil
}

// ScanObject is Scan plus a root-object requirement.
func ScanObject(ctx context.Context, body []byte, opts ScanOptions) (*Document, error) {
	doc, err := Scan(ctx, body, opts)
	if err != nil {
		return nil, err
	}
	if doc.rootKind != KindObject {
		return nil, ErrRootNotObject
	}
	return doc, nil
}

// RootKind returns the JSON type of the root value.
func (d *Document) RootKind() Kind { return d.rootKind }

// RootSpan returns the raw root-value range, excluding surrounding whitespace.
func (d *Document) RootSpan() Span { return d.rootSpan }

// Strings returns string value tokens in document order. The returned slice
// and each Path are independent copies; token identity is retained for
// Replace.
func (d *Document) Strings() []StringToken {
	out := make([]StringToken, len(d.strings))
	for i := range d.strings {
		out[i] = cloneToken(d.strings[i])
	}
	return out
}

// StringsAt returns every string value with exactly path, in document order.
// There can be more than one result when an object contains duplicate keys.
func (d *Document) StringsAt(path Path) []StringToken {
	var out []StringToken
	for i := range d.strings {
		if d.strings[i].Path.Equal(path) {
			out = append(out, cloneToken(d.strings[i]))
		}
	}
	return out
}

// StringAt returns the sole string value at path. Duplicate matching keys are
// ErrPathAmbiguous rather than being collapsed with first- or last-key wins.
func (d *Document) StringAt(path Path) (StringToken, error) {
	var found *StringToken
	for i := range d.strings {
		if !d.strings[i].Path.Equal(path) {
			continue
		}
		if found != nil {
			return StringToken{}, ErrPathAmbiguous
		}
		token := cloneToken(d.strings[i])
		found = &token
	}
	if found == nil {
		return StringToken{}, ErrPathNotFound
	}
	return *found, nil
}

// RawString returns a read-only view of token's original encoded bytes,
// including quotes. It rejects foreign or modified tokens.
func (d *Document) RawString(token StringToken) ([]byte, error) {
	canonical, err := d.canonicalToken(token)
	if err != nil {
		return nil, err
	}
	return d.body[canonical.Span.Start:canonical.Span.End], nil
}

// Replace transactionally applies selected string-value replacements. It
// validates every token, overlap, limit, and encoded replacement before
// allocating the output. On any error, no output is returned and the input is
// untouched. If no replacement changes a decoded value, the original body
// slice (and backing array) is returned with changed=false.
func (d *Document) Replace(ctx context.Context, replacements []Replacement) (out []byte, changed bool, err error) {
	return d.replace(ctx, replacements)
}

func cloneToken(token StringToken) StringToken {
	token.Path = token.Path.Clone()
	return token
}

func (d *Document) canonicalToken(token StringToken) (StringToken, error) {
	if token.document != d || token.ordinal < 0 || token.ordinal >= len(d.strings) {
		return StringToken{}, ErrInvalidToken
	}
	canonical := d.strings[token.ordinal]
	if token.Value != canonical.Value || token.Span != canonical.Span ||
		token.ParentKind != canonical.ParentKind || token.Depth != canonical.Depth ||
		!token.Path.Equal(canonical.Path) {
		return StringToken{}, ErrInvalidToken
	}
	return canonical, nil
}
