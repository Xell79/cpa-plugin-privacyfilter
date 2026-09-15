// Package walker selects protocol-defined, mutable string values from LLM
// request bodies. It does not detect secrets or apply redaction policy.
package walker

import (
	"errors"
	"fmt"

	"github.com/ahoo/cpa-plugin-privacyfilter/payload"
)

// Protocol identifies the request schema used to select targets. Protocol
// values are canonical registry values; a SourceFormat alias can resolve to a
// different Protocol value.
type Protocol string

const (
	ProtocolOpenAI         Protocol = "openai"
	ProtocolOpenAIResponse Protocol = "openai-response"
	ProtocolClaude         Protocol = "claude"
	ProtocolGemini         Protocol = "gemini"
	ProtocolInteractions   Protocol = "interactions"
)

// Scope describes the semantic origin of a target for later policy decisions.
type Scope string

const (
	ScopeSystem     Scope = "system"
	ScopeUser       Scope = "user"
	ScopeAssistant  Scope = "assistant"
	ScopeToolInput  Scope = "tool-input"
	ScopeToolOutput Scope = "tool-output"
)

// TargetKind tells a later redactor how the selected string is represented.
type TargetKind string

const (
	// TargetKindNaturalText is ordinary conversation or instruction text.
	TargetKindNaturalText TargetKind = "natural-text"
	// TargetKindEncodedJSON is a string whose decoded value conventionally
	// contains a complete JSON value. The walker deliberately does not parse it.
	TargetKindEncodedJSON TargetKind = "encoded-json"
	// TargetKindJSONValue is a string leaf in a native arbitrary JSON subtree.
	TargetKindJSONValue TargetKind = "json-value"
	// TargetKindToolOutput is model-visible tool-result text. It may contain JSON
	// or plain text, but the distinction is intentionally left to the redactor.
	TargetKindToolOutput TargetKind = "tool-output"
	// TargetKindCode is source code carried as a string.
	TargetKindCode TargetKind = "code"
	// TargetKindExecutionOutput is textual output from code execution.
	TargetKindExecutionOutput TargetKind = "execution-output"
)

// Mutability is the action a later redactor may take on a target. Every Target
// is mutable, but encoded values require a different operation from direct
// strings.
type Mutability uint8

const (
	MutabilityInvalid Mutability = iota
	// MutabilityDirect permits replacing the selected JSON string directly.
	MutabilityDirect
	// MutabilityEncodedJSON requires parsing/redacting the token's decoded value,
	// then replacing the complete outer JSON string.
	MutabilityEncodedJSON
	// MutabilityJSONOrPlain asks the redactor to try JSON and otherwise treat the
	// decoded value as plain tool output.
	MutabilityJSONOrPlain
)

func (m Mutability) String() string {
	switch m {
	case MutabilityDirect:
		return "direct"
	case MutabilityEncodedJSON:
		return "encoded-json"
	case MutabilityJSONOrPlain:
		return "json-or-plain"
	default:
		return "invalid"
	}
}

// TargetContext carries only bounded field-name and semantic metadata. It
// never stores a string value or complete path.
type TargetContext struct {
	Fields     payload.StringKeyContext
	ToolScope  Scope
	Structured bool
	Encoded    bool
}

// Target is one protocol-approved JSON string value. Path and Token.Path are
// independent immutable views so accidental diagnostic mutation cannot alter
// the token used for replacement.
type Target struct {
	Token   payload.StringToken
	Path    payload.Path
	Scope   Scope
	Kind    TargetKind
	Mutable Mutability
	Context TargetContext
}

// UnsupportedShape records a content/block shape the walker deliberately did
// not guess. Callers can use UnsupportedCount or this detail list to implement
// a strict block policy.
type UnsupportedShape struct {
	Protocol Protocol
	Path     payload.Path
	Detail   string
}

func (s UnsupportedShape) Error() string {
	return fmt.Sprintf("walker: unsupported %s shape at %s: %s", s.Protocol, s.Path, s.Detail)
}

// Is permits errors.Is(issue, ErrUnsupportedShape).
func (s UnsupportedShape) Is(target error) bool { return target == ErrUnsupportedShape }

// Result retains the byte-preserving Document and protocol-selected Targets.
// Skipped counts all indexed string values that were not targets. Opaque is the
// subset explicitly protected as signatures, reasoning, base64, URLs, IDs,
// names, schemas, or control values. UnsupportedCount equals len(Unsupported).
type Result struct {
	Protocol         Protocol
	SourceFormat     string
	Document         *payload.Document
	Targets          []Target
	Skipped          int
	Opaque           int
	UnsupportedCount int
	Unsupported      []UnsupportedShape
	// JSONNodes and StructuralBytes expose value-free cumulative accounting from
	// the outer scanner and walker so encoded-JSON inspection can share the same
	// request limits.
	JSONNodes       int
	StructuralBytes int
}

var (
	// ErrUnsupportedFormat means no registry entry exists for the exact source
	// format. It is never treated as a successfully scanned empty request.
	ErrUnsupportedFormat = errors.New("walker: unsupported source format")
	// ErrUnknownSourceFormat is retained as a descriptive alias.
	ErrUnknownSourceFormat = ErrUnsupportedFormat
	// ErrInvalidShape means a protocol field had an invalid or missing JSON type.
	ErrInvalidShape = errors.New("walker: invalid request shape")
	// ErrUnsupportedShape identifies a safely skipped, unrecognized block shape.
	ErrUnsupportedShape = errors.New("walker: unsupported request shape")
	// ErrAmbiguousPath means duplicate control members or simultaneous aliases
	// made protocol interpretation ambiguous.
	ErrAmbiguousPath = errors.New("walker: ambiguous control path")
	// ErrInvalidOptions means more than one variadic Options value was supplied.
	ErrInvalidOptions = errors.New("walker: invalid options")
)

// UnsupportedFormatError is returned for an exact SourceFormat registry miss.
type UnsupportedFormatError struct {
	SourceFormat string
}

func (e *UnsupportedFormatError) Error() string {
	return fmt.Sprintf("%v %q", ErrUnsupportedFormat, e.SourceFormat)
}

func (e *UnsupportedFormatError) Unwrap() error { return ErrUnsupportedFormat }

// UnknownSourceFormatError is an alias for UnsupportedFormatError.
type UnknownSourceFormatError = UnsupportedFormatError

// ShapeError describes a fatal type or required-field mismatch.
type ShapeError struct {
	Protocol Protocol
	Path     payload.Path
	Expected string
	Actual   payload.Kind
	Detail   string
}

func (e *ShapeError) Error() string {
	actual := e.Actual.String()
	if e.Actual == payload.KindInvalid {
		actual = "missing"
	}
	if e.Detail != "" {
		return fmt.Sprintf("%v for %s at %s: expected %s, got %s (%s)", ErrInvalidShape, e.Protocol, e.Path, e.Expected, actual, e.Detail)
	}
	return fmt.Sprintf("%v for %s at %s: expected %s, got %s", ErrInvalidShape, e.Protocol, e.Path, e.Expected, actual)
}

func (e *ShapeError) Unwrap() error { return ErrInvalidShape }

// AmbiguityError identifies duplicate structural keys or simultaneous aliases.
type AmbiguityError struct {
	Protocol Protocol
	Path     payload.Path
	Keys     []string
}

func (e *AmbiguityError) Error() string {
	return fmt.Sprintf("%v for %s at %s (keys %v)", ErrAmbiguousPath, e.Protocol, e.Path, e.Keys)
}

func (e *AmbiguityError) Unwrap() error { return ErrAmbiguousPath }
