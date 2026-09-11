package walker

import (
	"context"
	"fmt"
	"sort"

	"github.com/rheodev/cpa-plugin-privacyfilter/payload"
)

// Options configures JSON validation and indexing before protocol walking.
type Options struct {
	ScanOptions payload.ScanOptions
}

type walkFunc func(*collector, *node) error

type registryEntry struct {
	protocol Protocol
	walk     walkFunc
	alias    bool
}

// Registry is an immutable SourceFormat-to-walker registry. Its entries are
// private so callers cannot accidentally change process-wide protocol meaning.
type Registry struct {
	entries map[string]registryEntry
}

// NewRegistry returns the complete built-in registry. The only compatibility
// alias is gemini-cli, whose inbound body is the Interactions schema.
func NewRegistry() *Registry {
	return &Registry{entries: map[string]registryEntry{
		string(ProtocolOpenAI):         {protocol: ProtocolOpenAI, walk: walkOpenAI},
		string(ProtocolOpenAIResponse): {protocol: ProtocolOpenAIResponse, walk: walkResponses},
		string(ProtocolClaude):         {protocol: ProtocolClaude, walk: walkClaude},
		string(ProtocolGemini):         {protocol: ProtocolGemini, walk: walkGemini},
		string(ProtocolInteractions):   {protocol: ProtocolInteractions, walk: walkInteractions},
		"gemini-cli":                   {protocol: ProtocolInteractions, walk: walkInteractions, alias: true},
	}}
}

// DefaultRegistry is the process-wide immutable built-in registry.
var DefaultRegistry = NewRegistry()

// Lookup resolves an exact SourceFormat and reports its canonical Protocol.
func (r *Registry) Lookup(sourceFormat string) (Protocol, bool) {
	if r == nil {
		return "", false
	}
	entry, ok := r.entries[sourceFormat]
	if !ok {
		return "", false
	}
	return entry.protocol, true
}

// Resolve is Lookup with a typed error for an unsupported exact format.
func (r *Registry) Resolve(sourceFormat string) (Protocol, error) {
	protocol, ok := r.Lookup(sourceFormat)
	if !ok {
		return "", &UnsupportedFormatError{SourceFormat: sourceFormat}
	}
	return protocol, nil
}

// Formats returns all exact accepted SourceFormat values, including aliases.
func (r *Registry) Formats() []string {
	if r == nil {
		return nil
	}
	formats := make([]string, 0, len(r.entries))
	for format := range r.entries {
		formats = append(formats, format)
	}
	sort.Strings(formats)
	return formats
}

// IsAlias reports whether sourceFormat is an explicitly registered alias.
func (r *Registry) IsAlias(sourceFormat string) bool {
	if r == nil {
		return false
	}
	entry, ok := r.entries[sourceFormat]
	return ok && entry.alias
}

// Walk validates body as one root object and selects typed protocol targets.
// Zero or one Options value may be supplied; omission uses payload defaults.
func (r *Registry) Walk(ctx context.Context, sourceFormat string, body []byte, options ...Options) (*Result, error) {
	if len(options) > 1 {
		return nil, fmt.Errorf("%w: got %d option values", ErrInvalidOptions, len(options))
	}
	if r == nil {
		return nil, &UnsupportedFormatError{SourceFormat: sourceFormat}
	}
	entry, ok := r.entries[sourceFormat]
	if !ok {
		return nil, &UnsupportedFormatError{SourceFormat: sourceFormat}
	}
	var scanOptions payload.ScanOptions
	if len(options) == 1 {
		scanOptions = options[0].ScanOptions
	}
	document, err := payload.ScanObject(ctx, body, scanOptions)
	if err != nil {
		return nil, err
	}
	root, err := parseTree(ctx, body, document)
	if err != nil {
		return nil, err
	}
	c := newCollector(ctx, entry.protocol, sourceFormat, document)
	if err = c.validateRootControls(root); err != nil {
		return nil, err
	}
	if err = entry.walk(c, root); err != nil {
		return nil, err
	}
	if err = c.ctx.Err(); err != nil {
		return nil, err
	}
	return c.finish(), nil
}

// Walk uses DefaultRegistry.
func Walk(ctx context.Context, sourceFormat string, body []byte, options ...Options) (*Result, error) {
	return DefaultRegistry.Walk(ctx, sourceFormat, body, options...)
}

// Formats returns DefaultRegistry's exact accepted SourceFormat values.
func Formats() []string { return DefaultRegistry.Formats() }
