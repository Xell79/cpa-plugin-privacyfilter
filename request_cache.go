package main

import (
	"container/list"
	"crypto/sha256"
	"sync"
	"sync/atomic"
	"time"
)

// RequestScanContext identifies the policy and effective routing context under
// which a request body was inspected. All fields are compared exactly.
type RequestScanContext struct {
	// Revision is the config/policy revision used for the scan.
	Revision uint64

	// SourceFormat and Model are the effective values used for the scan. Callers
	// should resolve aliases or requested/upstream model names before acquiring a
	// state if their policy uses canonical values.
	SourceFormat string
	Model        string
}

// RequestScanCacheOptions controls retention of request-scoped scan state.
type RequestScanCacheOptions struct {
	// TTL is a sliding time-to-live measured from the most recent Acquire. A
	// zero or negative value disables time-based expiration. Capacity still
	// bounds the cache when expiration is disabled.
	TTL time.Duration

	// MaxEntries is the maximum number of RequestIDs retained. A zero or
	// negative value disables retention: Acquire still returns a usable
	// ephemeral state, but the state is never inserted into the cache.
	MaxEntries int
}

// RequestScanCacheStats is a bounded-cardinality snapshot. It deliberately
// contains neither RequestIDs nor body fingerprints or renderer state.
type RequestScanCacheStats struct {
	Entries       int
	MaxEntries    int
	TTL           time.Duration
	Acquires      uint64
	Created       uint64
	Reused        uint64
	ContextResets uint64
	Ephemeral     uint64
	SeenHits      uint64
	SeenMisses    uint64
	Records       uint64
	Completions   uint64
	Expirations   uint64
	Evictions     uint64
}

type requestScanCacheMetrics struct {
	acquires      atomic.Uint64
	created       atomic.Uint64
	reused        atomic.Uint64
	contextResets atomic.Uint64
	ephemeral     atomic.Uint64
	seenHits      atomic.Uint64
	seenMisses    atomic.Uint64
	records       atomic.Uint64
	completions   atomic.Uint64
	expirations   atomic.Uint64
	evictions     atomic.Uint64
}

// RendererStateFactory lazily creates renderer-specific request state. The
// cache treats the returned value as opaque and never logs or serializes it.
type RendererStateFactory func() any

// RequestScanState holds only the latest successful output fingerprint and an
// opaque renderer slot for one request/context pair. It must not be copied.
type RequestScanState struct {
	context RequestScanContext
	metrics *requestScanCacheMetrics

	fingerprintMu  sync.RWMutex
	hasFingerprint bool
	fingerprint    [sha256.Size]byte

	rendererMu       sync.Mutex
	rendererState    any
	hasRendererState bool
}

// NewEphemeralRequestScanState creates request state that is not owned by a
// cache. It is suitable for requests without a RequestID.
func NewEphemeralRequestScanState(context RequestScanContext) *RequestScanState {
	return newRequestScanState(context, nil)
}

func newRequestScanState(context RequestScanContext, metrics *requestScanCacheMetrics) *RequestScanState {
	return &RequestScanState{
		context: context,
		metrics: metrics,
	}
}

// Context returns the immutable policy/routing context bound to this state.
func (s *RequestScanState) Context() RequestScanContext {
	if s == nil {
		return RequestScanContext{}
	}
	return s.context
}

// Seen reports whether body equals the output of the latest successful scan.
// Before the first Record it always returns false.
func (s *RequestScanState) Seen(body []byte) bool {
	if s == nil {
		return false
	}

	fingerprint := sha256.Sum256(body)
	s.fingerprintMu.RLock()
	seen := s.hasFingerprint && s.fingerprint == fingerprint
	s.fingerprintMu.RUnlock()

	if s.metrics != nil {
		if seen {
			s.metrics.seenHits.Add(1)
		} else {
			s.metrics.seenMisses.Add(1)
		}
	}
	return seen
}

// Record records the body produced by a successful scan. If sanitizedOutput is
// non-nil, only its fingerprint is retained. If it is nil (the scanner left the
// body unchanged), input's fingerprint is retained. The input fingerprint is
// intentionally not retained after a changed scan: seeing the unsanitized input
// again must cause another scan.
func (s *RequestScanState) Record(input, sanitizedOutput []byte) {
	if s == nil {
		return
	}

	body := input
	if sanitizedOutput != nil {
		body = sanitizedOutput
	}
	fingerprint := sha256.Sum256(body)

	s.fingerprintMu.Lock()
	s.fingerprint = fingerprint
	s.hasFingerprint = true
	s.fingerprintMu.Unlock()

	if s.metrics != nil {
		s.metrics.records.Add(1)
	}
}

// LoadRendererState returns the opaque renderer state, if initialized. The
// cache never examines the value. Synchronization of mutable data inside the
// returned value remains the caller's responsibility.
func (s *RequestScanState) LoadRendererState() (any, bool) {
	if s == nil {
		return nil, false
	}
	s.rendererMu.Lock()
	defer s.rendererMu.Unlock()
	return s.rendererState, s.hasRendererState
}

// StoreRendererState replaces the opaque renderer state. Storing nil still
// marks the slot initialized.
func (s *RequestScanState) StoreRendererState(state any) {
	if s == nil {
		return
	}
	s.rendererMu.Lock()
	s.rendererState = state
	s.hasRendererState = true
	s.rendererMu.Unlock()
}

// GetOrCreateRendererState returns the opaque renderer state, invoking factory
// at most once while the slot remains uninitialized. A nil value returned by
// factory is still considered initialized. A nil factory simply returns nil.
func (s *RequestScanState) GetOrCreateRendererState(factory RendererStateFactory) any {
	if s == nil {
		return nil
	}

	s.rendererMu.Lock()
	defer s.rendererMu.Unlock()
	if !s.hasRendererState && factory != nil {
		s.rendererState = factory()
		s.hasRendererState = true
	}
	return s.rendererState
}

type requestScanCacheEntry struct {
	requestID  string
	state      *RequestScanState
	lastAccess time.Time
	element    *list.Element
}

// RequestScanCache stores one state per non-empty RequestID. A context change
// replaces the logical state rather than carrying fingerprints or renderer
// state across policy revisions, source formats, or models.
type RequestScanCache struct {
	mu         sync.Mutex
	entries    map[string]*requestScanCacheEntry
	lru        list.List
	ttl        time.Duration
	maxEntries int
	now        func() time.Time
	metrics    requestScanCacheMetrics
}

// NewRequestScanCache creates a request cache. See RequestScanCacheOptions for
// the explicit zero and negative boundary behavior.
func NewRequestScanCache(options RequestScanCacheOptions) *RequestScanCache {
	return newRequestScanCache(options, time.Now)
}

func newRequestScanCache(options RequestScanCacheOptions, now func() time.Time) *RequestScanCache {
	if options.TTL < 0 {
		options.TTL = 0
	}
	if options.MaxEntries < 0 {
		options.MaxEntries = 0
	}
	if now == nil {
		now = time.Now
	}
	return &RequestScanCache{
		entries:    make(map[string]*requestScanCacheEntry),
		ttl:        options.TTL,
		maxEntries: options.MaxEntries,
		now:        now,
	}
}

// Acquire returns the state for requestID and context, creating it when needed.
// Matching states are promoted in the LRU and have their sliding TTL refreshed.
// An empty RequestID, or a disabled cache, always yields a fresh ephemeral state
// and never creates a map entry.
func (c *RequestScanCache) Acquire(requestID string, context RequestScanContext) *RequestScanState {
	if c == nil {
		return NewEphemeralRequestScanState(context)
	}
	c.metrics.acquires.Add(1)

	if requestID == "" || c.maxEntries <= 0 {
		c.metrics.ephemeral.Add(1)
		return newRequestScanState(context, &c.metrics)
	}

	now := c.now()
	c.mu.Lock()
	if entry, ok := c.entries[requestID]; ok {
		switch {
		case c.expired(entry, now):
			c.removeLocked(entry)
			c.metrics.expirations.Add(1)
		case entry.state.context == context:
			entry.lastAccess = now
			c.lru.MoveToFront(entry.element)
			state := entry.state
			c.metrics.reused.Add(1)
			c.mu.Unlock()
			return state
		default:
			c.removeLocked(entry)
			c.metrics.contextResets.Add(1)
		}
	}

	state := newRequestScanState(context, &c.metrics)
	entry := &requestScanCacheEntry{
		requestID:  requestID,
		state:      state,
		lastAccess: now,
	}
	entry.element = c.lru.PushFront(entry)
	c.entries[requestID] = entry
	c.metrics.created.Add(1)

	for len(c.entries) > c.maxEntries {
		oldest := c.lru.Back()
		if oldest == nil {
			break
		}
		c.removeLocked(oldest.Value.(*requestScanCacheEntry))
		c.metrics.evictions.Add(1)
	}
	c.mu.Unlock()
	return state
}

// Complete idempotently removes requestID. It reports whether a retained entry
// existed. Empty IDs and ephemeral states have nothing to remove.
func (c *RequestScanCache) Complete(requestID string) bool {
	if c == nil || requestID == "" {
		return false
	}

	c.mu.Lock()
	entry, ok := c.entries[requestID]
	if ok {
		c.removeLocked(entry)
		c.metrics.completions.Add(1)
	}
	c.mu.Unlock()
	return ok
}

// Prune removes entries whose sliding TTL has elapsed and returns the number
// removed. It is a no-op when TTL is disabled. An entry expires at age >= TTL.
func (c *RequestScanCache) Prune() int {
	if c == nil || c.ttl <= 0 {
		return 0
	}

	now := c.now()
	removed := 0
	c.mu.Lock()
	for element := c.lru.Back(); element != nil; {
		previous := element.Prev()
		entry := element.Value.(*requestScanCacheEntry)
		if c.expired(entry, now) {
			c.removeLocked(entry)
			removed++
		}
		element = previous
	}
	if removed > 0 {
		c.metrics.expirations.Add(uint64(removed))
	}
	c.mu.Unlock()
	return removed
}

// Len returns the number of currently retained entries. It does not implicitly
// prune expired entries; callers that need expiration applied should call Prune.
func (c *RequestScanCache) Len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	length := len(c.entries)
	c.mu.Unlock()
	return length
}

// Stats returns aggregate counters and current occupancy without exposing IDs,
// contexts, fingerprints, or renderer values.
func (c *RequestScanCache) Stats() RequestScanCacheStats {
	if c == nil {
		return RequestScanCacheStats{}
	}

	c.mu.Lock()
	entries := len(c.entries)
	c.mu.Unlock()
	return RequestScanCacheStats{
		Entries:       entries,
		MaxEntries:    c.maxEntries,
		TTL:           c.ttl,
		Acquires:      c.metrics.acquires.Load(),
		Created:       c.metrics.created.Load(),
		Reused:        c.metrics.reused.Load(),
		ContextResets: c.metrics.contextResets.Load(),
		Ephemeral:     c.metrics.ephemeral.Load(),
		SeenHits:      c.metrics.seenHits.Load(),
		SeenMisses:    c.metrics.seenMisses.Load(),
		Records:       c.metrics.records.Load(),
		Completions:   c.metrics.completions.Load(),
		Expirations:   c.metrics.expirations.Load(),
		Evictions:     c.metrics.evictions.Load(),
	}
}

func (c *RequestScanCache) expired(entry *requestScanCacheEntry, now time.Time) bool {
	return c.ttl > 0 && now.Sub(entry.lastAccess) >= c.ttl
}

func (c *RequestScanCache) removeLocked(entry *requestScanCacheEntry) {
	delete(c.entries, entry.requestID)
	if entry.element != nil {
		c.lru.Remove(entry.element)
		entry.element = nil
	}
}
