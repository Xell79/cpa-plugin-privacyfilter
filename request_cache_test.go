package main

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testRequestScanContext() RequestScanContext {
	return RequestScanContext{
		Revision:     7,
		SourceFormat: "openai",
		Model:        "effective-model",
	}
}

func TestRequestScanStateSeenAndRecord(t *testing.T) {
	state := NewEphemeralRequestScanState(testRequestScanContext())
	input := []byte(`{"messages":[{"content":"secret"}]}`)
	sanitized := []byte(`{"messages":[{"content":"[secret]"}]}`)

	if state.Seen(input) {
		t.Fatal("unrecorded input reported as seen")
	}

	state.Record(input, nil)
	if !state.Seen(input) {
		t.Fatal("unchanged successful input was not a hit")
	}
	if state.Seen([]byte(`{"messages":[{"content":"changed"}]}`)) {
		t.Fatal("changed body reported as seen")
	}

	state.Record(input, sanitized)
	if !state.Seen(sanitized) {
		t.Fatal("sanitized output was not a hit")
	}
	if state.Seen(input) {
		t.Fatal("unsanitized input remained a hit after changed scan")
	}

	// Mutating caller-owned buffers cannot alter the retained fingerprint.
	copy(sanitized, []byte(`xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`))
	if !state.Seen([]byte(`{"messages":[{"content":"[secret]"}]}`)) {
		t.Fatal("state retained the caller's body buffer instead of only its hash")
	}
}

func TestRequestScanCacheContextChangesResetState(t *testing.T) {
	base := testRequestScanContext()
	tests := []struct {
		name    string
		context RequestScanContext
	}{
		{
			name: "revision",
			context: RequestScanContext{
				Revision:     base.Revision + 1,
				SourceFormat: base.SourceFormat,
				Model:        base.Model,
			},
		},
		{
			name: "source",
			context: RequestScanContext{
				Revision:     base.Revision,
				SourceFormat: "claude",
				Model:        base.Model,
			},
		},
		{
			name: "model",
			context: RequestScanContext{
				Revision:     base.Revision,
				SourceFormat: base.SourceFormat,
				Model:        "different-model",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := NewRequestScanCache(RequestScanCacheOptions{
				TTL:        time.Minute,
				MaxEntries: 4,
			})
			body := []byte("safe body")
			oldState := cache.Acquire("request-1", base)
			oldState.Record(body, nil)
			renderer := &struct{ marker string }{marker: "old"}
			oldState.StoreRendererState(renderer)

			if got := cache.Acquire("request-1", base); got != oldState {
				t.Fatal("matching context did not reuse state")
			}

			newState := cache.Acquire("request-1", tt.context)
			if newState == oldState {
				t.Fatal("changed context reused old logical state")
			}
			if newState.Seen(body) {
				t.Fatal("fingerprint crossed a context boundary")
			}
			if value, ok := newState.LoadRendererState(); ok || value != nil {
				t.Fatalf("renderer state crossed a context boundary: value=%v ok=%v", value, ok)
			}
			if got := newState.Context(); got != tt.context {
				t.Fatalf("Context() = %+v, want %+v", got, tt.context)
			}
			if got := cache.Len(); got != 1 {
				t.Fatalf("Len() = %d, want 1", got)
			}
			if got := cache.Stats().ContextResets; got != 1 {
				t.Fatalf("ContextResets = %d, want 1", got)
			}
		})
	}
}

func TestRequestScanCacheDifferentRequestIDsAreIsolated(t *testing.T) {
	cache := NewRequestScanCache(RequestScanCacheOptions{MaxEntries: 4})
	context := testRequestScanContext()
	body := []byte("same bytes")

	first := cache.Acquire("request-1", context)
	first.Record(body, nil)
	second := cache.Acquire("request-2", context)

	if first == second {
		t.Fatal("different RequestIDs shared a state")
	}
	if second.Seen(body) {
		t.Fatal("fingerprint crossed a RequestID boundary")
	}
	if got := cache.Len(); got != 2 {
		t.Fatalf("Len() = %d, want 2", got)
	}
}

func TestRequestScanCacheCompleteIsIdempotent(t *testing.T) {
	cache := NewRequestScanCache(RequestScanCacheOptions{MaxEntries: 2})
	context := testRequestScanContext()
	oldState := cache.Acquire("request-1", context)
	oldState.Record([]byte("body"), nil)

	if !cache.Complete("request-1") {
		t.Fatal("first Complete did not report removal")
	}
	if cache.Complete("request-1") {
		t.Fatal("second Complete reported a removal")
	}
	if got := cache.Len(); got != 0 {
		t.Fatalf("Len() = %d after Complete, want 0", got)
	}

	newState := cache.Acquire("request-1", context)
	if newState == oldState || newState.Seen([]byte("body")) {
		t.Fatal("completed request state was reused")
	}
	if got := cache.Stats().Completions; got != 1 {
		t.Fatalf("Completions = %d, want 1", got)
	}
}

type requestCacheFakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *requestCacheFakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *requestCacheFakeClock) Advance(duration time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(duration)
	c.mu.Unlock()
}

func TestRequestScanCacheTTLAndSlidingAccess(t *testing.T) {
	clock := &requestCacheFakeClock{now: time.Unix(1_000, 0)}
	cache := newRequestScanCache(RequestScanCacheOptions{
		TTL:        10 * time.Second,
		MaxEntries: 4,
	}, clock.Now)
	context := testRequestScanContext()
	original := cache.Acquire("request-1", context)

	clock.Advance(9 * time.Second)
	if removed := cache.Prune(); removed != 0 {
		t.Fatalf("Prune() before TTL removed %d entries", removed)
	}
	if got := cache.Acquire("request-1", context); got != original {
		t.Fatal("unexpired state was not reused")
	}

	clock.Advance(9 * time.Second)
	if removed := cache.Prune(); removed != 0 {
		t.Fatalf("sliding TTL was not refreshed; removed %d entries", removed)
	}
	clock.Advance(time.Second)
	if removed := cache.Prune(); removed != 1 {
		t.Fatalf("Prune() at TTL removed %d entries, want 1", removed)
	}
	if got := cache.Len(); got != 0 {
		t.Fatalf("Len() = %d after expiration, want 0", got)
	}

	fresh := cache.Acquire("request-1", context)
	clock.Advance(10 * time.Second)
	if got := cache.Acquire("request-1", context); got == fresh {
		t.Fatal("Acquire reused an expired state")
	}
	if got := cache.Stats().Expirations; got != 2 {
		t.Fatalf("Expirations = %d, want 2", got)
	}
}

func TestRequestScanCacheNonPositiveTTLDisablesExpiration(t *testing.T) {
	for _, ttl := range []time.Duration{0, -time.Second} {
		t.Run(ttl.String(), func(t *testing.T) {
			clock := &requestCacheFakeClock{now: time.Unix(1_000, 0)}
			cache := newRequestScanCache(RequestScanCacheOptions{
				TTL:        ttl,
				MaxEntries: 1,
			}, clock.Now)
			state := cache.Acquire("request-1", testRequestScanContext())
			clock.Advance(100 * 365 * 24 * time.Hour)
			if removed := cache.Prune(); removed != 0 {
				t.Fatalf("Prune() with TTL %s removed %d entries", ttl, removed)
			}
			if got := cache.Acquire("request-1", testRequestScanContext()); got != state {
				t.Fatalf("TTL %s did not disable expiration", ttl)
			}
			if got := cache.Stats().TTL; got != 0 {
				t.Fatalf("normalized TTL = %s, want 0", got)
			}
		})
	}
}

func TestRequestScanCacheEvictsLeastRecentlyUsed(t *testing.T) {
	cache := NewRequestScanCache(RequestScanCacheOptions{MaxEntries: 2})
	context := testRequestScanContext()
	first := cache.Acquire("request-1", context)
	second := cache.Acquire("request-2", context)

	// Refresh request-1, making request-2 the least recently used entry.
	if got := cache.Acquire("request-1", context); got != first {
		t.Fatal("request-1 unexpectedly changed")
	}
	third := cache.Acquire("request-3", context)

	if got := cache.Stats(); got.Entries != 2 || got.Evictions != 1 {
		t.Fatalf("Stats() after capacity eviction = %+v", got)
	}
	if got := cache.Acquire("request-1", context); got != first {
		t.Fatal("recently used request-1 was evicted")
	}
	if got := cache.Acquire("request-3", context); got != third {
		t.Fatal("new request-3 was not retained")
	}
	if got := cache.Acquire("request-2", context); got == second {
		t.Fatal("least recently used request-2 was retained")
	}
}

func TestRequestScanCacheNonPositiveCapacityIsEphemeral(t *testing.T) {
	for _, maxEntries := range []int{0, -1} {
		t.Run(fmt.Sprintf("max_%d", maxEntries), func(t *testing.T) {
			cache := NewRequestScanCache(RequestScanCacheOptions{MaxEntries: maxEntries})
			context := testRequestScanContext()
			first := cache.Acquire("request-1", context)
			first.Record([]byte("body"), nil)
			second := cache.Acquire("request-1", context)
			if first == second || second.Seen([]byte("body")) {
				t.Fatal("disabled cache retained request state")
			}
			if got := cache.Len(); got != 0 {
				t.Fatalf("Len() = %d, want 0", got)
			}
			stats := cache.Stats()
			if stats.MaxEntries != 0 || stats.Ephemeral != 2 {
				t.Fatalf("Stats() = %+v, want normalized capacity and two ephemeral states", stats)
			}
		})
	}
}

func TestRequestScanCacheEmptyRequestIDIsNeverStored(t *testing.T) {
	cache := NewRequestScanCache(RequestScanCacheOptions{MaxEntries: 2})
	context := testRequestScanContext()
	first := cache.Acquire("", context)
	first.Record([]byte("body"), nil)
	second := cache.Acquire("", context)

	if first == second || second.Seen([]byte("body")) {
		t.Fatal("empty RequestID reused cached state")
	}
	if got := cache.Len(); got != 0 {
		t.Fatalf("Len() = %d, want 0", got)
	}
	if cache.Complete("") {
		t.Fatal("Complete reported an empty-ID entry")
	}
	if got := cache.Stats().Ephemeral; got != 2 {
		t.Fatalf("Ephemeral = %d, want 2", got)
	}
}

func TestRequestScanStateRendererFactoryIsConcurrentAndSticky(t *testing.T) {
	state := NewEphemeralRequestScanState(testRequestScanContext())
	type rendererState struct{ marker int }
	createdState := &rendererState{marker: 42}
	var factoryCalls atomic.Int64

	const goroutines = 32
	results := make(chan any, goroutines)
	var wait sync.WaitGroup
	for range goroutines {
		wait.Add(1)
		go func() {
			defer wait.Done()
			results <- state.GetOrCreateRendererState(func() any {
				factoryCalls.Add(1)
				return createdState
			})
		}()
	}
	wait.Wait()
	close(results)

	for result := range results {
		if result != createdState {
			t.Fatalf("factory result = %v, want shared renderer state", result)
		}
	}
	if got := factoryCalls.Load(); got != 1 {
		t.Fatalf("factory called %d times, want 1", got)
	}
	if value, ok := state.LoadRendererState(); !ok || value != createdState {
		t.Fatalf("LoadRendererState() = %v, %v", value, ok)
	}

	state.StoreRendererState(nil)
	if value, ok := state.LoadRendererState(); !ok || value != nil {
		t.Fatalf("stored nil state = %v, %v, want nil, true", value, ok)
	}
}

func TestRequestScanCacheConcurrentReconfigureCompleteSeenRecord(t *testing.T) {
	cache := NewRequestScanCache(RequestScanCacheOptions{
		TTL:        time.Minute,
		MaxEntries: 16,
	})

	const (
		goroutines = 24
		iterations = 300
	)
	start := make(chan struct{})
	var wait sync.WaitGroup
	for worker := range goroutines {
		worker := worker
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			for iteration := range iterations {
				requestID := fmt.Sprintf("request-%d", (worker+iteration)%24)
				context := RequestScanContext{
					Revision:     uint64(iteration % 4),
					SourceFormat: []string{"openai", "claude"}[worker%2],
					Model:        fmt.Sprintf("model-%d", (worker+iteration*2)%3),
				}
				state := cache.Acquire(requestID, context)
				body := []byte(fmt.Sprintf("body-%d-%d", worker, iteration%7))
				if !state.Seen(body) {
					if iteration%2 == 0 {
						state.Record(body, nil)
					} else {
						state.Record(body, append([]byte("sanitized-"), body...))
					}
				}
				state.GetOrCreateRendererState(func() any {
					return &struct{ revision uint64 }{revision: context.Revision}
				})
				if iteration%13 == 0 {
					cache.Complete(requestID)
				}
				if iteration%47 == 0 {
					cache.Prune()
				}
				_ = cache.Len()
				_ = cache.Stats()
			}
		}()
	}
	close(start)
	wait.Wait()

	if got := cache.Len(); got > 16 {
		t.Fatalf("Len() = %d, exceeds capacity 16", got)
	}
	stats := cache.Stats()
	if stats.Acquires != goroutines*iterations {
		t.Fatalf("Acquires = %d, want %d", stats.Acquires, goroutines*iterations)
	}
	if stats.Records == 0 || stats.ContextResets == 0 || stats.Completions == 0 {
		t.Fatalf("concurrent operations did not exercise expected paths: %+v", stats)
	}
}
