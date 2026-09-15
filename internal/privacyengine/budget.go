package privacyengine

import (
	"fmt"
	"sync"
)

const (
	defaultMaxBytes    = 1 << 20 // large enough for the approximately 490 KiB issue #3 request
	defaultMaxFindings = 256
	defaultMaxNodes    = 1024
)

// Limits bounds cumulative work for one request. Zero fields select the safe
// package defaults; negative values are invalid. Limits deliberately have no
// unlimited sentinel, so accidentally omitted configuration stays bounded.
type Limits struct {
	MaxBytes    int
	MaxFindings int
	MaxNodes    int
}

// DefaultLimits returns the limits used for zero-valued fields.
func DefaultLimits() Limits {
	return Limits{
		MaxBytes:    defaultMaxBytes,
		MaxFindings: defaultMaxFindings,
		MaxNodes:    defaultMaxNodes,
	}
}

func normalizeLimits(limits Limits) (Limits, error) {
	if limits.MaxBytes < 0 || limits.MaxFindings < 0 || limits.MaxNodes < 0 {
		return Limits{}, fmt.Errorf("privacyengine: limits must not be negative")
	}
	defaults := DefaultLimits()
	if limits.MaxBytes == 0 {
		limits.MaxBytes = defaults.MaxBytes
	}
	if limits.MaxFindings == 0 {
		limits.MaxFindings = defaults.MaxFindings
	}
	if limits.MaxNodes == 0 {
		limits.MaxNodes = defaults.MaxNodes
	}
	return limits, nil
}

// Usage is a point-in-time snapshot of cumulative request work.
type Usage struct {
	Bytes    int
	Findings int
	Nodes    int
}

// Budget is a concurrency-safe, cumulative request budget. Construct one per
// request and pass it to every Detect or Redact call made while walking that
// request. The zero value is usable and adopts DefaultLimits on first use.
type Budget struct {
	mu          sync.Mutex
	initialized bool
	limits      Limits
	usage       Usage
}

// NewBudget validates limits and constructs an empty request budget.
func NewBudget(limits Limits) (*Budget, error) {
	normalized, err := normalizeLimits(limits)
	if err != nil {
		return nil, err
	}
	return &Budget{initialized: true, limits: normalized}, nil
}

func newBudgetUnchecked(limits Limits) *Budget {
	return &Budget{initialized: true, limits: limits}
}

func (b *Budget) initializeLocked() {
	if b.initialized {
		return
	}
	b.limits = DefaultLimits()
	b.initialized = true
}

// Limits returns the effective immutable limits of this budget.
func (b *Budget) Limits() Limits {
	if b == nil {
		return Limits{}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.initializeLocked()
	return b.limits
}

// Usage returns a concurrency-safe snapshot.
func (b *Budget) Usage() Usage {
	if b == nil {
		return Usage{}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.initializeLocked()
	return b.usage
}

func (b *Budget) takeNode(byteCount int) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.initializeLocked()
	if b.usage.Nodes >= b.limits.MaxNodes {
		return &LimitError{
			Resource: ResourceNodes, Limit: b.limits.MaxNodes,
			Used: b.usage.Nodes, Requested: 1,
		}
	}
	if byteCount < 0 || byteCount > b.limits.MaxBytes-b.usage.Bytes {
		return &LimitError{
			Resource: ResourceBytes, Limit: b.limits.MaxBytes,
			Used: b.usage.Bytes, Requested: byteCount,
		}
	}
	b.usage.Nodes++
	b.usage.Bytes += byteCount
	return nil
}

func (b *Budget) remainingFindings() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.initializeLocked()
	return b.limits.MaxFindings - b.usage.Findings
}

func (b *Budget) takeFindings(count int) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.initializeLocked()
	if count < 0 || count > b.limits.MaxFindings-b.usage.Findings {
		return &LimitError{
			Resource: ResourceFindings, Limit: b.limits.MaxFindings,
			Used: b.usage.Findings, Requested: count,
		}
	}
	b.usage.Findings += count
	return nil
}
