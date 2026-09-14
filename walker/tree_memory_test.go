package walker

import (
	"context"
	"errors"
	"strings"
	"testing"
	"unsafe"

	"github.com/ahoo/cpa-plugin-privacyfilter/payload"
)

func wideDeepNumericBody(depth, leaves int) []byte {
	var body strings.Builder
	body.Grow(depth*6 + leaves*2 + 1)
	for range depth {
		body.WriteString(`{"k":`)
	}
	body.WriteByte('[')
	for index := 0; index < leaves; index++ {
		if index != 0 {
			body.WriteByte(',')
		}
		body.WriteString("12345678")
	}
	body.WriteByte(']')
	for range depth {
		body.WriteByte('}')
	}
	return []byte(body.String())
}

func parseTreeStats(t *testing.T, depth, leaves int) (pathNodes, retained int) {
	t.Helper()
	body := wideDeepNumericBody(depth, leaves)
	document, err := payload.ScanObject(context.Background(), body, payload.ScanOptions{})
	if err != nil {
		t.Fatalf("ScanObject(depth=%d, leaves=%d): %v", depth, leaves, err)
	}
	root, err := parseTree(context.Background(), body, document)
	if err != nil {
		t.Fatalf("parseTree(depth=%d, leaves=%d): %v", depth, leaves, err)
	}
	return len(root.path.arena.nodes), root.path.arena.budget.used
}

func TestParentLinkedPathStorageScalesWithNodesNotDepthProduct(t *testing.T) {
	const leaves = 4_000
	shallowPaths, shallowRetained := parseTreeStats(t, 8, leaves)
	deepPaths, deepRetained := parseTreeStats(t, 96, leaves)

	if shallowPaths != leaves+8 || deepPaths != leaves+96 {
		t.Fatalf("path arena sizes = shallow %d, deep %d; want %d and %d", shallowPaths, deepPaths, leaves+8, leaves+96)
	}
	if deepRetained > shallowRetained+1<<20 {
		t.Fatalf("deep shape retained %d bytes versus shallow %d; path storage appears depth-amplified", deepRetained, shallowRetained)
	}
	if deepRetained > 16<<20 {
		t.Fatalf("scaled deep shape retained %d bytes, want <= 16 MiB", deepRetained)
	}

	widePaths, wideRetained := parseTreeStats(t, 96, 2*leaves)
	if widePaths != 2*leaves+96 {
		t.Fatalf("wide path arena size = %d, want %d", widePaths, 2*leaves+96)
	}
	if wideRetained > deepRetained*5/2 {
		t.Fatalf("doubling nodes grew retained bytes from %d to %d", deepRetained, wideRetained)
	}
}

var treeAllocationSink *node

func treeAllocatedBytesPerParse(t *testing.T, depth, leaves int) int64 {
	t.Helper()
	body := wideDeepNumericBody(depth, leaves)
	document, err := payload.ScanObject(context.Background(), body, payload.ScanOptions{})
	if err != nil {
		t.Fatalf("ScanObject(depth=%d, leaves=%d): %v", depth, leaves, err)
	}
	result := testing.Benchmark(func(benchmark *testing.B) {
		for range benchmark.N {
			root, parseErr := parseTree(context.Background(), body, document)
			if parseErr != nil {
				benchmark.Fatal(parseErr)
			}
			treeAllocationSink = root
		}
	})
	return result.AllocedBytesPerOp()
}

func TestTreeAllocationDoesNotScaleByLeafDepth(t *testing.T) {
	const leaves = 1_000
	shallow := treeAllocatedBytesPerParse(t, 8, leaves)
	deep := treeAllocatedBytesPerParse(t, 96, leaves)
	wide := treeAllocatedBytesPerParse(t, 96, 2*leaves)

	if deep > shallow*2 {
		t.Fatalf("deep tree allocated %d bytes versus shallow %d; want <= 2x", deep, shallow)
	}
	if deep > 8<<20 {
		t.Fatalf("scaled deep tree allocated %d bytes, want <= 8 MiB", deep)
	}
	if wide > deep*5/2 {
		t.Fatalf("doubling leaves grew allocations from %d to %d; want <= 2.5x", deep, wide)
	}
}

func TestTreeSharesStructuralRetentionBudgetWithScanner(t *testing.T) {
	body := []byte(`{"messages":[]}`)
	limits := payload.Limits{MaxStructuralBytes: 2_000}
	document, err := payload.ScanObject(context.Background(), body, payload.ScanOptions{Limits: limits})
	if err != nil {
		t.Fatalf("scanner should fit the shared budget: %v", err)
	}
	if _, err = parseTree(context.Background(), body, document); !errors.Is(err, payload.ErrStructuralLimit) {
		t.Fatalf("parseTree error = %v, want ErrStructuralLimit", err)
	}
}

func parsedTree(t *testing.T, body []byte) (*payload.Document, *node) {
	t.Helper()
	document, err := payload.ScanObject(context.Background(), body, payload.ScanOptions{})
	if err != nil {
		t.Fatalf("ScanObject: %v", err)
	}
	root, err := parseTree(context.Background(), body, document)
	if err != nil {
		t.Fatalf("parseTree: %v", err)
	}
	return document, root
}

func TestTargetCapacityChargeCoversTargetType(t *testing.T) {
	if size := int(unsafe.Sizeof(Target{})); size > retainedTreeTargetBytes {
		t.Fatalf("Target size %d exceeds retained charge %d", size, retainedTreeTargetBytes)
	}
}

func TestReserveTargetCapacityRejectsUnavailableArena(t *testing.T) {
	for index, path := range []treePath{{}, {arena: &treePathArena{}}} {
		if _, err := path.reserveTargetCapacity(nil); err == nil {
			t.Fatalf("case %d accepted unavailable arena budget", index)
		}
	}
}

func TestCollectorErrorStopsTargetCollection(t *testing.T) {
	document, root := parsedTree(t, []byte(`{"value":"x"}`))
	collector := newCollector(context.Background(), ProtocolOpenAI, "openai", document, root)
	sentinel := errors.New("sticky collector error")
	collector.err = sentinel
	used := collector.budget.used
	if err := collector.add(root.object[0].value, ScopeToolInput, TargetKindJSONValue, MutabilityDirect); !errors.Is(err, sentinel) {
		t.Fatalf("add error = %v, want sticky collector error", err)
	}
	if collector.budget.used != used || len(collector.result.Targets) != 0 || len(collector.targets) != 0 {
		t.Fatal("target collection changed state after sticky error")
	}
}

func TestCollectorStructuralErrorPrecedesLaterShapeError(t *testing.T) {
	body := []byte(`{"contents":[{"parts":[0,{"text":5}]}]}`)
	document, root := parsedTree(t, body)
	collector := newCollector(context.Background(), ProtocolGemini, "gemini", document, root)
	collector.budget.limit = collector.budget.used
	if err := walkGemini(collector, root); !errors.Is(err, payload.ErrStructuralLimit) {
		t.Fatalf("walkGemini error = %v, want ErrStructuralLimit", err)
	}
	if len(collector.result.Targets) != 0 || len(collector.result.Unsupported) != 0 {
		t.Fatal("collector retained results after structural refusal")
	}
}

func TestCollectorTargetContextBudgetBoundary(t *testing.T) {
	const initialTargetCapacity = 16
	const pathDepth = 1
	required := retainedTreeIndexEntryBytes +
		initialTargetCapacity*retainedTreeTargetBytes +
		2*pathDepth*retainedPathSegmentBytes +
		retainedFieldContextBytes

	for _, shortBy := range []int{1, 0} {
		document, root := parsedTree(t, []byte(`{"API-Key":"x"}`))
		collector := newCollector(context.Background(), ProtocolOpenAI, "openai", document, root)
		before := collector.budget.used
		collector.budget.limit = before + required - shortBy
		err := collector.add(root.object[0].value, ScopeToolInput, TargetKindJSONValue, MutabilityDirect)
		if shortBy == 1 {
			if !errors.Is(err, payload.ErrStructuralLimit) || len(collector.result.Targets) != 0 || len(collector.targets) != 0 {
				t.Fatal("one-byte-short target budget did not refuse atomically")
			}
			continue
		}
		if err != nil || len(collector.result.Targets) != 1 {
			t.Fatalf("exact target budget failed: %v", err)
		}
		if collector.budget.used-before != required {
			t.Fatalf("target budget delta = %d, want %d", collector.budget.used-before, required)
		}
		if collector.result.Targets[0].Context.Fields.ImmediateKey != "api_key" {
			t.Fatal("normalized target context was not retained")
		}
	}
}

func TestCollectorOpaqueBudgetBoundary(t *testing.T) {
	for _, shortBy := range []int{1, 0} {
		document, root := parsedTree(t, []byte(`{"value":"x"}`))
		collector := newCollector(context.Background(), ProtocolOpenAI, "openai", document, root)
		collector.budget.limit = collector.budget.used + retainedTreeIndexEntryBytes - shortBy
		err := collector.markOpaque(root.object[0].value)
		if shortBy == 1 {
			if !errors.Is(err, payload.ErrStructuralLimit) || len(collector.opaque) != 0 {
				t.Fatal("one-byte-short opaque budget retained an index entry")
			}
			continue
		}
		if err != nil || len(collector.opaque) != 1 {
			t.Fatalf("exact opaque budget failed: %v", err)
		}
	}
}

func TestCollectorUnsupportedValueBudgetBoundary(t *testing.T) {
	const prefix = "unknown message role "
	untrusted := strings.Repeat("x", 64)
	const initialUnsupportedCapacity = 16
	const pathDepth = 1
	required := len(prefix) + 2 + 4*len(untrusted) +
		initialUnsupportedCapacity*retainedTreeUnsupportedBytes +
		pathDepth*retainedPathSegmentBytes + retainedTreeIndexEntryBytes

	for _, shortBy := range []int{1, 0} {
		document, root := parsedTree(t, []byte(`{"role":"x"}`))
		collector := newCollector(context.Background(), ProtocolOpenAI, "openai", document, root)
		collector.budget.limit = collector.budget.used + required - shortBy
		collector.unsupportedValue(root.object[0].value, prefix, untrusted)
		if shortBy == 1 {
			if !errors.Is(collector.err, payload.ErrStructuralLimit) || len(collector.result.Unsupported) != 0 {
				t.Fatal("one-byte-short unsupported budget retained a diagnostic")
			}
			continue
		}
		if collector.err != nil || len(collector.result.Unsupported) != 1 {
			t.Fatalf("exact unsupported budget failed: %v", collector.err)
		}
		if collector.budget.used != collector.budget.limit {
			t.Fatal("unsupported diagnostic did not consume its reserved bound")
		}
	}
}

func TestTargetAndTokenPathsDoNotAlias(t *testing.T) {
	body := []byte(`{"messages":[{"role":"user","content":"x"}]}`)
	result, err := Walk(context.Background(), "openai", body)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(result.Targets) != 1 {
		t.Fatalf("target count = %d, want 1", len(result.Targets))
	}
	target := result.Targets[0]
	originalTokenPath := target.Token.Path.Clone()
	target.Path[0] = payload.Key("changed")
	if !target.Token.Path.Equal(originalTokenPath) {
		t.Fatal("mutating Target.Path changed Token.Path")
	}
	if _, _, err = result.Document.Replace(context.Background(), []payload.Replacement{{Token: target.Token, Value: "y"}}); err != nil {
		t.Fatalf("diagnostic path mutation invalidated token: %v", err)
	}

	result, err = Walk(context.Background(), "openai", body)
	if err != nil {
		t.Fatalf("second Walk: %v", err)
	}
	target = result.Targets[0]
	originalTargetPath := target.Path.Clone()
	target.Token.Path[0] = payload.Key("changed")
	if !target.Path.Equal(originalTargetPath) {
		t.Fatal("mutating Token.Path changed Target.Path")
	}
	if _, _, err = result.Document.Replace(context.Background(), []payload.Replacement{{Token: target.Token, Value: "y"}}); !errors.Is(err, payload.ErrInvalidToken) {
		t.Fatalf("modified token error = %v, want ErrInvalidToken", err)
	}
}
