//go:build linux && !race

package walker

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"syscall"
	"testing"

	"github.com/ahoo/cpa-plugin-privacyfilter/payload"
)

const treeRSSChildEnvironment = "PRIVACYFILTER_TREE_RSS_CHILD"

func TestWideDeepTreeResidentMemoryBound(t *testing.T) {
	if os.Getenv(treeRSSChildEnvironment) == "1" {
		runWideDeepTreeRSSChild(t)
		return
	}
	if testing.Short() {
		t.Skip("resource subprocess disabled in short mode")
	}

	command := exec.Command(os.Args[0], "-test.run=^TestWideDeepTreeResidentMemoryBound$", "-test.count=1")
	command.Env = append(os.Environ(),
		treeRSSChildEnvironment+"=1",
		"GOMEMLIMIT=256MiB",
		"GOMAXPROCS=1",
	)
	if err := command.Run(); err != nil {
		t.Fatalf("wide/deep resource subprocess failed: %v", err)
	}
	usage, ok := command.ProcessState.SysUsage().(*syscall.Rusage)
	if !ok || usage == nil {
		t.Fatal("wide/deep resource subprocess did not expose Linux rusage")
	}
	const maxRSSKiB = 256 << 10
	if usage.Maxrss > maxRSSKiB {
		t.Fatalf("wide/deep resource subprocess max RSS = %d KiB, want <= %d KiB", usage.Maxrss, maxRSSKiB)
	}
}

func runWideDeepTreeRSSChild(t *testing.T) {
	debug.SetMemoryLimit(256 << 20)
	debug.SetGCPercent(50)
	body := wideDeepNumericBody(120, 150_000)
	if len(body) < 1<<20 {
		t.Fatalf("wide/deep fixture is only %d bytes", len(body))
	}
	document, err := payload.ScanObject(context.Background(), body, payload.ScanOptions{})
	if err != nil {
		t.Fatalf("wide/deep scanner failed: %v", err)
	}
	root, err := parseTree(context.Background(), body, document)
	if err != nil {
		t.Fatalf("wide/deep tree failed: %v", err)
	}
	if got := len(root.path.arena.nodes); got < 150_000 {
		t.Fatalf("wide/deep fixture retained only %d path nodes", got)
	}
	treeAllocationSink = root
	runtime.KeepAlive(body)
	runtime.KeepAlive(document)
}
