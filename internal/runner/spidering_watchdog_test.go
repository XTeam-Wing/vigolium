package runner

import (
	"sync"
	"testing"
	"time"
)

// These guard the spidering watchdog — the hard guarantee that a wedged RunSpider
// (unresponsive/anti-bot browser, an unbounded rod CDP call, a stuck teardown)
// can never hang the scan forever. runWithWatchdog is the testable core;
// runSpiderWatchdog wraps it around the real (browser-driven) RunSpider.

// TestRunWithWatchdog_FastWorkReturnsResult: work that finishes before the
// timeout returns its own result, and onTimeout is never called.
func TestRunWithWatchdog_FastWorkReturnsResult(t *testing.T) {
	var onTimeoutCalled bool
	got := runWithWatchdog(
		2*time.Second,
		func() string { return "work" },
		func() string { onTimeoutCalled = true; return "timeout" },
	)
	if got != "work" {
		t.Fatalf("got %q, want %q", got, "work")
	}
	if onTimeoutCalled {
		t.Fatal("onTimeout was called even though work finished in time")
	}
}

// TestRunWithWatchdog_WedgedWorkTimesOut: work that blocks past the timeout does
// NOT hang the caller — onTimeout's result is returned promptly, within a small
// multiple of the timeout (proving the wedged worker is abandoned, not awaited).
func TestRunWithWatchdog_WedgedWorkTimesOut(t *testing.T) {
	release := make(chan struct{})
	defer close(release) // let the abandoned worker exit at test end

	const timeout = 100 * time.Millisecond
	start := time.Now()
	got := runWithWatchdog(
		timeout,
		func() string {
			<-release // simulate a wedged op that never returns on its own
			return "work"
		},
		func() string { return "timeout" },
	)
	elapsed := time.Since(start)

	if got != "timeout" {
		t.Fatalf("got %q, want %q (watchdog should have fired)", got, "timeout")
	}
	// Must return ~at the timeout, not block on the wedged worker. Generous upper
	// bound to stay non-flaky on loaded CI.
	if elapsed > 2*time.Second {
		t.Fatalf("runWithWatchdog blocked %s on a wedged worker; the watchdog did not abandon it", elapsed)
	}
}

// TestRunWithWatchdog_LateWorkerDoesNotBlock: after the watchdog fires and the
// caller has moved on, the abandoned worker finishing later must not panic or
// deadlock on the (buffered) done channel.
func TestRunWithWatchdog_LateWorkerDoesNotBlock(t *testing.T) {
	finished := make(chan struct{})
	var once sync.Once

	got := runWithWatchdog(
		50*time.Millisecond,
		func() int {
			time.Sleep(300 * time.Millisecond) // finishes well after the watchdog fired
			once.Do(func() { close(finished) })
			return 1
		},
		func() int { return -1 },
	)
	if got != -1 {
		t.Fatalf("got %d, want -1 (timeout path)", got)
	}

	// The late worker must complete cleanly (buffered send, no deadlock/panic).
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("abandoned worker never finished — it likely blocked sending on the done channel")
	}
}
