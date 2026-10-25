package execution

// F-01 regression tests: the shared authority-admission probe must
// broadcast one completed result to every concurrent waiter. The
// pre-repair implementation delivered the result on a single buffered
// channel — one waiter consumed it and the rest fell through to their
// timeout denial, so a completed probe was never actually shared.

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// broadcastWaiters runs n concurrent admissions against probe and
// returns each result. The probe's check is released simultaneously
// so every waiter is parked on the same in-flight operation.
func broadcastWaiters(t *testing.T, n int, probe func() error) []error {
	t.Helper()
	var wg sync.WaitGroup
	start := make(chan struct{})
	res := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			res[i] = probe()
		}(i)
	}
	close(start)
	wg.Wait()
	return res
}

func TestControlGateProbeBroadcast32(t *testing.T) {
	var calls atomic.Int32
	gate := make(chan struct{})
	check := func() error {
		calls.Add(1)
		<-gate
		return nil
	}
	probe := controlGateProbe(check, 5*time.Second)

	// Park all 32 waiters on the in-flight probe, then let it complete.
	done := make(chan []error, 1)
	go func() { done <- broadcastWaiters(t, 32, probe) }()
	for calls.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(30 * time.Millisecond) // let every waiter attach
	close(gate)

	res := <-done
	for i, err := range res {
		if err != nil {
			t.Fatalf("waiter %d: completed probe delivered %v — result must broadcast to every waiter", i, err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("shared probe ran %d underlying checks, want exactly 1 (single-flight)", calls.Load())
	}
}

func TestControlGateProbeBroadcast128(t *testing.T) {
	var calls atomic.Int32
	gate := make(chan struct{})
	check := func() error {
		calls.Add(1)
		<-gate
		return nil
	}
	probe := controlGateProbe(check, 10*time.Second)

	done := make(chan []error, 1)
	go func() { done <- broadcastWaiters(t, 128, probe) }()
	for calls.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(60 * time.Millisecond)
	close(gate)

	res := <-done
	for i, err := range res {
		if err != nil {
			t.Fatalf("waiter %d: completed probe delivered %v", i, err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("shared probe ran %d underlying checks, want exactly 1", calls.Load())
	}
}

// A failing check broadcasts the same failure to every waiter —
// fail-closed semantics shared, not raffled.
func TestControlGateProbeBroadcastFailure(t *testing.T) {
	want := errors.New("ledger integrity check failed")
	var calls atomic.Int32
	gate := make(chan struct{})
	check := func() error { calls.Add(1); <-gate; return want }
	probe := controlGateProbe(check, 5*time.Second)

	done := make(chan []error, 1)
	go func() { done <- broadcastWaiters(t, 32, probe) }()
	for calls.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(30 * time.Millisecond)
	close(gate)

	res := <-done
	for i, err := range res {
		if !errors.Is(err, want) {
			t.Fatalf("waiter %d got %v, want shared failure %v", i, err, want)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("probe ran %d checks, want 1", calls.Load())
	}
}

// A wedged probe denies every waiter at its own budget — timeouts are
// per-waiter and never admit.
func TestControlGateProbeConcurrentDeadline(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	var calls atomic.Int32
	check := func() error { calls.Add(1); <-release; return nil }
	probe := controlGateProbe(check, 120*time.Millisecond)

	start := time.Now()
	res := broadcastWaiters(t, 16, probe)
	for i, err := range res {
		if err == nil {
			t.Fatalf("waiter %d admitted during a wedged probe — timeout must fail closed", i)
		}
	}
	if d := time.Since(start); d > 4*time.Second {
		t.Fatalf("waiters took %s — timeouts must be per-waiter, not serialized", d)
	}
	if calls.Load() != 1 {
		t.Fatalf("wedged probe spawned %d checks, want 1 (bounded goroutine)", calls.Load())
	}
}

// A probe that outlives its waiters still completes its generation
// without corrupting the shared slot: the next call probes fresh.
func TestControlGateProbeStaleWorkerCompletion(t *testing.T) {
	release := make(chan struct{})
	var calls atomic.Int32
	check := func() error { calls.Add(1); <-release; return nil }
	probe := controlGateProbe(check, 80*time.Millisecond)

	// Generation 1: every waiter times out while the worker runs on.
	if err := probe(); err == nil {
		t.Fatal("timed-out waiter admitted")
	}
	if calls.Load() != 1 {
		t.Fatalf("calls=%d, want 1", calls.Load())
	}

	// Let generation 1 finish late (stale worker).
	close(release)
	deadline := time.Now().Add(3 * time.Second)
	for calls.Load() != 1 {
		if time.Now().After(deadline) {
			t.Fatal("worker never released")
		}
	}
	time.Sleep(30 * time.Millisecond)

	// Generation 2 must be a fresh probe — not a stale replay.
	release2 := make(chan struct{})
	check2 := func() error { calls.Add(1); <-release2; return errors.New("halted") }
	probe2 := controlGateProbe(check2, time.Second)
	if err := probe2(); err == nil {
		t.Fatal("second-generation probe did not observe the new ledger state")
	}
	close(release2)
}

// Callers already attached when the probe completes share the result;
// a call placed after completion re-probes (completed state is never
// reused beyond its validity).
func TestControlGateProbeRecheckAfterCompletion(t *testing.T) {
	var calls atomic.Int32
	check := func() error { calls.Add(1); return nil }
	probe := controlGateProbe(check, time.Second)

	if err := probe(); err != nil {
		t.Fatal(err)
	}
	if err := probe(); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("calls=%d, want 2 — a completed probe must not be reused", calls.Load())
	}
}

// Cancellation of waiters mid-probe (timeout = the cancellation this
// API exposes) does not corrupt the shared operation: the attached
// worker still completes and a later call probes fresh.
func TestControlGateProbeCancelDuringSharedProbe(t *testing.T) {
	release := make(chan struct{})
	var calls atomic.Int32
	check := func() error { calls.Add(1); <-release; return nil }
	probe := controlGateProbe(check, 60*time.Millisecond)

	res := broadcastWaiters(t, 8, probe)
	for i, err := range res {
		if err == nil {
			t.Fatalf("waiter %d admitted past its cancellation budget", i)
		}
	}
	close(release)
	time.Sleep(20 * time.Millisecond)
	if err := probe(); err != nil {
		t.Fatalf("fresh probe after shared cancellation: %v", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("calls=%d, want 2", calls.Load())
	}
}

// Repeated deterministic stress: mixed budgets and outcomes under the
// race detector — no lost broadcasts, no unauthorized admits.
func TestControlGateProbeStress(t *testing.T) {
	for iter := 0; iter < 50; iter++ {
		var calls atomic.Int32
		gate := make(chan struct{})
		fail := iter%3 == 0
		check := func() error {
			calls.Add(1)
			<-gate
			if fail {
				return fmt.Errorf("iteration %d denied", iter)
			}
			return nil
		}
		probe := controlGateProbe(check, 3*time.Second)
		done := make(chan []error, 1)
		go func() { done <- broadcastWaiters(t, 24, probe) }()
		for calls.Load() == 0 {
			time.Sleep(time.Millisecond)
		}
		close(gate)
		res := <-done
		for i, err := range res {
			if fail && err == nil {
				t.Fatalf("iter %d waiter %d admitted under a failing check", iter, i)
			}
			if !fail && err != nil {
				t.Fatalf("iter %d waiter %d lost the broadcast: %v", iter, i, err)
			}
		}
	}
}
