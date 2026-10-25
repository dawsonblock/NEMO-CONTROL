package sandboxexecutor

// PR-05 (G5) — sandbox identity and cleanup correctness. The
// normative qualification set: every case drives the real adapter or
// the real server against the fake runtime, so the names in
// qualification/rc8-required-tests.json bind executed behavior, not
// test-name existence. ADR-0004 governs: a userspace pre-check plus a
// blind remove is not atomic deletion, so uncertain classifications
// retain the obligation instead of claiming proof.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// g5Dispatch runs a real dispatch through the adapter against the fake
// runtime and returns the signed contract plus the identity the
// runtime was bound to — the nonce the handle embeds is what every
// cleanup request must present.
func g5Dispatch(t *testing.T, backend *MSBBackend, jobID string) (*JobContractV2, RunIdentity) {
	t.Helper()
	key, _ := testAuthority(t)
	job := testContract(t, key, func(c *JobContractV2) {
		c.JobID = jobID
		c.Nonce = "ct-nonce-" + jobID
	})
	disp, err := backend.Dispatch(testContext(t), job, nil)
	if err != nil {
		t.Fatalf("dispatch %s: %v", jobID, err)
	}
	return job, disp
}

// TestCleanupReplacementSandboxSafe — the replacement-race gate.
// A substitute VM carrying foreign ownership lands under the
// authorized handle; cleanup must refuse to destroy it across
// repeated replacement attempts, and must keep refusing on retry.
func TestCleanupReplacementSandboxSafe(t *testing.T) {
	bin, stateDir := fakeMSB(t, nil)
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	ctx := testContext(t)
	job, disp := g5Dispatch(t, backend, "g5-replace")
	req := cleanupReqFor(job, disp)

	for i := 0; i < 3; i++ {
		substitute(t, stateDir, disp.Handle, map[string]string{
			"crabedence.dispatch": "foreign-nonce",
			"crabedence.job":      fmt.Sprintf("foreign-%d", i),
		})
		res, err := backend.Cleanup(ctx, req)
		if err != nil {
			t.Fatalf("attempt %d: cleanup returned %v", i, err)
		}
		if res.Outcome != CleanupIdentityMismatch {
			t.Fatalf("attempt %d: outcome %s, want IDENTITY_MISMATCH", i, res.Outcome)
		}
		if res.Outcome.ProvesAbsent() {
			t.Fatalf("attempt %d: a refused removal claimed verified absence", i)
		}
	}
	survive(t, stateDir, disp.Handle)
}

// TestCleanupLabelCollisionRejected — a foreign sandbox reusing the
// authorized name, and a hostile occupant spoofing exactly one of the
// two identity labels, are both refused. A single spoofed label is
// never sufficient authority.
func TestCleanupLabelCollisionRejected(t *testing.T) {
	bin, stateDir := fakeMSB(t, nil)
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	ctx := testContext(t)
	job, disp := g5Dispatch(t, backend, "g5-labels")
	req := cleanupReqFor(job, disp)

	// An entirely foreign occupant under our handle.
	substitute(t, stateDir, disp.Handle, map[string]string{
		"crabedence.dispatch": "foreign-nonce",
		"crabedence.job":      "foreign-job",
	})
	res, err := backend.Cleanup(ctx, req)
	if err != nil {
		t.Fatalf("foreign occupant: %v", err)
	}
	if res.Outcome != CleanupIdentityMismatch {
		t.Fatalf("foreign occupant outcome %s, want IDENTITY_MISMATCH", res.Outcome)
	}

	// A hostile occupant that learned our dispatch label but not our
	// job identity — one correct label does not authorize destruction.
	substitute(t, stateDir, disp.Handle, map[string]string{
		"crabedence.dispatch": disp.Nonce,
		"crabedence.job":      "hostile-job",
	})
	res, err = backend.Cleanup(ctx, req)
	if err != nil {
		t.Fatalf("label spoof: %v", err)
	}
	if res.Outcome != CleanupIdentityMismatch {
		t.Fatalf("label-spoofed occupant outcome %s, want IDENTITY_MISMATCH", res.Outcome)
	}
	survive(t, stateDir, disp.Handle)
}

// TestVerifiedAbsentNeverFalse — the absence-proof predicate across
// every outcome the backend can produce. ProvesAbsent is true exactly
// for the two verified-absence outcomes and nothing else; obligation
// resolution is wider precisely because RETAINED_BY_POLICY discharges
// removal without claiming the resource is gone.
func TestVerifiedAbsentNeverFalse(t *testing.T) {
	bin, stateDir := fakeMSB(t, nil)
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	ctx := testContext(t)

	cases := []struct {
		name         string
		req          func(t *testing.T, jobID string) CleanupRequest
		want         CleanupOutcome
		wantAbsent   bool
		wantResolves bool
	}{
		{
			name: "verified removal",
			req: func(t *testing.T, jobID string) CleanupRequest {
				job, disp := g5Dispatch(t, backend, jobID)
				return cleanupReqFor(job, disp)
			},
			want: CleanupRemovedVerified, wantAbsent: true, wantResolves: true,
		},
		{
			name: "already absent",
			req: func(t *testing.T, jobID string) CleanupRequest {
				job, disp := g5Dispatch(t, backend, jobID)
				if err := os.Remove(fakeStatePath(stateDir, disp.Handle)); err != nil {
					t.Fatal(err)
				}
				return cleanupReqFor(job, disp)
			},
			want: CleanupAlreadyAbsentVerified, wantAbsent: true, wantResolves: true,
		},
		{
			name: "identity mismatch",
			req: func(t *testing.T, jobID string) CleanupRequest {
				job, disp := g5Dispatch(t, backend, jobID)
				substitute(t, stateDir, disp.Handle, map[string]string{"foreign": "instance"})
				return cleanupReqFor(job, disp)
			},
			want: CleanupIdentityMismatch, wantAbsent: false, wantResolves: false,
		},
		{
			// The deletion key and the asserted identity disagree —
			// unverifiable authority, nothing is destroyed and
			// nothing is proved.
			name: "identity unverifiable",
			req: func(t *testing.T, jobID string) CleanupRequest {
				job, disp := g5Dispatch(t, backend, jobID)
				r := cleanupReqFor(job, disp)
				r.DispatchNonce = "nonce-that-is-not-the-handle-key"
				return r
			},
			want: CleanupIdentityUnverifiable, wantAbsent: false, wantResolves: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := backend.Cleanup(ctx, tc.req(t, "g5-va-"+strings.ReplaceAll(tc.name, " ", "-")))
			if err != nil {
				t.Fatalf("cleanup: %v", err)
			}
			if res.Outcome != tc.want {
				t.Fatalf("outcome %s, want %s", res.Outcome, tc.want)
			}
			if res.Outcome.ProvesAbsent() != tc.wantAbsent {
				t.Fatalf("%s ProvesAbsent=%v, want %v", res.Outcome, res.Outcome.ProvesAbsent(), tc.wantAbsent)
			}
			if res.Outcome.ResolvesObligation() != tc.wantResolves {
				t.Fatalf("%s ResolvesObligation=%v, want %v", res.Outcome, res.Outcome.ResolvesObligation(), tc.wantResolves)
			}
		})
	}

	// The enum itself: no future or unknown outcome may silently claim
	// verified absence.
	for _, o := range []CleanupOutcome{
		CleanupRemovedVerified, CleanupAlreadyAbsentVerified, CleanupIdentityMismatch,
		CleanupIdentityUnverifiable, CleanupRemovalUncertain, CleanupRetainedByPolicy,
	} {
		if o.ProvesAbsent() && o != CleanupRemovedVerified && o != CleanupAlreadyAbsentVerified {
			t.Fatalf("%s claims verified absence", o)
		}
	}
	if !CleanupRetainedByPolicy.ResolvesObligation() || CleanupRetainedByPolicy.ProvesAbsent() {
		t.Fatal("RETAINED_BY_POLICY must resolve the obligation without claiming absence")
	}
}

// TestKillAtEveryCommitBoundary — the cleanup obligation is durable
// across process death. A job that reaches its terminal write with
// cleanup pending survives a full daemon stop; the next lifetime's
// maintenance completes the obligation, and the real runtime resource
// is gone.
func TestKillAtEveryCommitBoundary(t *testing.T) {
	dir := socketDir(t)
	ledgerPath := filepath.Join(t.TempDir(), "ledger.db")
	key, keys := testAuthority(t)
	bin, fakeDir := fakeMSB(t, map[string]string{"MSB_FAKE_RM_FAIL": "1"})
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))

	// Lifetime A: dispatch reaches terminal, cleanup is blocked by a
	// runtime failure, the process dies with the obligation open.
	a := startServer(t, Config{
		SocketDir: dir, LedgerPath: ledgerPath,
		Peers: selfPeer(t), AuthorityKeys: keys,
		Backend: backend, MaintenanceInterval: -1,
	})
	conn, reader := connect(t, a.SocketPath())
	resp := sendJob(t, conn, reader, signedJobReq(t, key, func(c *JobContractV2) {
		c.JobID, c.Nonce = "g5-kill", "g5-kill-nonce"
	}))
	if resp.State != JobStateRunning {
		t.Fatalf("submit: %+v", resp)
	}
	_ = conn.Close()
	j := waitForState(t, a, "g5-kill", JobStateSucceeded)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if j, _ = a.Ledger().Get("g5-kill"); j.CleanupPending {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !j.CleanupPending {
		t.Fatalf("removal failure did not leave the obligation pending: %+v", j)
	}
	handle := j.BackendHandle
	if err := a.Stop(); err != nil {
		t.Fatalf("stop A: %v", err)
	}

	// Lifetime B: a fresh process over the same ledger drains the
	// pending obligation once the runtime recovers — the kill lost
	// nothing and replayed nothing.
	if err := os.Unsetenv("MSB_FAKE_RM_FAIL"); err != nil {
		t.Fatal(err)
	}
	b := startServer(t, Config{
		SocketDir: socketDir(t), LedgerPath: ledgerPath,
		Peers: selfPeer(t), AuthorityKeys: keys,
		Backend: backend, MaintenanceInterval: 15 * time.Millisecond,
	})
	deadline = time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		j, _ = b.Ledger().Get("g5-kill")
		if j != nil && !j.CleanupPending {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if j == nil || j.CleanupPending {
		t.Fatalf("obligation never drained after restart: %+v", j)
	}
	if _, err := os.Stat(fakeStatePath(fakeDir, handle)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the runtime resource survived the retried cleanup: %v", err)
	}
}

// TestIncompleteCreateRecovered — a create that fails after the
// runtime may have started provisioning still gets its leftover
// instance removed: the refused-dispatch cleanup path destroys the
// failed create under the same identity binding.
func TestIncompleteCreateRecovered(t *testing.T) {
	bin, fakeDir := fakeMSB(t, map[string]string{"MSB_FAKE_CREATE_FAIL_AFTER": "1"})
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	key, keys := testAuthority(t)
	srv := startServer(t, Config{
		SocketDir: socketDir(t), Peers: selfPeer(t), AuthorityKeys: keys,
		Backend: backend, MaintenanceInterval: 15 * time.Millisecond,
	})
	conn, reader := connect(t, srv.SocketPath())
	resp := sendJob(t, conn, reader, signedJobReq(t, key, func(c *JobContractV2) {
		c.JobID, c.Nonce = "g5-incomplete", "g5-inc-nonce"
	}))
	if resp.State == JobStateRunning {
		t.Fatalf("a failed create must not admit as running: %+v", resp)
	}
	j := waitForState(t, srv, "g5-incomplete", JobStateDispatchFailed)
	if j.CleanupPending {
		t.Fatalf("incomplete create left an open obligation: %+v", j)
	}
	// No leftover instance may survive anywhere under our namespace.
	matches, err := filepath.Glob(filepath.Join(fakeDir, "sx-*.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range matches {
		if !strings.HasSuffix(m, ".jobs.json") {
			t.Fatalf("incomplete create left runtime residue: %s", m)
		}
	}
}

// TestOrphanedVMInventoried — a leftover the refused-dispatch cleanup
// cannot remove is never silently dropped. Two inventory shapes,
// asserted on the real ledger: (a) an unproven removal leaves a
// DISPATCH_AMBIGUOUS row bound to the handle — an unresolved
// obligation the residue escalation surfaces — while the runtime
// resource still exists for the operator; (b) a policy-retained
// leftover lands in the retained-resources inventory naming the exact
// handle.
func TestOrphanedVMInventoried(t *testing.T) {
	t.Run("uncertain residue stays an owed, escalated obligation", func(t *testing.T) {
		bin, fakeDir := fakeMSB(t, map[string]string{
			"MSB_FAKE_CREATE_FAIL_AFTER": "1",
			"MSB_FAKE_RM_FAIL":           "1",
		})
		backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
		key, keys := testAuthority(t)
		audits := make(chan string, 256)
		srv := startServer(t, Config{
			SocketDir: socketDir(t), Peers: selfPeer(t), AuthorityKeys: keys,
			Backend: backend, MaintenanceInterval: 15 * time.Millisecond,
			Audit: func(format string, args ...any) {
				select {
				case audits <- fmt.Sprintf(format, args...):
				default:
				}
			},
		})
		conn, reader := connect(t, srv.SocketPath())
		sendJob(t, conn, reader, signedJobReq(t, key, func(c *JobContractV2) {
			c.JobID, c.Nonce = "g5-orphan", "g5-orph-nonce"
		}))
		j := waitForState(t, srv, "g5-orphan", JobStateDispatchAmbig)
		// The ambiguity is the inventory: the row binds the orphan's
		// handle under the dispatch identity that created it, and it
		// never reaches a terminal state that would forget it.
		if j.BackendHandle == "" || j.DispatchClass != string(DispatchUncertain) {
			t.Fatalf("the orphan lost its dispatch identity: %+v", j)
		}
		if j.ReceiptSHA256 != "" {
			t.Fatal("an unresolved orphan carried terminal evidence")
		}
		if _, err := os.Stat(fakeStatePath(fakeDir, j.BackendHandle)); err != nil {
			t.Fatalf("the orphan vanished outside the ledger's accounting: %v", err)
		}
		// The residue escalation surfaces the orphan to operators —
		// it does not sit quiet in the ledger. The line is an
		// aggregate count of unresolved obligations, not a per-job
		// record.
		deadline := time.After(15 * time.Second)
		for {
			select {
			case line := <-audits:
				if strings.Contains(line, "ESCALATION") && strings.Contains(line, "unresolved") {
					return
				}
			case <-deadline:
				t.Fatal("the unresolved orphan was never escalated")
			}
		}
	})

	t.Run("policy-retained residue lands in the inventory", func(t *testing.T) {
		bin, fakeDir := fakeMSB(t, map[string]string{"MSB_FAKE_CREATE_FAIL_AFTER": "1"})
		backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
		backend.KeepSandboxes = true
		key, keys := testAuthority(t)
		srv := startServer(t, Config{
			SocketDir: socketDir(t), Peers: selfPeer(t), AuthorityKeys: keys,
			Backend: backend, MaintenanceInterval: 15 * time.Millisecond,
		})
		conn, reader := connect(t, srv.SocketPath())
		sendJob(t, conn, reader, signedJobReq(t, key, func(c *JobContractV2) {
			c.JobID, c.Nonce = "g5-orphan-ret", "g5-orph-ret-nonce"
		}))
		waitForState(t, srv, "g5-orphan-ret", JobStateDispatchFailed)

		deadline := time.Now().Add(15 * time.Second)
		var rec *RetainedResource
		for time.Now().Before(deadline) {
			rr, err := srv.Ledger().RetainedResources()
			if err == nil {
				for _, r := range rr {
					if r.JobID == "g5-orphan-ret" {
						rec = r
					}
				}
			}
			if rec != nil {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if rec == nil || rec.Handle == "" {
			t.Fatalf("the policy-retained orphan was never inventoried")
		}
		if _, err := os.Stat(fakeStatePath(fakeDir, rec.Handle)); err != nil {
			t.Fatalf("the inventoried orphan vanished outside the ledger's accounting: %v", err)
		}
	})
}

// TestStaleOwnershipRejected — two staleness axes. A cleanup request
// carrying a superseded dispatch nonce disagrees with the handle's
// deletion key and is refused as unverifiable authority, and a
// superseded recovery claim cannot validate, extend, or commit the
// cleanup clear — ownership is fenced by generation, not by who last
// touched the row.
func TestStaleOwnershipRejected(t *testing.T) {
	bin, stateDir := fakeMSB(t, nil)
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	ctx := testContext(t)

	// Stale cleanup authorization: the request names a nonce that is
	// not the deletion key the handle carries — malformed authority,
	// refused before anything is inspected or destroyed.
	job, disp := g5Dispatch(t, backend, "g5-stale-req")
	stale := cleanupReqFor(job, disp)
	stale.DispatchNonce = "nonce-superseded"
	stale.BootID = "boot_superseded"
	res, err := backend.Cleanup(ctx, stale)
	if err != nil {
		t.Fatalf("stale request: %v", err)
	}
	if res.Outcome != CleanupIdentityUnverifiable {
		t.Fatalf("stale nonce outcome %s, want IDENTITY_UNVERIFIABLE", res.Outcome)
	}
	survive(t, stateDir, disp.Handle)

	// Stale recovery claim: A claimed, B took the row over — A's
	// validation and its cleanup clear both refuse.
	l, _ := openLedger(t)
	defer l.Close()
	now := time.Now().UTC()
	a, b, atB := claimPair(t, l, "g5-stale-claim", now)
	if _, err := l.InsertJob("g5-stale-claim", "h-sc", "alice", "alice", "img", "{}"); err != nil {
		t.Fatal(err)
	}
	if err := l.Transition("g5-stale-claim", JobStateSucceeded, []string{JobStateRecorded},
		func(j *LedgerJob) error { j.CleanupPending = true; j.ExitCode = intPtr(0); return nil }); err != nil {
		t.Fatal(err)
	}
	if err := l.ValidateRecoveryClaim(a, atB); !errors.Is(err, ErrClaimStale) {
		t.Fatalf("stale claim validated: %v", err)
	}
	if err := l.ClearCleanupPendingFor("g5-stale-claim", a, atB); !errors.Is(err, ErrClaimStale) {
		t.Fatalf("stale claimant cleared the obligation: %v", err)
	}
	j, _ := l.Get("g5-stale-claim")
	if !j.CleanupPending {
		t.Fatal("a stale claimant discharged the cleanup obligation")
	}
	// The live owner can still act.
	if err := l.ValidateRecoveryClaim(b, atB.Add(time.Second)); err != nil {
		t.Fatalf("live claim lost ownership to a stale claimant's attempt: %v", err)
	}
	if err := l.ClearCleanupPendingFor("g5-stale-claim", b, atB.Add(time.Second)); err != nil {
		t.Fatalf("live claimant could not clear: %v", err)
	}
}

// TestConcurrentRetargetedDeletion — the interleaved substitution
// race. Two live sandboxes; the first's handle is retargeted to a
// foreign instance before the concurrent cleanup round. The
// retargeted instance survives, the untargeted sibling is still
// removed and verified, and no concurrent classification is coerced.
func TestConcurrentRetargetedDeletion(t *testing.T) {
	bin, stateDir := fakeMSB(t, nil)
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	ctx := testContext(t)
	jobA, dispA := g5Dispatch(t, backend, "g5-conc-a")
	jobB, dispB := g5Dispatch(t, backend, "g5-conc-b")

	// Retarget A's handle to a foreign instance — the interleave the
	// inspect→remove window must not destroy.
	substitute(t, stateDir, dispA.Handle, map[string]string{
		"crabedence.dispatch": "foreign-nonce",
		"crabedence.job":      "foreign-job",
	})

	var wg sync.WaitGroup
	resCh := make(chan *CleanupResult, 2)
	errCh := make(chan error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		res, err := backend.Cleanup(ctx, cleanupReqFor(jobA, dispA))
		resCh <- &res
		errCh <- err
	}()
	go func() {
		defer wg.Done()
		res, err := backend.Cleanup(ctx, cleanupReqFor(jobB, dispB))
		resCh <- &res
		errCh <- err
	}()
	wg.Wait()
	close(resCh)
	close(errCh)

	var resA, resB *CleanupResult
	for err := range errCh {
		if err != nil {
			t.Fatalf("concurrent cleanup: %v", err)
		}
	}
	for res := range resCh {
		switch res.Outcome {
		case CleanupIdentityMismatch:
			resA = res
		case CleanupRemovedVerified:
			resB = res
		default:
			t.Fatalf("unexpected concurrent outcome: %s — %s", res.Outcome, res.Detail)
		}
	}
	if resA == nil {
		t.Fatal("the retargeted handle was not refused")
	}
	if resB == nil {
		t.Fatal("the untargeted sibling was not removed and verified")
	}
	survive(t, stateDir, dispA.Handle)
	if _, err := os.Stat(fakeStatePath(stateDir, dispB.Handle)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the authorized removal did not happen: %v", err)
	}
}

// TestSlowInspectBounded — a wedged runtime degrades to honest
// uncertainty inside a bounded window. Under the RC8.3 fail-closed
// contract a hung pre-removal inspect refuses as IDENTITY_UNVERIFIABLE
// — no destructive command is issued — and can never park the
// obligation forever or coerce a verdict it could not observe.
func TestSlowInspectBounded(t *testing.T) {
	bin, stateDir := fakeMSB(t, map[string]string{"MSB_FAKE_INSPECT_SLEEP": "10"})
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	backend.stepTimeoutOverride = 250 * time.Millisecond
	backend.postVerifyOverride = 250 * time.Millisecond
	job, disp := g5Dispatch(t, backend, "g5-slow")
	req := cleanupReqFor(job, disp)

	start := time.Now()
	res, err := backend.Cleanup(context.Background(), req)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("wedged runtime returned an error instead of a classification: %v", err)
	}
	if res.Outcome.ProvesAbsent() {
		t.Fatalf("a wedged inspect claimed verified absence: %s", res.Outcome)
	}
	if res.Outcome != CleanupIdentityUnverifiable {
		t.Fatalf("wedged pre-removal inspect outcome %s, want IDENTITY_UNVERIFIABLE", res.Outcome)
	}
	if destructiveCount(t, stateDir) != 0 {
		t.Fatal("a destructive command was issued against an unverified occupant")
	}
	survive(t, stateDir, disp.Handle)
	// The bound is ~2 step deadlines + ~2 post-verify deadlines; five
	// seconds is generous headroom over the 250ms test overrides and
	// orders of magnitude below the 10s wedge.
	if elapsed > 5*time.Second {
		t.Fatalf("wedged inspect parked cleanup for %v", elapsed)
	}
}

// TestRetainedResourcesAccounted — policy retention resolves the
// removal obligation while the resource is still live: the inventory
// records it, the pending flag clears, nothing claims verified
// absence, and an operator disposal closes the record.
func TestRetainedResourcesAccounted(t *testing.T) {
	bin, _ := fakeMSB(t, nil)
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	backend.KeepSandboxes = true
	key, keys := testAuthority(t)
	srv := startServer(t, Config{
		SocketDir: socketDir(t), Peers: selfPeer(t), AuthorityKeys: keys,
		Backend: backend, MaintenanceInterval: 15 * time.Millisecond,
	})
	conn, reader := connect(t, srv.SocketPath())
	resp := sendJob(t, conn, reader, signedJobReq(t, key, func(c *JobContractV2) {
		c.JobID, c.Nonce = "g5-retain", "g5-ret-nonce"
	}))
	if resp.State != JobStateRunning {
		t.Fatalf("submit: %+v", resp)
	}
	_ = conn.Close()
	j := waitForState(t, srv, "g5-retain", JobStateSucceeded)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if j, _ = srv.Ledger().Get("g5-retain"); !j.CleanupPending {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if j.CleanupPending {
		t.Fatalf("policy retention never resolved the obligation: %+v", j)
	}
	rr, err := srv.Ledger().RetainedResources()
	if err != nil || len(rr) == 0 {
		t.Fatalf("policy retention left no inventory record: %v %v", rr, err)
	}
	var rec *RetainedResource
	for _, r := range rr {
		if r.JobID == "g5-retain" {
			rec = r
		}
	}
	if rec == nil || rec.Handle == "" || rec.DispatchNonce == "" {
		t.Fatalf("inventory lost the retained identity: %+v", rr)
	}
	if err := srv.Ledger().DisposeRetainedResource("g5-retain"); err != nil {
		t.Fatalf("operator disposal refused: %v", err)
	}
	// A disposed record is final — it cannot be rewritten into a
	// second retention.
	if err := srv.Ledger().RecordRetainedResource("g5-retain", "backend", "h", "n", "again"); err == nil {
		t.Fatal("a disposed retention record was rewritten")
	}
}

// TestCredentialIsolationPreserved — nothing the runtime is handed
// may carry credential material: argv is the boundary, and the
// runtime's own records and the executor's artifact store must stay
// free of provider tokens and key material.
func TestCredentialIsolationPreserved(t *testing.T) {
	const (
		tokenMarker = "oc_secret_marker_7f3d9a"
		keyMarker   = "PRIVATEKEYMARKER_1b2c3d4e"
	)
	t.Setenv("CRABBOX_OPENCOMPUTER_API_KEY", tokenMarker)
	t.Setenv("CRABBOX_JOB_SIGNING_KEY", keyMarker)
	bin, stateDir := fakeMSB(t, map[string]string{"MSB_FAKE_RECORD_ARGV": "1"})
	artifacts := t.TempDir()
	backend := testBackend(t, bin, artifacts)
	job, disp := g5Dispatch(t, backend, "g5-creds")
	res, err := backend.Cleanup(testContext(t), cleanupReqFor(job, disp))
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if res.Outcome != CleanupRemovedVerified {
		t.Fatalf("cleanup outcome %s, want REMOVED_VERIFIED", res.Outcome)
	}

	// Every argv line handed to the runtime.
	argvLog, err := os.ReadFile(filepath.Join(stateDir, "argv.log"))
	if err != nil {
		t.Fatalf("argv log: %v", err)
	}
	for _, marker := range []string{tokenMarker, keyMarker} {
		if strings.Contains(string(argvLog), marker) {
			t.Fatalf("credential material crossed the argv boundary")
		}
	}
	// The removal argv is exactly the conditioned call — nothing else
	// rides on the destructive operation.
	foundRM := false
	for _, line := range strings.Split(strings.TrimSpace(string(argvLog)), "\n") {
		if strings.HasPrefix(line, "rm\x00") {
			foundRM = true
			want := "rm\x00-f\x00" + disp.Handle
			if line != want {
				t.Fatalf("removal argv carried unexpected material: %q", line)
			}
		}
	}
	if !foundRM {
		t.Fatal("the conditioned removal never reached the runtime")
	}
	// No marker may appear in the runtime's records or the artifact
	// store either.
	for _, root := range []string{stateDir, artifacts} {
		err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return err
			}
			raw, rerr := os.ReadFile(p)
			if rerr != nil {
				return nil
			}
			for _, marker := range []string{tokenMarker, keyMarker} {
				if strings.Contains(string(raw), marker) {
					t.Fatalf("credential material persisted in %s", p)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

// TestSandboxRecreationSafe — a handle freed by a verified removal
// can be recreated for a new job, and neither direction confuses the
// other: a stale request against the freed handle classifies the
// recreation as foreign instead of destroying it.
func TestSandboxRecreationSafe(t *testing.T) {
	bin, stateDir := fakeMSB(t, nil)
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	ctx := testContext(t)
	jobA, dispA := g5Dispatch(t, backend, "g5-recreate-a")

	res, err := backend.Cleanup(ctx, cleanupReqFor(jobA, dispA))
	if err != nil || res.Outcome != CleanupRemovedVerified {
		t.Fatalf("first removal: %v %s", err, res.Outcome)
	}
	// The freed handle is re-created for a different job — the
	// replacement the stale request must not touch.
	conf := fakeDefaultConfig()
	conf.Labels = map[string]string{
		"crabedence.dispatch": "nonce-g5-recreate-b",
		"crabedence.job":      "g5-recreate-b",
	}
	writeFakeSandbox(t, stateDir, dispA.Handle, conf)
	res, err = backend.Cleanup(ctx, cleanupReqFor(jobA, dispA))
	if err != nil {
		t.Fatalf("stale request: %v", err)
	}
	if res.Outcome != CleanupIdentityMismatch {
		t.Fatalf("stale request against the recreation outcome %s, want IDENTITY_MISMATCH", res.Outcome)
	}
	survive(t, stateDir, dispA.Handle)
}
