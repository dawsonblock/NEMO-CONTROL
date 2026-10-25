package witness

// F-02/F-03 — durable custody obligations, explicit custody states,
// and verified startup readiness. Every assertion runs the real
// outbox, the real sender, and the real witness service — a "fake"
// here is a second real signer or ledger, never a stub verification.

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openclaw/crabbox/internal/evidence"
)

// outboxPath is the harness outbox's durable location.
func (h *harness) outboxPath() string { return filepath.Join(h.dir, "outbox.db") }

// waitSocket blocks until the witness socket exists.
func waitSocket(t *testing.T, sock string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(sock); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("witness socket did not appear")
}

// rewriteAck overwrites the stored acknowledgement JSON for a
// delivered row — the test-only corruption path that simulates a
// durable ack that no longer matches the witness's record.
func (h *harness) rewriteAck(t *testing.T, seq int64, mutate func(*Ack)) {
	t.Helper()
	var raw string
	if err := h.outbox.db.QueryRowContext(context.Background(),
		`SELECT ack FROM custody_outbox WHERE seq=$1`, seq).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var ack Ack
	if err := json.Unmarshal([]byte(raw), &ack); err != nil {
		t.Fatal(err)
	}
	mutate(&ack)
	out, err := json.Marshal(ack)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.outbox.db.ExecContext(context.Background(),
		`UPDATE custody_outbox SET ack=$1 WHERE seq=$2`, string(out), seq); err != nil {
		t.Fatal(err)
	}
}

// TestCustodyStartupUnverifiedNeverHealthy: a fresh sender holds no
// verified evidence of custody — its state is UNVERIFIED_STARTUP and
// the health check is false even while the witness is perfectly
// reachable. Health is earned by a completed verified drain, never
// assumed from the absence of observed failure (F-03).
func TestCustodyStartupUnverifiedNeverHealthy(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()

	if got := h.sender.CustodyState(context.Background()); got != "UNVERIFIED_STARTUP" {
		t.Fatalf("fresh sender state = %s, want UNVERIFIED_STARTUP", got)
	}
	if h.sender.CustodyHealthy(context.Background()) {
		t.Fatal("unverified startup must not read as healthy custody")
	}
	if !h.drain() {
		t.Fatalf("first drain failed: %s", h.sender.LastError())
	}
	if got := h.sender.CustodyState(context.Background()); got != "HEALTHY" {
		t.Fatalf("post-drain state = %s, want HEALTHY", got)
	}
}

// TestCustodyWitnessOfflineStartupNeverHealthy: a witness that is
// unreachable at startup produces no optimistic health — the sender
// stays unverified regardless of how many times it retries.
func TestCustodyWitnessOfflineStartupNeverHealthy(t *testing.T) {
	h := newHarness(t, false) // witness never serves
	defer h.outbox.Close()

	for i := 0; i < 3; i++ {
		if h.drain() {
			t.Fatal("drain succeeded while the witness was offline")
		}
		got := h.sender.CustodyState(context.Background())
		if got == "HEALTHY" {
			t.Fatal("offline witness produced healthy custody")
		}
	}
}

// TestCustodyInvalidCheckpointRejected: a witness whose checkpoint
// fails custodian-trust verification never advances readiness — the
// sender stays unverified even though transport succeeded.
func TestCustodyInvalidCheckpointRejected(t *testing.T) {
	h := newHarness(t, false)
	defer h.outbox.Close()
	// The service signs checkpoints with a key the kernel-side
	// custodian trust does not pin: every checkpoint fails
	// verification at the sender boundary.
	foreign, err := evidence.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(h.ledger, foreign, h.dep, h.ktrust, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = svc.Serve(ctx, h.socket) }()
	waitSocket(t, h.socket)

	if h.drain() {
		t.Fatal("drain succeeded against a checkpoint the trust set does not pin")
	}
	if got := h.sender.CustodyState(context.Background()); got != "UNVERIFIED_STARTUP" {
		t.Fatalf("state = %s, want UNVERIFIED_STARTUP — the bad signature produced no readiness", got)
	}
	if !strings.Contains(h.sender.LastError(), "checkpoint") {
		t.Fatalf("last error %q does not name the checkpoint failure", h.sender.LastError())
	}
}

// TestCustodyStaleReadinessExpires: verified readiness is bounded by
// the freshness policy — once the mark ages out the state is DEGRADED
// again until the next verified drain.
func TestCustodyStaleReadinessExpires(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	h.sender.SetFreshnessBound(60 * time.Millisecond)

	if !h.drain() {
		t.Fatalf("drain failed: %s", h.sender.LastError())
	}
	if !h.sender.CustodyHealthy(context.Background()) {
		t.Fatal("fresh verified drain must read healthy")
	}
	time.Sleep(120 * time.Millisecond)
	if got := h.sender.CustodyState(context.Background()); got != "DEGRADED" {
		t.Fatalf("stale readiness state = %s, want DEGRADED", got)
	}
	if !h.drain() {
		t.Fatalf("re-drain failed: %s", h.sender.LastError())
	}
	if got := h.sender.CustodyState(context.Background()); got != "HEALTHY" {
		t.Fatalf("re-verified state = %s, want HEALTHY", got)
	}
}

// TestCustodyDegradedMarkerSurvivesRestart: a durable degraded marker
// written before a crash is still there after the process restarts —
// an evidence-loss indicator is not process state (F-02).
func TestCustodyDegradedMarkerSurvivesRestart(t *testing.T) {
	h := newHarness(t, false)
	h.enqueue("exec-restart-1", `{"outcome":"ok"}`)

	if err := h.outbox.MarkDegraded(context.Background(), "custody enqueue exec-lost: outbox write failed"); err != nil {
		t.Fatal(err)
	}
	path := h.outboxPath()
	if err := h.outbox.Close(); err != nil {
		t.Fatal(err)
	}
	// "Restart": same durable path, new handle, new sender.
	reopened, err := OpenOutbox(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	st, err := reopened.CustodyStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.DegradedReason == "" {
		t.Fatal("degraded marker vanished across restart — evidence-loss indicators are durable")
	}
	restarted := NewSender(h.client, reopened, h.dep, h.ctrust, nil)
	if got := restarted.CustodyState(context.Background()); got != "DEGRADED" {
		t.Fatalf("restarted sender state = %s, want DEGRADED", got)
	}
}

// TestCustodyDegradedClearsOnlyOnVerifiedRepair: the degraded marker
// is discharged exclusively by the verified repair path — a drain
// that never reaches the witness leaves it standing, and clearing it
// records the repair evidence in the audit log.
func TestCustodyDegradedClearsOnlyOnVerifiedRepair(t *testing.T) {
	h := newHarness(t, false)
	defer h.outbox.Close()
	if err := h.outbox.MarkDegraded(context.Background(), "obligation enqueue failed"); err != nil {
		t.Fatal(err)
	}
	// Witness down: the drain cannot verify, the marker stands.
	if h.drain() {
		t.Fatal("drain succeeded while witness offline")
	}
	st, err := h.outbox.CustodyStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.DegradedReason == "" {
		t.Fatal("unverified drain discharged a degraded marker")
	}
	// Witness up: the verified drain discharges it with an audit trail.
	h.serve()
	defer h.cancel()
	if !h.drain() {
		t.Fatalf("verified drain failed: %s", h.sender.LastError())
	}
	st, err = h.outbox.CustodyStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.DegradedReason != "" {
		t.Fatalf("verified repair left degraded marker: %q", st.DegradedReason)
	}
	events, err := h.outbox.CustodyEvents(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	var sawRepair bool
	for _, ev := range events {
		if strings.Contains(ev, "degraded_repaired") {
			sawRepair = true
		}
	}
	if !sawRepair {
		t.Fatal("verified repair left no audit event")
	}
}

// TestCustodyRepairRequiredStickyUntilOperatorRepair: a contradiction
// marker is sticky — successful drains never clear it; only an
// explicit operator repair after a verified pass does.
func TestCustodyRepairRequiredStickyUntilOperatorRepair(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	if err := h.outbox.MarkRepairRequired(context.Background(), "custody head fork at seq 7"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if !h.drain() {
			t.Fatalf("drain failed: %s", h.sender.LastError())
		}
		if got := h.sender.CustodyState(context.Background()); got != "REPAIR_REQUIRED" {
			t.Fatalf("successful drain cleared REPAIR_REQUIRED — got %s", got)
		}
	}
	// Unauthorized repairs are refused before any pass runs.
	if err := h.sender.OperatorRepair(context.Background(), "", "no actor"); err == nil {
		t.Fatal("repair without an actor was admitted")
	}
	if err := h.sender.OperatorRepair(context.Background(), "alice", ""); err == nil {
		t.Fatal("repair without a reason was admitted")
	}
	if got := h.sender.CustodyState(context.Background()); got != "REPAIR_REQUIRED" {
		t.Fatalf("unauthorized repair cleared the marker — got %s", got)
	}
	if err := h.sender.OperatorRepair(context.Background(), "alice", "operator confirmed fork resolved: witness restored"); err != nil {
		t.Fatalf("operator repair: %v", err)
	}
	if got := h.sender.CustodyState(context.Background()); got != "HEALTHY" {
		t.Fatalf("post-repair state = %s, want HEALTHY", got)
	}
}

// TestCustodyFailedProbeImmediatelyDegrades: a failed drain after a
// fresh success invalidates readiness at once — a millisecond-old
// verified pass can never mask the current failure, and only a new
// complete verified pass restores HEALTHY.
func TestCustodyFailedProbeImmediatelyDegrades(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	if !h.drain() {
		t.Fatalf("drain failed: %s", h.sender.LastError())
	}
	if got := h.sender.CustodyState(context.Background()); got != "HEALTHY" {
		t.Fatalf("state after verified drain = %s, want HEALTHY", got)
	}
	h.cancel() // witness down — the next pass cannot reach it
	if h.drain() {
		t.Fatal("drain succeeded against a dead witness")
	}
	if got := h.sender.CustodyState(context.Background()); got != "DEGRADED" {
		t.Fatalf("a fresh failure was masked by a prior success: state = %s, want DEGRADED", got)
	}
	// Recovery is only a new complete verified pass.
	h.serve()
	defer h.cancel()
	if !h.drain() {
		t.Fatalf("recovery drain failed: %s", h.sender.LastError())
	}
	if got := h.sender.CustodyState(context.Background()); got != "HEALTHY" {
		t.Fatalf("post-recovery state = %s, want HEALTHY", got)
	}
}

// TestCustodyConflictingAckEscalates: a stored acknowledgement that
// differs from the one the witness returns for the same envelope is a
// fork — escalated to REPAIR_REQUIRED, never overwritten. The resend
// window reaches the row when the witness restores to an empty
// ledger: the resubmitted envelope earns the same ack the witness
// originally minted, and the corrupted recorded ack contradicts it.
func TestCustodyConflictingAckEscalates(t *testing.T) {
	h := newHarness(t, true)
	seq := h.enqueue("exec-ack-fork", `{"a":1}`)
	if !h.drain() {
		t.Fatalf("drain failed: %s", h.sender.LastError())
	}
	h.cancel() // original witness down
	// Restore the witness from an empty ledger — the resubmission
	// path re-issues the ack for the same envelope.
	restored, err := OpenLedger(filepath.Join(h.dir, "restored", "witness.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	svc2 := NewService(restored, h.wsigner, h.dep, h.ktrust, nil)
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	for i := 0; i < 20; i++ {
		if err := os.Remove(h.socket); err == nil || os.IsNotExist(err) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	go func() { _ = svc2.Serve(ctx2, h.socket) }()
	waitSocket(t, h.socket)
	// Corrupt the stored ack signature — the resubmitted envelope's
	// ack now contradicts the recorded one.
	h.rewriteAck(t, seq, func(ack *Ack) {
		ack.Signature = "01" + ack.Signature[2:]
	})
	if h.drain() {
		t.Fatal("drain succeeded against a conflicting recorded ack")
	}
	if got := h.sender.CustodyState(context.Background()); got != "REPAIR_REQUIRED" {
		t.Fatalf("state = %s, want REPAIR_REQUIRED", got)
	}
}

// TestCustodyContradictoryHeadEscalates: an outbox that forks from
// the witness's claimed custody head escalates to REPAIR_REQUIRED —
// the two stores diverged and neither is silently overwritten.
func TestCustodyContradictoryHeadEscalates(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	h.enqueue("exec-1", `{"v":1}`)
	if !h.drain() {
		t.Fatalf("drain failed: %s", h.sender.LastError())
	}
	// A second outbox on the same deployment whose seq-1 chain-link
	// differs — e.g. an outbox restored from a divergent backup.
	other, err := OpenOutbox(filepath.Join(h.dir, "other", "outbox.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if _, err := other.Enqueue(context.Background(), h.prod, "exec-1", "digest-exec-1", []byte(`{"v":2}`)); err != nil {
		t.Fatal(err)
	}
	forked := NewSender(h.client, other, h.dep, h.ctrust, nil)
	if forked.drain(context.Background()) {
		t.Fatal("drain succeeded on a forked custody stream")
	}
	if got := forked.CustodyState(context.Background()); got != "REPAIR_REQUIRED" {
		t.Fatalf("forked outbox state = %s, want REPAIR_REQUIRED", got)
	}
}

// TestCustodyEmptyPayloadRefused: an obligation with no receipt bytes
// can never be verifiable — the outbox refuses it as an evidence
// fault rather than minting an empty envelope.
func TestCustodyEmptyPayloadRefused(t *testing.T) {
	h := newHarness(t, false)
	defer h.outbox.Close()
	if _, err := h.outbox.Enqueue(context.Background(), h.prod, "exec-empty", "digest", nil); !errors.Is(err, ErrEvidenceContradiction) {
		t.Fatalf("empty payload enqueue = %v, want ErrEvidenceContradiction", err)
	}
	if _, err := h.outbox.Enqueue(context.Background(), h.prod, "exec-empty", "digest", []byte{}); !errors.Is(err, ErrEvidenceContradiction) {
		t.Fatalf("zero-length payload enqueue = %v, want ErrEvidenceContradiction", err)
	}
}

// TestCustodyObligationIdempotentEnqueue: re-enqueueing the same
// execution with identical receipt bytes returns the same durable
// sequence; different bytes are a contradiction, never an overwrite.
func TestCustodyObligationIdempotentEnqueue(t *testing.T) {
	h := newHarness(t, false)
	defer h.outbox.Close()
	s1, err := h.outbox.Enqueue(context.Background(), h.prod, "exec-dup", "d1", []byte("payload-A"))
	if err != nil {
		t.Fatal(err)
	}
	s2, err := h.outbox.Enqueue(context.Background(), h.prod, "exec-dup", "d1", []byte("payload-A"))
	if err != nil {
		t.Fatal(err)
	}
	if s1 != s2 {
		t.Fatalf("idempotent enqueue returned seq %d then %d", s1, s2)
	}
	if _, err := h.outbox.Enqueue(context.Background(), h.prod, "exec-dup", "d1", []byte("payload-B")); !errors.Is(err, ErrEvidenceContradiction) {
		t.Fatalf("conflicting re-enqueue = %v, want ErrEvidenceContradiction", err)
	}
	// The original bytes survived — never overwritten.
	row := h.row(t, s1)
	content, err := row.Envelope.ContentBytes()
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "payload-A" {
		t.Fatalf("conflicting enqueue overwrote the recorded obligation: %q", content)
	}
}

// TestCustodyObligationHighWaterMonotonic: the high-water mark moves
// only forward and is durable across restart.
func TestCustodyObligationHighWaterMonotonic(t *testing.T) {
	h := newHarness(t, false)
	defer h.outbox.Close()
	ctx := context.Background()
	if hw, err := h.outbox.ObligationHighWater(ctx); err != nil || hw != 0 {
		t.Fatalf("initial hwm = %d/%v, want 0", hw, err)
	}
	if err := h.outbox.AdvanceObligationHWM(ctx, 42); err != nil {
		t.Fatal(err)
	}
	if err := h.outbox.AdvanceObligationHWM(ctx, 10); err != nil {
		t.Fatal(err)
	}
	if hw, _ := h.outbox.ObligationHighWater(ctx); hw != 42 {
		t.Fatalf("regressed hwm = %d, want 42", hw)
	}
	path := h.outboxPath()
	h.outbox.Close()
	reopened, err := OpenOutbox(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if hw, _ := reopened.ObligationHighWater(ctx); hw != 42 {
		t.Fatalf("hwm after restart = %d, want 42", hw)
	}
}

// TestCustodyColdRestartUnackedReceipts: a cold restart holding
// obligations the witness never acknowledged is UNVERIFIED until the
// drain re-verifies and delivers — never optimistically healthy.
func TestCustodyColdRestartUnackedReceipts(t *testing.T) {
	h := newHarness(t, false)
	h.enqueue("exec-cold-1", `{"cold":true}`)
	h.enqueue("exec-cold-2", `{"cold":2}`)
	// Restart: fresh sender over the same durable outbox, witness down.
	path := h.outboxPath()
	h.outbox.Close()
	reopened, err := OpenOutbox(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	restarted := NewSender(h.client, reopened, h.dep, h.ctrust, nil)
	if got := restarted.CustodyState(context.Background()); got != "UNVERIFIED_STARTUP" {
		t.Fatalf("cold-restart state = %s, want UNVERIFIED_STARTUP", got)
	}
	if n, _ := reopened.Undelivered(context.Background()); n != 2 {
		t.Fatalf("undelivered = %d, want 2", n)
	}
	// Witness arrives: the backlog drains, readiness is earned.
	h.serve()
	defer h.cancel()
	if !restarted.drain(context.Background()) {
		t.Fatalf("restart drain failed: %s", restarted.LastError())
	}
	if got := restarted.CustodyState(context.Background()); got != "HEALTHY" {
		t.Fatalf("post-reconcile state = %s, want HEALTHY", got)
	}
	if h.records() != 2 {
		t.Fatalf("witness records = %d, want 2", h.records())
	}
}
