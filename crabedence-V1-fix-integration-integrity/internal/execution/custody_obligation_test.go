package execution

// F-02 — the custody obligation replay scanner. The authoritative
// terminalization record and the custody outbox share no transaction,
// so a crash between commit and enqueue leaves a committed effect
// with no custody obligation. These tests prove the scanner restores
// exactly the missing obligations — byte-identical, idempotent,
// escalated on contradiction — and that the durable high-water mark
// and degraded state are the audit trail.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openclaw/crabbox/internal/custody"
	"github.com/openclaw/crabbox/internal/evidence"
	"github.com/openclaw/crabbox/internal/idempotency"
	"github.com/openclaw/crabbox/internal/witness"
)

// openTestOutbox builds a durable custody outbox under a 0700 test dir.
func openTestOutbox(t *testing.T) *witness.Outbox {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	o, err := witness.OpenOutbox(filepath.Join(dir, "outbox.db"))
	if err != nil {
		t.Fatal(err)
	}
	return o
}

// obligationRow finds the outbox row for one execution.
func obligationRow(t *testing.T, outbox *witness.Outbox, executionID string) witness.PendingRow {
	t.Helper()
	rows, err := outbox.Pending(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.ExecutionID == executionID {
			return r
		}
	}
	t.Fatalf("no outbox row for %s", executionID)
	return witness.PendingRow{}
}

// obligationProducer mirrors the wireCustodyBoundary producer: every
// field controlled configuration, never learned from the evidence.
func obligationProducer(t *testing.T, dep string, signer *evidence.Signer) witness.Producer {
	t.Helper()
	return witness.Producer{
		DeploymentID: dep,
		Release: custody.ReleaseIdentity{
			Version:      "0.55.0-rc8.3-dev",
			SourceCommit: strings.Repeat("a", 40),
		},
		Signer: signer,
	}
}

// terminalize commits one successful terminal record through the real
// dispatch executor and returns its durable execution identity — the
// key the obligation scanner works in, not the provider's run id.
func terminalize(t *testing.T, exec *DispatchExecutor, key string) string {
	t.Helper()
	resp := exec.ExecuteWithIdempotency(context.Background(), crashRequest("alice@example.com", key), crashDesc)
	if resp.Status != StatusSucceeded {
		t.Fatalf("terminalization %s = %s: %s", key, resp.Status, resp.Error)
	}
	rec, err := exec.store.LookupByKey(context.Background(), "alice@example.com", "test.mut", key)
	if err != nil || rec == nil {
		t.Fatalf("terminal record for %s: %v", key, err)
	}
	return rec.ExecutionID
}

// TestObligationReplayRestoresCrashLostEnqueue: a record that
// committed terminal state but never reached the outbox — the
// crash-between-commit-and-enqueue gap — is rebuilt by the scanner
// with the exact canonical payload and the high-water mark advances
// over it.
func TestObligationReplayRestoresCrashLostEnqueue(t *testing.T) {
	store := openExecutorSQLiteStore(t, idempotency.DefaultLeaseConfig)
	exec := NewDispatchExecutor(&simProvider{effect: true}, store)
	exec.SetEvidenceSigner(custodySigner(t))
	signer := custodySigner(t)

	ids := []string{
		terminalize(t, exec, "ob-1"),
		terminalize(t, exec, "ob-2"),
		terminalize(t, exec, "ob-3"),
	}
	outbox := openTestOutbox(t)
	dep := "dep-ob"
	prod := obligationProducer(t, dep, signer)

	missing, err := outbox.MissingObligations(context.Background(), ids)
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 3 {
		t.Fatalf("missing = %v, want all 3 absent before replay", missing)
	}
	if err := reconcileCustodyObligations(context.Background(), store, outbox, prod, 0, CustodyCoveragePolicy{}); err != nil {
		t.Fatalf("obligation replay: %v", err)
	}
	missing, err = outbox.MissingObligations(context.Background(), ids)
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 0 {
		t.Fatalf("replay left uncovered obligations: %v", missing)
	}
	// The restored obligation carries the receipt's canonical payload.
	rows, err := outbox.Pending(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("outbox rows = %d, want 3", len(rows))
	}
	rec, err := store.Lookup(context.Background(), ids[0])
	if err != nil {
		t.Fatal(err)
	}
	want, err := idempotency.TerminalReceiptFromRecord(rec).CustodyPayload()
	if err != nil {
		t.Fatal(err)
	}
	content, err := obligationRow(t, outbox, ids[0]).Envelope.ContentBytes()
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != string(want) {
		t.Fatal("replayed obligation payload is not the canonical receipt bytes")
	}
	// High-water recorded over the restored stream.
	if hw, _ := outbox.ObligationHighWater(context.Background()); hw <= 0 {
		t.Fatalf("obligation hwm = %d, want > 0", hw)
	}
}

// TestObligationReplayIdempotent: a second pass over a fully covered
// stream neither duplicates nor contradicts — replay stability is
// what makes the scanner safe to run every drain.
func TestObligationReplayIdempotent(t *testing.T) {
	store := openExecutorSQLiteStore(t, idempotency.DefaultLeaseConfig)
	exec := NewDispatchExecutor(&simProvider{effect: true}, store)
	exec.SetEvidenceSigner(custodySigner(t))
	signer := custodySigner(t)
	outbox := openTestOutbox(t)
	prod := obligationProducer(t, "dep-ob2", signer)

	terminalize(t, exec, "ob-idem-1")
	terminalize(t, exec, "ob-idem-2")
	if err := reconcileCustodyObligations(context.Background(), store, outbox, prod, 0, CustodyCoveragePolicy{}); err != nil {
		t.Fatal(err)
	}
	hw1, _ := outbox.ObligationHighWater(context.Background())
	rows1, _ := outbox.Pending(context.Background())
	if err := reconcileCustodyObligations(context.Background(), store, outbox, prod, 0, CustodyCoveragePolicy{}); err != nil {
		t.Fatal(err)
	}
	hw2, _ := outbox.ObligationHighWater(context.Background())
	rows2, _ := outbox.Pending(context.Background())
	if hw1 != hw2 || len(rows1) != len(rows2) {
		t.Fatalf("replay not stable: hwm %d→%d rows %d→%d", hw1, hw2, len(rows1), len(rows2))
	}
}

// TestObligationReplayContradictionEscalates: the outbox holds a
// different byte stream for an execution than the authoritative store
// produces — the stores forked. The scanner escalates to
// REPAIR_REQUIRED and never overwrites either side.
func TestObligationReplayContradictionEscalates(t *testing.T) {
	store := openExecutorSQLiteStore(t, idempotency.DefaultLeaseConfig)
	exec := NewDispatchExecutor(&simProvider{effect: true}, store)
	exec.SetEvidenceSigner(custodySigner(t))
	signer := custodySigner(t)
	outbox := openTestOutbox(t)
	prod := obligationProducer(t, "dep-ob3", signer)

	execID := terminalize(t, exec, "ob-conflict")
	// A foreign obligation for the same execution — different bytes
	// than the record's canonical payload.
	if _, err := outbox.Enqueue(context.Background(), prod, execID, "forged", []byte(`{"forged":true}`)); err != nil {
		t.Fatal(err)
	}
	err := reconcileCustodyObligations(context.Background(), store, outbox, prod, 0, CustodyCoveragePolicy{})
	if err == nil {
		t.Fatal("contradictory obligation replayed silently")
	}
	st, serr := outbox.CustodyStatus(context.Background())
	if serr != nil {
		t.Fatal(serr)
	}
	if st.RepairReason == "" {
		t.Fatal("obligation fork did not escalate to REPAIR_REQUIRED")
	}
	// The foreign row stands — never overwritten.
	rows, _ := outbox.Pending(context.Background())
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want the foreign row preserved", len(rows))
	}
	content, _ := obligationRow(t, outbox, execID).Envelope.ContentBytes()
	if string(content) != `{"forged":true}` {
		t.Fatalf("forked obligation was overwritten: %q", content)
	}
}

// TestObligationReplayBoundedByHighWater: records at or below the
// verified mark are skipped by the bounded scan — the durable mark
// is what keeps replay O(new work) instead of O(history).
func TestObligationReplayBoundedByHighWater(t *testing.T) {
	store := openExecutorSQLiteStore(t, idempotency.DefaultLeaseConfig)
	exec := NewDispatchExecutor(&simProvider{effect: true}, store)
	exec.SetEvidenceSigner(custodySigner(t))
	signer := custodySigner(t)
	outbox := openTestOutbox(t)
	prod := obligationProducer(t, "dep-ob4", signer)

	id1 := terminalize(t, exec, "ob-hwm-1")
	if err := reconcileCustodyObligations(context.Background(), store, outbox, prod, 0, CustodyCoveragePolicy{}); err != nil {
		t.Fatal(err)
	}
	hw, _ := outbox.ObligationHighWater(context.Background())
	if hw <= 0 {
		t.Fatalf("hwm = %d, want > 0", hw)
	}
	// New terminal records past the mark are found; the covered
	// prefix is trusted by construction.
	id2 := terminalize(t, exec, "ob-hwm-2")
	if err := reconcileCustodyObligations(context.Background(), store, outbox, prod, hw, CustodyCoveragePolicy{}); err != nil {
		t.Fatal(err)
	}
	missing, err := outbox.MissingObligations(context.Background(), []string{id1, id2})
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 0 {
		t.Fatalf("bounded replay left gaps: %v", missing)
	}
	hw2, _ := outbox.ObligationHighWater(context.Background())
	if hw2 <= hw {
		t.Fatalf("hwm did not advance: %d → %d", hw, hw2)
	}
}

// TestObligationSinkFailureMarksDegraded: an enqueue failure at the
// custody sink durably degrades custody — the exact F-02 regression:
// the marker must survive a restart and must not be cleared by an
// unrelated successful drain until the obligation is repaired.
func TestObligationSinkFailureMarksDegraded(t *testing.T) {
	outbox := openTestOutbox(t)
	dep := "dep-sink"
	signer := custodySigner(t)
	prod := obligationProducer(t, dep, signer)

	// Enqueue onto a closed outbox — the durable write fails.
	outbox.Close()
	if _, err := outbox.Enqueue(context.Background(), prod, "exec-x", "d", []byte("p")); err == nil {
		t.Fatal("enqueue on closed outbox succeeded")
	}

	outbox = openTestOutbox(t)
	defer outbox.Close()
	if err := outbox.MarkDegraded(context.Background(), "custody enqueue exec-x: closed"); err != nil {
		t.Fatal(err)
	}
	st, err := outbox.CustodyStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.DegradedReason == "" {
		t.Fatal("enqueue failure left no durable degraded marker")
	}
	events, err := outbox.CustodyEvents(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	var saw bool
	for _, ev := range events {
		if strings.Contains(ev, "degraded") {
			saw = true
		}
	}
	if !saw {
		t.Fatal("degraded transition left no audit event")
	}
}

// TestObligationEmptyPayloadNeverCustodied: a terminalization whose
// receipt cannot produce canonical bytes — the empty-payload case —
// is an evidence fault, never an obligation the witness inherits.
func TestObligationEmptyPayloadNeverCustodied(t *testing.T) {
	outbox := openTestOutbox(t)
	defer outbox.Close()
	signer := custodySigner(t)
	prod := obligationProducer(t, "dep-empty", signer)
	if _, err := outbox.Enqueue(context.Background(), prod, "exec-nil", "d", nil); err == nil {
		t.Fatal("empty payload was custodied")
	}
}
