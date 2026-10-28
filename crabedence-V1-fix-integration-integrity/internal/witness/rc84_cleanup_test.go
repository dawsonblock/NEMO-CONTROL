package witness

// RC8.4 cleanup — the orderings the review found unenforced. Each test
// below reproduces a defect that the branch's own release notes claimed
// was closed, against the shipped protocol rather than a synthetic
// state.

import (
	"context"
	"errors"
	"testing"
	"time"
)

// A kernel that crashes between the witness admitting a permit and the
// local admission row exists leaves a witness-only transaction. The
// documented recovery for it is an abort, and it must not require a
// local permit that was never written.
func TestRC84RecoveryAbortsPrepareOnlyCrash(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	insertLegacyRow(t, h, 1, "prepare-only", "")

	authority, trust := testRepairAuthority(t, h.dep)
	auth := testAuth(t, h.outbox, authority, trust, h.dep, OperationMigrate)
	fc, err := h.fenceClient(auth)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	fence, err := fc.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	// Admit at the witness only: the crash window AdmitMigration
	// describes.
	permit, err := fc.Prepare(ctx, fence, 1, "preimage-digest")
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}

	plan, err := PlanRecovery(ctx, h.outbox, h.client, h.dep, fence.FenceID)
	if err != nil {
		t.Fatalf("plan recovery: %v", err)
	}
	if plan.Quarantined || plan.Action != RecoveryAbort {
		t.Fatalf("plan = %+v, want an unquarantined ABORT", plan)
	}
	if plan.HasLocalTx {
		t.Fatal("plan claims a local transaction this outbox never wrote")
	}
	if plan.TxID != permit.TxID {
		t.Fatalf("plan resolves %s, the witness admitted %s", plan.TxID, permit.TxID)
	}
	grant := testRecoveryGrant(t, authority, plan, RecoveryAbort)
	if _, err := ExecuteRecovery(ctx, h.outbox, recoveryClient(h, plan.GrantDigest), trust, grant, plan, time.Now()); err != nil {
		t.Fatalf("recovery of a prepare-only crash failed: %v", err)
	}

	active, err := h.ledger.ActiveFence(ctx, h.dep)
	if err != nil {
		t.Fatal(err)
	}
	if active != nil {
		t.Fatalf("recovery abort did not release the epoch: %+v", active)
	}
	// A resumed kernel must not be able to redeem the aborted admission.
	if _, err := fc.Prepare(ctx, fence, 1, "preimage-digest"); err == nil {
		t.Fatal("a resumed kernel re-admitted a transaction recovery had aborted")
	}
}

// One epoch covers N targets. Aborting the second transaction must not
// release the epoch while the first has a committed local rewrite:
// AbortFence already refuses that, and the per-transaction path has to
// agree with it.
func TestRC84AbortMigrationRefusedOverCommittedEpoch(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	insertLegacyRow(t, h, 1, "legacy-a", "")
	insertLegacyRow(t, h, 2, "legacy-b", rowHash(t, h, 1))

	authority, trust := testRepairAuthority(t, h.dep)
	auth := testAuth(t, h.outbox, authority, trust, h.dep, OperationMigrate)
	fc, err := h.fenceClient(auth)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	fence, err := fc.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}

	req1 := h.migrateRequest(auth, fence, 1, "digest-a", []byte(`{"canonical":"a"}`))
	res1, err := h.outbox.MigrateLegacySuffix(ctx, h.prod, req1)
	if err != nil {
		t.Fatalf("migration 1: %v", err)
	}
	terminal, err := fc.Finalize(ctx, req1.Permit, FinalizeReport{
		ProofDigest: res1.ProofDigest, JournalSeq: res1.JournalSeq,
		BeforeDigest: res1.BeforeDigest, AfterDigest: res1.AfterDigest,
		ResultDigest: "result-a",
	})
	if err != nil {
		t.Fatalf("finalize 1: %v", err)
	}
	if err := h.outbox.CompleteMigrationTx(ctx, &terminal); err != nil {
		t.Fatalf("complete 1: %v", err)
	}

	permit2, err := fc.Prepare(ctx, fence, 2, rowHash(t, h, 2))
	if err != nil {
		t.Fatalf("prepare 2: %v", err)
	}
	if _, err := h.outbox.AdmitMigration(ctx, &permit2); err != nil {
		t.Fatalf("admit 2: %v", err)
	}
	if err := h.outbox.RevokePermit(ctx, permit2.TxID, "abandoned"); err != nil {
		t.Fatalf("revoke 2: %v", err)
	}
	if _, err := fc.AbortMigration(ctx, permit2, "abandoned"); !errors.Is(err, ErrMigrationOutcomeUnknown) {
		t.Fatalf("aborting one transaction released an epoch holding a committed rewrite: %v", err)
	}
	active, err := h.ledger.ActiveFence(ctx, h.dep)
	if err != nil {
		t.Fatal(err)
	}
	if active == nil || active.FenceID != fence.FenceID {
		t.Fatalf("the epoch is no longer active after a refused abort: %+v", active)
	}
}

// A quarantined epoch mints nothing. PrepareMigration used to write
// PREPARED over RECOVERY_REQUIRED, so the marker that keeps custody
// frozen could be cleared by the ordinary path.
func TestRC84PrepareRefusedInQuarantinedEpoch(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	insertLegacyRow(t, h, 1, "legacy-a", "")
	insertLegacyRow(t, h, 2, "legacy-b", rowHash(t, h, 1))

	authority, trust := testRepairAuthority(t, h.dep)
	auth := testAuth(t, h.outbox, authority, trust, h.dep, OperationMigrate)
	fc, err := h.fenceClient(auth)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	fence, err := fc.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	req1 := h.migrateRequest(auth, fence, 1, "digest-a", []byte(`{"canonical":"a"}`))
	res1, err := h.outbox.MigrateLegacySuffix(ctx, h.prod, req1)
	if err != nil {
		t.Fatalf("migration 1: %v", err)
	}
	terminal, err := fc.Finalize(ctx, req1.Permit, FinalizeReport{
		ProofDigest: res1.ProofDigest, JournalSeq: res1.JournalSeq,
		BeforeDigest: res1.BeforeDigest, AfterDigest: res1.AfterDigest,
		ResultDigest: "result-a",
	})
	if err != nil {
		t.Fatalf("finalize 1: %v", err)
	}
	if err := h.outbox.CompleteMigrationTx(ctx, &terminal); err != nil {
		t.Fatalf("complete 1: %v", err)
	}
	// A contradictory finalize is what quarantines the epoch.
	if _, err := fc.Finalize(ctx, req1.Permit, FinalizeReport{
		ProofDigest: "different-proof", JournalSeq: res1.JournalSeq,
		BeforeDigest: res1.BeforeDigest, AfterDigest: res1.AfterDigest,
		ResultDigest: "result-a",
	}); err == nil {
		t.Fatal("contradictory finalize was accepted")
	}
	if rec, err := h.ledger.Fence(ctx, h.dep, fence.FenceID); err != nil {
		t.Fatal(err)
	} else if rec.State != FenceRecoveryRequired {
		t.Fatalf("fence is %s after a contradiction, want %s", rec.State, FenceRecoveryRequired)
	}

	if _, err := fc.Prepare(ctx, fence, 2, rowHash(t, h, 2)); !errors.Is(err, ErrFenceRecoveryRequired) {
		t.Fatalf("a quarantined epoch admitted a new transaction: %v", err)
	}
	rec, err := h.ledger.Fence(ctx, h.dep, fence.FenceID)
	if err != nil {
		t.Fatal(err)
	}
	if rec.State != FenceRecoveryRequired {
		t.Fatalf("a refused prepare still moved the quarantine to %s", rec.State)
	}
}

// Releasing a quarantined epoch is the recovery path's job. The
// ordinary abort must refuse it, and the same abort carrying the
// recovery marker must succeed.
func TestRC84OrdinaryAbortCannotResolveQuarantine(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	insertLegacyRow(t, h, 1, "legacy-a", "")

	authority, trust := testRepairAuthority(t, h.dep)
	auth := testAuth(t, h.outbox, authority, trust, h.dep, OperationMigrate)
	fc, err := h.fenceClient(auth)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	fence, err := fc.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	permit, err := fc.Prepare(ctx, fence, 1, "preimage")
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if _, err := h.outbox.AdmitMigration(ctx, &permit); err != nil {
		t.Fatalf("admit: %v", err)
	}
	if err := h.ledger.MarkRecoveryRequired(ctx, h.dep, fence.FenceID, "probe"); err != nil {
		t.Fatal(err)
	}
	if err := h.outbox.RevokePermit(ctx, permit.TxID, "probe"); err != nil {
		t.Fatal(err)
	}

	if _, err := fc.AbortMigration(ctx, permit, "ordinary"); !errors.Is(err, ErrFenceRecoveryRequired) {
		t.Fatalf("the ordinary abort resolved a quarantined epoch: %v", err)
	}

	// The recovery path must still be able to release it, end to end.
	plan, err := PlanRecovery(ctx, h.outbox, h.client, h.dep, fence.FenceID)
	if err != nil {
		t.Fatalf("plan recovery: %v", err)
	}
	if plan.Quarantined || plan.Action != RecoveryAbort {
		t.Fatalf("plan = %+v, want an unquarantined ABORT", plan)
	}
	grant := testRecoveryGrant(t, authority, plan, RecoveryAbort)
	if _, err := ExecuteRecovery(ctx, h.outbox, recoveryClient(h, plan.GrantDigest), trust, grant, plan, time.Now()); err != nil {
		t.Fatalf("a recovery abort could not resolve the quarantine: %v", err)
	}
	active, err := h.ledger.ActiveFence(ctx, h.dep)
	if err != nil {
		t.Fatal(err)
	}
	if active != nil {
		t.Fatalf("recovery abort did not release the quarantined epoch: %+v", active)
	}
}

// The refusal path must not dereference a fence request the caller
// never sent: the socket loop has no recover, so a panic here takes the
// witness down.
func TestRC84FenceOpWithoutBodyIsRefused(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	resp := h.service.Handle(context.Background(), Request{Op: OpFenceBegin, DeploymentID: h.dep})
	if resp.OK || resp.Error == "" {
		t.Fatalf("a fence op with no body was accepted: %+v", resp)
	}
	if resp.Code != CodeFenceState {
		t.Fatalf("refusal code = %q, want %q", resp.Code, CodeFenceState)
	}
}
