package witness

// RC8.4 PR-03 — authenticated recovery. An epoch that outlives its
// initiating grant must still be resolvable, and resolving it must not
// be possible by waiting, by guessing, or by re-using the authorization
// that already failed.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openclaw/crabbox/internal/evidence"
)

// restartWitness stops the harness service, reopens the ledger and
// serves again on the same socket — the crash/restart the recovery path
// has to survive.
func restartWitness(t *testing.T, h *harness) {
	t.Helper()
	if h.cancel != nil {
		h.cancel()
	}
	if err := h.ledger.Close(); err != nil {
		t.Fatalf("close ledger: %v", err)
	}
	ledger, err := OpenLedger(h.ledgerPath)
	if err != nil {
		t.Fatalf("reopen ledger: %v", err)
	}
	h.ledger = ledger
	h.service = NewService(ledger, h.wsigner, h.dep, h.ktrust, nil)
	h.serve()
}

func testRecoveryGrant(t *testing.T, signer *evidence.Signer, plan RecoveryPlan, action string) *RecoveryGrant {
	t.Helper()
	now := time.Now().UTC()
	g := &RecoveryGrant{
		Subject: "alice@example.com", DeploymentID: plan.DeploymentID,
		FenceID: plan.FenceID, Epoch: plan.Epoch, TxID: plan.TxID,
		OriginalGrantDigest: plan.GrantDigest, BaseSeq: plan.BaseSeq, BaseHash: plan.BaseHash,
		Action: action, ObservedLocalState: plan.LocalState,
		ObservedJournalSeq: plan.JournalSeq, ObservedAfterDigest: plan.AfterDigest,
		Nonce: testNonce(t), NotBefore: now.Add(-time.Minute).Format(time.RFC3339),
		ExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339), Audience: "custodyctl",
	}
	if err := SignRecoveryGrant(signer, g); err != nil {
		t.Fatalf("sign recovery grant: %v", err)
	}
	return g
}

func recoveryClient(h *harness, grantDigest string) *FenceClient {
	return &FenceClient{
		Client: h.client, Signer: h.kernel, DeploymentID: h.dep,
		GrantDigest: grantDigest, KernelTrust: h.ktrust, CustodianTrust: h.ctrust,
	}
}

// D-RC84-06 (F2): an epoch whose initiating grant can no longer act is
// still recoverable. The local commit happened; the witness never
// recorded it; the original grant has expired. A separate recovery
// authorization must finish the work, and the fence identity and
// original grant binding must survive the handover.
func TestRC84ExpiredGrantRecoveryAfterWitnessRestart(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	insertLegacyRow(t, h, 1, "recover-a", "")

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
	req := h.migrateRequest(auth, fence, 1, "digest-a", []byte(`{"canonical":"a"}`))
	res, err := h.outbox.MigrateLegacySuffix(ctx, h.prod, req)
	if err != nil {
		t.Fatalf("migration: %v", err)
	}
	// The crash window: the local commit exists, the witness record does
	// not, and the run dies here.
	if res.JournalSeq == 0 {
		t.Fatal("migration did not record a journal entry")
	}

	restartWitness(t, h)
	defer h.cancel()

	plan, err := PlanRecovery(ctx, h.outbox, h.client, h.dep, fence.FenceID)
	if err != nil {
		t.Fatalf("plan recovery: %v", err)
	}
	if plan.Quarantined || plan.Action != RecoveryFinalize {
		t.Fatalf("plan = %+v, want an unquarantined FINALIZE", plan)
	}
	if plan.GrantDigest != req.Permit.GrantDigest {
		t.Fatalf("plan lost the original grant binding: %s", plan.GrantDigest)
	}

	// The initiating grant is expired. The replacement authorization is
	// signed by the repair authority and binds the original grant
	// digest without being equal to it.
	grant := testRecoveryGrant(t, authority, plan, RecoveryFinalize)
	if _, err := ExecuteRecovery(ctx, h.outbox, recoveryClient(h, plan.GrantDigest), trust, grant, plan, time.Now()); err != nil {
		t.Fatalf("execute recovery: %v", err)
	}
	tx, err := h.outbox.MigrationTx(ctx, plan.TxID)
	if err != nil {
		t.Fatal(err)
	}
	if tx.State != LocalTxFinalized {
		t.Fatalf("local transaction is %s after recovery, want %s", tx.State, LocalTxFinalized)
	}
	if _, err := fc.End(ctx, fence, res.AfterDigest); err != nil {
		t.Fatalf("close recovered epoch: %v", err)
	}
}

// D-RC84-07: an abort releases custody, so it must be preceded by a
// durable local revocation. After recovery aborts, the old permit is
// dead and cannot be redeemed by a resumed kernel.
func TestRC84RecoveryAbortRevokesPermitBeforeRelease(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	insertLegacyRow(t, h, 1, "recover-abort", "")

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
	req := h.migrateRequest(auth, fence, 1, "digest-a", []byte(`{"canonical":"a"}`))
	if req.Permit.TxID == "" {
		t.Fatal("permit was not admitted")
	}

	plan, err := PlanRecovery(ctx, h.outbox, h.client, h.dep, fence.FenceID)
	if err != nil {
		t.Fatalf("plan recovery: %v", err)
	}
	if plan.Quarantined || plan.Action != RecoveryAbort {
		t.Fatalf("plan = %+v, want an unquarantined ABORT", plan)
	}
	grant := testRecoveryGrant(t, authority, plan, RecoveryAbort)
	if _, err := ExecuteRecovery(ctx, h.outbox, recoveryClient(h, plan.GrantDigest), trust, grant, plan, time.Now()); err != nil {
		t.Fatalf("execute recovery: %v", err)
	}

	tx, err := h.outbox.MigrationTx(ctx, plan.TxID)
	if err != nil {
		t.Fatal(err)
	}
	if tx.State != LocalTxRevoked {
		t.Fatalf("local transaction is %s after abort recovery, want %s", tx.State, LocalTxRevoked)
	}
	active, err := h.ledger.ActiveFence(ctx, h.dep)
	if err != nil {
		t.Fatal(err)
	}
	if active != nil {
		t.Fatalf("recovery abort did not release the epoch: %+v", active)
	}
	// A resumed kernel holding the old permit must find it dead.
	if _, err := h.outbox.MigrateLegacySuffix(ctx, h.prod, req); !errors.Is(err, ErrPermitConsumed) {
		t.Fatalf("revoked permit was redeemable after recovery abort: %v", err)
	}
	if content, _ := h.row(t, 1).Envelope.ContentBytes(); len(content) != 0 {
		t.Fatal("the revoked permit mutated the row")
	}
}

// Recovery is single-use and fact-bound: a replayed authorization, and
// an authorization issued against a different observed state, are both
// refusals.
func TestRC84RecoveryRejectsReplayAndWrongFacts(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	insertLegacyRow(t, h, 1, "recover-replay", "")

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
	req := h.migrateRequest(auth, fence, 1, "digest-a", []byte(`{"canonical":"a"}`))
	if req.Permit.TxID == "" {
		t.Fatal("permit was not admitted")
	}
	plan, err := PlanRecovery(ctx, h.outbox, h.client, h.dep, fence.FenceID)
	if err != nil {
		t.Fatal(err)
	}
	grant := testRecoveryGrant(t, authority, plan, RecoveryAbort)
	if _, err := ExecuteRecovery(ctx, h.outbox, recoveryClient(h, plan.GrantDigest), trust, grant, plan, time.Now()); err != nil {
		t.Fatalf("first recovery: %v", err)
	}
	// Replay of the same completed authorization is refused.
	if _, err := ExecuteRecovery(ctx, h.outbox, recoveryClient(h, plan.GrantDigest), trust, grant, plan, time.Now()); !errors.Is(err, ErrRecoveryAuthorization) {
		t.Fatalf("replayed recovery grant was accepted: %v", err)
	}

	// A fresh authorization that observed a different local state is a
	// contradiction, not a retry.
	second := testRecoveryGrant(t, authority, plan, RecoveryAbort)
	second.ObservedLocalState = LocalTxAdmitted
	if _, err := ExecuteRecovery(ctx, h.outbox, recoveryClient(h, plan.GrantDigest), trust, second, plan, time.Now()); err == nil {
		t.Fatal("recovery grant issued against a different observed state was accepted")
	}
}

// A disagreement the derivation cannot account for stays quarantined.
func TestRC84RecoveryQuarantinesUnaccountableState(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	insertLegacyRow(t, h, 1, "recover-quarantine", "")

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
	req := h.migrateRequest(auth, fence, 1, "digest-a", []byte(`{"canonical":"a"}`))
	if req.Permit.TxID == "" {
		t.Fatal("permit was not admitted")
	}
	// Simulate a witness store restored from an older snapshot: the
	// epoch reads CLOSED while this outbox still holds an admitted
	// permit. A commit may exist without its marker, so the derivation
	// must refuse to guess.
	if _, err := h.ledger.db.ExecContext(ctx,
		`UPDATE custody_fence SET state = $1 WHERE deployment_id = $2 AND fence_id = $3`,
		FenceClosed, h.dep, fence.FenceID); err != nil {
		t.Fatalf("simulate restored witness: %v", err)
	}
	plan, err := PlanRecovery(ctx, h.outbox, h.client, h.dep, fence.FenceID)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Quarantined {
		t.Fatalf("plan resolved an unaccountable state instead of quarantining it: %+v", plan)
	}
	grant := testRecoveryGrant(t, authority, plan, RecoveryAbort)
	if _, err := ExecuteRecovery(ctx, h.outbox, recoveryClient(h, plan.GrantDigest), trust, grant, plan, time.Now()); !errors.Is(err, ErrFenceRecoveryRequired) {
		t.Fatalf("quarantined plan executed: %v", err)
	}
}
