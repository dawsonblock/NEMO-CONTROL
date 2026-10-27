package witness

// RC8.4 PR-05 — deterministic schedules for the transactional fence.
//
// These are the orderings that decide whether the protocol holds. Each
// one is driven through a real witness, a real outbox and the real
// SQLite transactions, and each asserts a terminal property rather than
// a log line. The race detector is necessary but not sufficient here:
// these failures are ordering failures, so the schedule is made explicit
// instead of hoped for.

import (
	"context"
	"errors"
	"testing"
)

// A finalize that lands and an End that never does must leave the epoch
// closable by the ordinary path — the transaction is COMMITTED, so no
// admission is outstanding and nothing is unresolved.
func TestRC84CrashAfterFinalizeBeforeEnd(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	insertLegacyRow(t, h, 1, "finalize-a", "")

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
	result, err := fc.Finalize(ctx, req.Permit, FinalizeReport{
		ProofDigest: res.ProofDigest, JournalSeq: res.JournalSeq,
		BeforeDigest: res.BeforeDigest, AfterDigest: res.AfterDigest, ResultDigest: res.AfterDigest,
	})
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	// The crash: the local row was never completed and End never ran.
	if result.State != MigrationTxCommitted {
		t.Fatalf("finalize returned %s", result.State)
	}
	if _, err := fc.End(ctx, fence, res.AfterDigest); err != nil {
		t.Fatalf("close after a finalized transaction: %v", err)
	}
	active, err := h.ledger.ActiveFence(ctx, h.dep)
	if err != nil {
		t.Fatal(err)
	}
	if active != nil {
		t.Fatalf("epoch still active after close: %+v", active)
	}
}

// Re-preparing the same transaction is idempotent and returns the same
// permit bytes. Re-signing would mint a new IssuedAt, and the local row
// would then hold a digest the witness never issued.
func TestRC84DuplicatePrepareIsIdempotent(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	insertLegacyRow(t, h, 1, "dup-prepare", "")

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
	preimage := h.row(t, 1).EnvelopeHash
	first, err := fc.Prepare(ctx, fence, 1, preimage)
	if err != nil {
		t.Fatalf("first prepare: %v", err)
	}
	second, err := fc.Prepare(ctx, fence, 1, preimage)
	if err != nil {
		t.Fatalf("second prepare: %v", err)
	}
	if first.Signature != second.Signature || first.IssuedAt != second.IssuedAt {
		t.Fatal("re-preparing the same transaction minted a different permit")
	}
	d1, err := PermitDigest(&first)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := PermitDigest(&second)
	if err != nil {
		t.Fatal(err)
	}
	if d1 != d2 {
		t.Fatalf("permit digest changed across re-entry: %s vs %s", d1, d2)
	}
}

// One admitted transaction at a time. Admitting a second target while
// the first is outstanding is an unresolved outcome, not a queue.
func TestRC84PrepareRefusedWhileAnotherTransactionAdmitted(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	insertLegacyRow(t, h, 1, "serial-a", "")
	insertLegacyRow(t, h, 2, "serial-b", rowHash(t, h, 1))

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
	if _, err := fc.Prepare(ctx, fence, 1, h.row(t, 1).EnvelopeHash); err != nil {
		t.Fatalf("first prepare: %v", err)
	}
	if _, err := fc.Prepare(ctx, fence, 2, h.row(t, 2).EnvelopeHash); !errors.Is(err, ErrMigrationOutcomeUnknown) {
		t.Fatalf("second transaction admitted while the first is outstanding: %v", err)
	}
}

// The permit names the bytes it was admitted against. If the target
// moved between admission and the rewrite, the permit is stale.
func TestRC84PermitBoundToPreimage(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	insertLegacyRow(t, h, 1, "preimage-a", "")

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
	// Someone rewrote the target after admission: the permit no longer
	// describes the bytes it would replace.
	if _, err := h.outbox.db.ExecContext(ctx,
		`UPDATE custody_outbox SET envelope_hash = 'moved' WHERE seq = 1`); err != nil {
		t.Fatal(err)
	}
	// The refusal may come from the chain check or from the permit's own
	// preimage binding; either way the permit must not be redeemable and
	// the row must be untouched.
	if _, err := h.outbox.MigrateLegacySuffix(ctx, h.prod, req); err == nil {
		t.Fatal("a permit admitted against a different preimage was redeemable")
	}
	if content, _ := h.row(t, 1).Envelope.ContentBytes(); len(content) != 0 {
		t.Fatal("the stale permit mutated the row")
	}
}

// An epoch with an admitted transaction cannot be released by the
// ordinary abort: the transaction's outcome is unresolved.
func TestRC84AbortRefusedWhileTransactionAdmitted(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	insertLegacyRow(t, h, 1, "abort-admitted", "")

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
	if _, err := fc.Prepare(ctx, fence, 1, h.row(t, 1).EnvelopeHash); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if _, err := fc.Abort(ctx, fence); !errors.Is(err, ErrMigrationOutcomeUnknown) {
		t.Fatalf("ordinary abort released an epoch with an admitted transaction: %v", err)
	}
}
