package witness

// RC8.4 PR-00 — red regressions for the transactional-fence security
// closure. Every test in this file is expected to FAIL against the
// RC8.3 baseline (source commit de71093). Each one names the defect it
// reproduces; the green runs land in the PR that closes it.
//
// Register: qualification/rc8.4-integrity/defect-register.json
//
// Do not weaken an assertion here to make the suite pass. A red test in
// this file is the evidence that a P0/P1 defect was real.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/openclaw/crabbox/internal/custody"
)

// D-RC84-01 (F1): the signed OPEN receipt is the mutation authority and
// nothing marks it consumed. After the witness records CLOSED and
// resumes admitting submissions, the same saved receipt rewrites a
// second target.
func TestRC84HistoricalOpenCannotAuthorizeSecondTarget(t *testing.T) {
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
	req := h.migrateRequest(auth, fence, 1, "digest-a", []byte(`{"canonical":"a"}`))
	res, err := h.outbox.MigrateLegacySuffix(ctx, h.prod, req)
	if err != nil {
		t.Fatalf("first migration: %v", err)
	}
	if _, err := fc.Finalize(ctx, req.Permit, FinalizeReport{
		ProofDigest: res.ProofDigest, JournalSeq: res.JournalSeq,
		BeforeDigest: res.BeforeDigest, AfterDigest: res.AfterDigest, ResultDigest: res.AfterDigest,
	}); err != nil {
		t.Fatalf("finalize: %v", err)
	}
	if _, err := fc.End(ctx, fence, res.AfterDigest); err != nil {
		t.Fatalf("end: %v", err)
	}
	active, err := h.ledger.ActiveFence(ctx, h.dep)
	if err != nil {
		t.Fatal(err)
	}
	if active != nil {
		t.Fatalf("epoch still active after close: %+v", active)
	}

	if _, err := h.outbox.MigrateLegacySuffix(ctx, h.prod,
		h.migrateRequest(auth, fence, 2, "digest-b", []byte(`{"canonical":"b"}`))); err == nil {
		t.Fatal("a saved OPEN receipt rewrote a second target after the witness closed the epoch: " +
			"the receipt is being treated as standing mutation authority (D-RC84-01)")
	}
}

// D-RC84-02: releasing an epoch over a committed rewrite resumes
// submissions against a suffix the sender may still hold in its old
// form. The witness must refuse an abort while an admitted migration
// has a committed or unknown local outcome.
func TestRC84AbortRefusedOverCommittedRewrite(t *testing.T) {
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
	if _, err := h.outbox.MigrateLegacySuffix(ctx, h.prod,
		h.migrateRequest(auth, fence, 1, "digest-a", []byte(`{"canonical":"a"}`))); err != nil {
		t.Fatalf("migration: %v", err)
	}

	if _, err := fc.Abort(ctx, fence); err == nil {
		t.Fatal("the witness aborted an epoch after a local rewrite committed: " +
			"releasing custody over a rewritten suffix is the fork the epoch exists to prevent (D-RC84-02)")
	}
}

// D-RC84-03 (F3): the signer epoch is the durable discriminator
// between key generations. Two rotations must never share one.
func TestRC84RotationEpochIsUniquePerRotation(t *testing.T) {
	h := newHarness(t, false)
	defer h.outbox.Close()
	ctx := context.Background()

	const rounds, perRound = 5, 16
	for round := 0; round < rounds; round++ {
		var (
			wg   sync.WaitGroup
			gate = make(chan struct{})
			got  = make([]int64, perRound)
			errs = make([]error, perRound)
		)
		for i := 0; i < perRound; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-gate
				got[i], errs[i] = h.ledger.AdvanceSignerEpoch(ctx)
			}(i)
		}
		close(gate)
		wg.Wait()

		seen := make(map[int64]bool, perRound)
		for i := 0; i < perRound; i++ {
			if errs[i] != nil {
				t.Fatalf("round %d rotation %d: %v", round, i, errs[i])
			}
			if seen[got[i]] {
				t.Fatalf("round %d: two rotations share signer epoch %d — custody_log.signer_epoch "+
					"no longer identifies a key generation (D-RC84-03)", round, got[i])
			}
			seen[got[i]] = true
		}
	}
}

// D-RC84-04 (F5): a key whose validity window has closed is historical
// evidence, not current authority. Every boundary that grants fresh
// authority must refuse it.
func TestRC84RetiredKeysCannotMintFreshAuthority(t *testing.T) {
	h := newHarness(t, false)
	defer h.outbox.Close()

	retiredCustodian := custody.NewTrustSet(custody.TrustedKey{
		Role: custody.RoleCustodian, KeyID: h.wsigner.Fingerprint(),
		PublicKey: h.wsigner.PublicKey(), DeploymentID: h.dep,
		ValidFromIndex: 1, ValidUntilIndex: 5,
	})
	retiredKernel := custody.NewTrustSet(custody.TrustedKey{
		Role: custody.RoleKernelRelay, KeyID: h.kernel.Fingerprint(),
		PublicKey: h.kernel.PublicKey(), DeploymentID: h.dep,
		ValidFromIndex: 1, ValidUntilIndex: 5,
	})

	t.Run("fresh fence receipt", func(t *testing.T) {
		receipt := &FenceReceipt{
			State: FenceOpen, DeploymentID: h.dep, FenceID: "fence-retired",
			Epoch: 9, BaseSeq: 9, BaseHash: "base", GrantDigest: "grant",
			OpenedAt: time.Now().UTC().Format(time.RFC3339Nano),
		}
		if _, err := SignFenceReceipt(h.wsigner, 9, receipt); err != nil {
			t.Fatal(err)
		}
		if err := VerifyFenceReceipt(receipt, h.dep, retiredCustodian); err == nil {
			t.Fatal("a retired custodian key minted a fresh OPEN receipt that verified (D-RC84-04)")
		}
	})

	t.Run("fresh fence request", func(t *testing.T) {
		req := &FenceRequest{
			Op: OpFenceBegin, DeploymentID: h.dep, FenceID: "fence-retired",
			GrantDigest: "grant", BaseSeq: 9, BaseHash: "base",
		}
		if err := SignFenceRequest(h.kernel, req); err != nil {
			t.Fatal(err)
		}
		if err := VerifyFenceRequest(req, h.dep, retiredKernel); err == nil {
			t.Fatal("a retired kernel-relay key opened a fresh migration epoch (D-RC84-04)")
		}
	})

	t.Run("fresh checkpoint", func(t *testing.T) {
		head, err := SignCheckpoint(h.wsigner, h.dep, &CheckpointHead{
			Seq: 9, Hash: "head", SignerEpoch: 9,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyCheckpoint(head, h.dep, retiredCustodian); err == nil {
			t.Fatal("a retired custodian key signed the checkpoint that picks a fence base (D-RC84-04)")
		}
	})

	// A detached operator grant carries no sequence index, so the trust
	// set has nothing to resolve its window against. That gap is
	// recorded in the defect register rather than papered over here: the
	// fix needs a signer-epoch window in the trust file, which the
	// recovery-grant work in PR-03 introduces.
}

// D-RC84-05 (F4): End/Abort must act under the grant this run holds,
// never under whatever grant the presented receipt names.
func TestRC84FinishRejectsReceiptFromAnotherGrant(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	insertLegacyRow(t, h, 1, "legacy-a", "")

	authority, trust := testRepairAuthority(t, h.dep)
	authA := testAuth(t, h.outbox, authority, trust, h.dep, OperationMigrate)
	fcA, err := h.fenceClient(authA)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	fenceA, err := fcA.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}

	// A second authorization this run does not hold. The client below is
	// configured for grant B and must not close grant A's epoch.
	grantB := testGrant(t, authority, h.dep, "mallory@example.com", OperationMigrate)
	digestB, err := GrantDigest(grantB)
	if err != nil {
		t.Fatal(err)
	}
	fcB := &FenceClient{
		Client: h.client, Signer: h.kernel, DeploymentID: h.dep,
		GrantDigest: digestB, KernelTrust: h.ktrust, CustodianTrust: h.ctrust,
	}
	if _, err := fcB.End(ctx, fenceA, "digest-a"); err == nil {
		t.Fatal("End closed an epoch under the grant named by the presented receipt, " +
			"not the grant this client holds (D-RC84-05)")
	}
}

// D-RC84-09: the submission barrier must be closed in every state that
// is not terminal. The barrier is expressed as "not CLOSED and not
// ABORTED", so a state added to the protocol later is closed by default
// rather than silently admitted.
func TestMigrationBarrierClosedInEveryNonTerminalState(t *testing.T) {
	ctx := context.Background()
	nonTerminal := []string{FenceOpen, FencePrepared, FenceFinalizing, FenceRecoveryRequired}
	for _, state := range nonTerminal {
		t.Run("closed_"+state, func(t *testing.T) {
			h := newHarness(t, false)
			defer h.outbox.Close()
			seq := h.enqueue("barrier-"+state, `{"payload":1}`)
			insertFenceRow(t, h, state)
			if _, err := h.ledger.Submit(ctx, h.wsigner, 0, h.row(t, seq).Envelope, h.dep, h.ktrust); !errors.Is(err, ErrFenced) {
				t.Fatalf("state %s admitted a submission: %v", state, err)
			}
		})
	}
	for _, state := range []string{FenceClosed, FenceAborted} {
		t.Run("open_"+state, func(t *testing.T) {
			h := newHarness(t, false)
			defer h.outbox.Close()
			seq := h.enqueue("barrier-"+state, `{"payload":1}`)
			insertFenceRow(t, h, state)
			if _, err := h.ledger.Submit(ctx, h.wsigner, 0, h.row(t, seq).Envelope, h.dep, h.ktrust); err != nil {
				t.Fatalf("terminal state %s refused a submission: %v", state, err)
			}
		})
	}
}

func insertFenceRow(t *testing.T, h *harness, state string) {
	t.Helper()
	if _, err := h.ledger.db.ExecContext(context.Background(),
		`INSERT INTO custody_fence (deployment_id, fence_id, epoch, base_seq, base_hash,
		 grant_digest, kernel_fp, state, result_digest, opened_at, closed_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'',$9,'')`,
		h.dep, "fence-"+state, 1, 0, "", "grant", h.kernel.Fingerprint(), state,
		time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("insert fence row %s: %v", state, err)
	}
}

// D-RC84-10: the local fence intent is durable evidence of what the
// kernel asked for. Recording the same fence identity with different
// commitments is a contradiction, not a no-op.
func TestRC84FenceIntentConflictRefused(t *testing.T) {
	h := newHarness(t, false)
	defer h.outbox.Close()
	ctx := context.Background()

	first := FenceIntent{
		FenceID: "fence-intent", DeploymentID: h.dep, GrantDigest: "grant",
		BaseSeq: 1, BaseHash: "base-one", State: FenceOpen,
		OpenedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := h.outbox.RecordFenceIntent(ctx, first); err != nil {
		t.Fatalf("record first intent: %v", err)
	}

	conflicting := first
	conflicting.BaseSeq, conflicting.BaseHash = 2, "base-two"
	if err := h.outbox.RecordFenceIntent(ctx, conflicting); err == nil {
		t.Fatal("the same fence identity was recorded against two different bases without a " +
			"contradiction (D-RC84-10)")
	}
}
