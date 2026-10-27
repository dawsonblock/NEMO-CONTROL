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
	res, err := h.outbox.MigrateLegacySuffix(ctx, h.prod,
		h.migrateRequest(auth, fence, 1, "digest-a", []byte(`{"canonical":"a"}`)))
	if err != nil {
		t.Fatalf("first migration: %v", err)
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
			Epoch: 9, BaseSeq: 0, BaseHash: "base", GrantDigest: "grant",
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
			GrantDigest: "grant", BaseSeq: 0, BaseHash: "base",
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
			Seq: 3, Hash: "head", SignerEpoch: 9,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyCheckpoint(head, h.dep, retiredCustodian); err == nil {
			t.Fatal("a retired custodian key signed the checkpoint that picks a fence base (D-RC84-04)")
		}
	})

	t.Run("fresh operator grant", func(t *testing.T) {
		authority, _ := testRepairAuthority(t, h.dep)
		retiredRepair := custody.NewTrustSet(custody.TrustedKey{
			Role: custody.RoleRepairAuthority, KeyID: authority.Fingerprint(),
			PublicKey: authority.PublicKey(), DeploymentID: h.dep,
			ValidFromIndex: 1, ValidUntilIndex: 5,
		})
		grant := testGrant(t, authority, h.dep, "alice@example.com", OperationMigrate)
		if err := VerifyOperatorGrant(grant, retiredRepair, h.dep, OperationMigrate, time.Now()); err == nil {
			t.Fatal("a retired repair-authority key issued a fresh migration grant (D-RC84-04)")
		}
	})
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
