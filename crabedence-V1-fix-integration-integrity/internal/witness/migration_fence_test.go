package witness

// RC8.3 PR-01/PR-02 — witness-fenced migration epochs. A checkpoint
// alone proves the custodian's state at one instant; only a signed,
// open epoch proves nothing can still land while a rewrite commits.

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/openclaw/crabbox/internal/custody"
	"github.com/openclaw/crabbox/internal/evidence"
)

// injectWitnessRecord stores a custody row directly in the witness
// ledger. It models a custodian that already holds a record the local
// outbox has not acknowledged — an RC8.1-era witness, or an
// acknowledgement lost in transit — which is the state a migration must
// refuse to rewrite.
func (h *harness) injectWitnessRecord(t *testing.T, seq int64, exec string, env *custody.Envelope) {
	t.Helper()
	envHash, err := env.Hash()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	ack, err := SignAck(h.wsigner, 0, env, envHash)
	if err != nil {
		t.Fatal(err)
	}
	ackJSON, _ := json.Marshal(ack)
	if _, err := h.ledger.db.ExecContext(context.Background(),
		`INSERT INTO custody_log (deployment_id, seq, execution_id, envelope_hash, envelope_json, ack, signer_epoch, received_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		h.dep, seq, exec, envHash, string(raw), string(ackJSON), 0,
		time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
}

// fenceClient wires the kernel side of the epoch handshake against the
// harness witness.
func (h *harness) fenceClient(auth MigrationAuthorization) (*FenceClient, error) {
	digest, err := GrantDigest(auth.Grant)
	if err != nil {
		return nil, err
	}
	return &FenceClient{
		Client: h.client, Signer: h.kernel, DeploymentID: h.dep,
		GrantDigest: digest, KernelTrust: h.ktrust, CustodianTrust: h.ctrust,
	}, nil
}

// openFence opens a real migration epoch against the running witness
// service. The epoch is aborted at cleanup unless the test closed it.
func (h *harness) openFence(t *testing.T, auth MigrationAuthorization) FenceReceipt {
	t.Helper()
	fc, err := h.fenceClient(auth)
	if err != nil {
		t.Fatalf("fence client: %v", err)
	}
	fence, err := fc.Begin(context.Background())
	if err != nil {
		t.Fatalf("open migration epoch: %v", err)
	}
	t.Cleanup(func() {
		_, _ = fc.Abort(context.Background(), fence)
	})
	return fence
}

// migrateRequest assembles the full library input for one rewrite.
func (h *harness) migrateRequest(auth MigrationAuthorization, fence FenceReceipt, rowSeq int64, digest string, payload []byte) MigrationRequest {
	return MigrationRequest{
		RowSeq: rowSeq, TerminalReceiptDigest: digest, Native: payload,
		Fence: fence, Authorization: auth, CustodianTrust: h.ctrust,
	}
}

// migrate runs one fenced rewrite with a freshly opened epoch, closing
// it on success and aborting it on failure — the same lifecycle the
// operator command drives.
func (h *harness) migrate(t *testing.T, auth MigrationAuthorization, rowSeq int64, digest string, payload []byte) (MigrationResult, error) {
	t.Helper()
	fc, err := h.fenceClient(auth)
	if err != nil {
		t.Fatalf("fence client: %v", err)
	}
	fence, err := fc.Begin(context.Background())
	if err != nil {
		t.Fatalf("open migration epoch: %v", err)
	}
	res, merr := h.outbox.MigrateLegacySuffix(context.Background(), h.prod,
		h.migrateRequest(auth, fence, rowSeq, digest, payload))
	if merr != nil {
		_, _ = fc.Abort(context.Background(), fence)
		return res, merr
	}
	if _, err := fc.End(context.Background(), fence, res.AfterDigest); err != nil {
		t.Fatalf("close migration epoch: %v", err)
	}
	return res, nil
}

// TestMigrationRequiresVerifiedFenceSignature: a fence receipt minted
// by a key outside the pinned custodian set authorizes nothing, even
// though every field of it is internally consistent.
func TestMigrationRequiresVerifiedFenceSignature(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	insertLegacyRow(t, h, 1, "forged-fence", "")

	authority, trust := testRepairAuthority(t, h.dep)
	auth := testAuth(t, h.outbox, authority, trust, h.dep, OperationMigrate)
	digest, err := GrantDigest(auth.Grant)
	if err != nil {
		t.Fatal(err)
	}
	attacker, err := evidence.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	forged := &FenceReceipt{
		State: FenceOpen, DeploymentID: h.dep, FenceID: FenceIDFor(h.dep, digest, 0, ""),
		Epoch: 1, BaseSeq: 0, BaseHash: "", GrantDigest: digest,
		OpenedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	if _, err := SignFenceReceipt(attacker, 0, forged); err != nil {
		t.Fatal(err)
	}

	_, err = h.outbox.MigrateLegacySuffix(context.Background(), h.prod,
		h.migrateRequest(auth, *forged, 1, "digest", []byte(`{"x":1}`)))
	if err == nil {
		t.Fatal("migration accepted a fence signed by an unpinned key")
	}
	if !errors.Is(err, ErrEvidenceContradiction) {
		t.Fatalf("refusal is not a typed contradiction: %v", err)
	}
	if content, _ := h.row(t, 1).Envelope.ContentBytes(); len(content) != 0 {
		t.Fatal("refused migration mutated the row")
	}
}

// TestMigrationRejectsClosedFence: a receipt that verifies but records
// a closed epoch is not an authorization to rewrite.
func TestMigrationRejectsClosedFence(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	insertLegacyRow(t, h, 1, "closed-fence", "")
	authority, trust := testRepairAuthority(t, h.dep)
	auth := testAuth(t, h.outbox, authority, trust, h.dep, OperationMigrate)

	fence := h.openFence(t, auth)
	fc, err := h.fenceClient(auth)
	if err != nil {
		t.Fatal(err)
	}
	closed, err := fc.End(context.Background(), fence, "result-digest")
	if err != nil {
		t.Fatalf("close epoch: %v", err)
	}
	if _, err := h.outbox.MigrateLegacySuffix(context.Background(), h.prod,
		h.migrateRequest(auth, closed, 1, "digest", []byte(`{"x":1}`))); err == nil {
		t.Fatal("migration committed under a closed epoch")
	}
}

// TestFenceRefusesInFlightSubmission is the core RC8.3 property: once
// the epoch is open, a submission that was already on the wire is
// refused instead of landing at the witness under bytes the migration
// is about to replace.
func TestFenceRefusesInFlightSubmission(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	insertLegacyRow(t, h, 1, "inflight-a", "")
	authority, trust := testRepairAuthority(t, h.dep)
	auth := testAuth(t, h.outbox, authority, trust, h.dep, OperationMigrate)
	fence := h.openFence(t, auth)

	_, err := h.client.Submit(context.Background(), h.dep, h.row(t, 1).Envelope)
	if !errors.Is(err, ErrFenced) {
		t.Fatalf("in-flight submission was not fenced: %v", err)
	}
	if n := h.records(); n != 0 {
		t.Fatalf("fenced submission reached custody: %d records", n)
	}

	// The rewrite commits under the epoch, and closing it resumes
	// submissions.
	if _, err := h.outbox.MigrateLegacySuffix(context.Background(), h.prod,
		h.migrateRequest(auth, fence, 1, "digest", []byte(`{"x":1}`))); err != nil {
		t.Fatalf("fenced migration: %v", err)
	}
	fc, err := h.fenceClient(auth)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fc.End(context.Background(), fence, "result"); err != nil {
		t.Fatalf("close epoch: %v", err)
	}
	if !h.drain() {
		t.Fatalf("drain after epoch close: %s", h.sender.LastError())
	}
	if h.records() != 1 {
		t.Fatalf("rewritten row did not reach custody after the epoch closed")
	}
}

// TestFenceRefusesStaleBase: an operator who names a head the witness
// no longer holds is asking to freeze a state it has not seen.
func TestFenceRefusesStaleBase(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	h.enqueue("first", `{"payload":"one"}`)
	if !h.drain() {
		t.Fatalf("drain: %v", h.sender.LastError())
	}
	head, err := h.client.Checkpoint(context.Background(), h.dep)
	if err != nil {
		t.Fatal(err)
	}
	// A second submission moves the head past the operator's view.
	h.enqueue("second", `{"payload":"two"}`)
	if !h.drain() {
		t.Fatalf("drain: %v", h.sender.LastError())
	}

	req := &FenceRequest{
		Op: OpFenceBegin, DeploymentID: h.dep,
		FenceID:     FenceIDFor(h.dep, "grant-digest", head.Seq, head.Hash),
		GrantDigest: "grant-digest", BaseSeq: head.Seq, BaseHash: head.Hash,
	}
	if err := SignFenceRequest(h.kernel, req); err != nil {
		t.Fatal(err)
	}
	_, err = h.client.BeginFence(context.Background(), req)
	if !errors.Is(err, ErrStaleFenceBase) {
		t.Fatalf("stale fence base was admitted: %v", err)
	}
	if fence, err := h.ledger.ActiveFence(context.Background(), h.dep); err != nil || fence != nil {
		t.Fatalf("a refused fence was still recorded: %+v, %v", fence, err)
	}
}

// TestFenceSurvivesWitnessRestart: an epoch is durable state, not a
// lease. A witness that restarts still refuses submissions until the
// migration closes the epoch.
func TestFenceSurvivesWitnessRestart(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	insertLegacyRow(t, h, 1, "restart-a", "")
	authority, trust := testRepairAuthority(t, h.dep)
	auth := testAuth(t, h.outbox, authority, trust, h.dep, OperationMigrate)
	fence := h.openFence(t, auth)
	h.cancel()

	ledgerPath := h.ledgerPath
	reopened, err := OpenLedger(ledgerPath)
	if err != nil {
		t.Fatalf("reopen ledger: %v", err)
	}
	defer reopened.Close()
	active, err := reopened.ActiveFence(context.Background(), h.dep)
	if err != nil {
		t.Fatal(err)
	}
	if active == nil || active.FenceID != fence.FenceID {
		t.Fatalf("epoch did not survive the restart: %+v", active)
	}
	if _, err := reopened.Submit(context.Background(), h.wsigner, h.row(t, 1).Envelope, h.dep, h.ktrust); !errors.Is(err, ErrFenced) {
		t.Fatalf("restarted witness admitted a submission inside an open epoch: %v", err)
	}
}

// TestFenceAbortRefusedAfterCustodyAdvanced: an abort is only safe
// while nothing was admitted. If custody moved, the epoch is an
// integrity fault and must be escalated, never quietly released.
func TestFenceAbortRefusedAfterCustodyAdvanced(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	authority, trust := testRepairAuthority(t, h.dep)
	auth := testAuth(t, h.outbox, authority, trust, h.dep, OperationMigrate)
	fence := h.openFence(t, auth)

	// Simulate custody advancing inside the epoch (only reachable
	// through a ledger fault; the service refuses submissions).
	if _, err := h.ledger.db.ExecContext(context.Background(),
		`UPDATE custody_fence SET base_seq = -1 WHERE fence_id = $1`, fence.FenceID); err != nil {
		t.Fatal(err)
	}
	fc, err := h.fenceClient(auth)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fc.Abort(context.Background(), fence); !errors.Is(err, ErrContradiction) {
		t.Fatalf("abort over advanced custody was admitted: %v", err)
	}
}

// TestFenceRequiresPinnedKernelRequest: the witness will not freeze for
// an unauthenticated caller.
func TestFenceRequiresPinnedKernelRequest(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	attacker, err := evidence.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	req := &FenceRequest{
		Op: OpFenceBegin, DeploymentID: h.dep,
		FenceID: FenceIDFor(h.dep, "g", 0, ""), GrantDigest: "g",
	}
	if err := SignFenceRequest(attacker, req); err != nil {
		t.Fatal(err)
	}
	if _, err := h.client.BeginFence(context.Background(), req); err == nil {
		t.Fatal("witness froze for an unpinned kernel key")
	}
	if fence, _ := h.ledger.ActiveFence(context.Background(), h.dep); fence != nil {
		t.Fatal("refused request left an epoch open")
	}
}

// TestMigrationProofBindsFence: the proof a migration leaves behind
// names the epoch it ran inside, and verification fails if the epoch
// no longer verifies.
func TestMigrationProofBindsFence(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	insertLegacyRow(t, h, 1, "proof-fence", "")
	authority, trust := testRepairAuthority(t, h.dep)
	auth := testAuth(t, h.outbox, authority, trust, h.dep, OperationMigrate)
	if _, err := h.migrate(t, auth, 1, "digest", []byte(`{"x":1}`)); err != nil {
		t.Fatalf("migration: %v", err)
	}
	journal, err := h.outbox.MigrationJournal(context.Background())
	if err != nil || len(journal) != 1 {
		t.Fatalf("journal = %+v, %v", journal, err)
	}
	proofTrust := MigrationProofTrust{DeploymentID: h.dep, ProofTrust: h.ktrust, CustodianTrust: h.ctrust}
	if err := VerifyMigrationProof(journal[0], proofTrust); err != nil {
		t.Fatalf("proof with epoch: %v", err)
	}
	if err := h.outbox.VerifyMigrationProofAgainstChain(context.Background(), journal[0], proofTrust); err != nil {
		t.Fatalf("proof against chain: %v", err)
	}
	// Without the custodian set the epoch cannot be verified, so the
	// proof cannot either.
	if err := VerifyMigrationProof(journal[0], MigrationProofTrust{DeploymentID: h.dep, ProofTrust: h.ktrust, CustodianTrust: custody.NewTrustSet()}); err == nil {
		t.Fatal("proof verified with no pinned custodian set")
	}
}

// TestMigrationRefusesFenceFromAnotherGrant: an epoch opened by one
// authorization cannot launder a different one.
func TestMigrationRefusesFenceFromAnotherGrant(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	insertLegacyRow(t, h, 1, "grant-binding", "")
	authority, trust := testRepairAuthority(t, h.dep)
	first := testAuth(t, h.outbox, authority, trust, h.dep, OperationMigrate)
	fence := h.openFence(t, first)
	second := testAuth(t, h.outbox, authority, trust, h.dep, OperationMigrate)

	_, err := h.outbox.MigrateLegacySuffix(context.Background(), h.prod,
		h.migrateRequest(second, fence, 1, "digest", []byte(`{"x":1}`)))
	if err == nil {
		t.Fatal("migration ran under an epoch opened by a different grant")
	}
}
