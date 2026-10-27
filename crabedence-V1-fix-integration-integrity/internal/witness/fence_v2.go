package witness

// RC8.4 — transactional migration fencing (protocol v2).
//
// RC8.3 made the fence receipt the mutation authority. A receipt is a
// historical object: it can be copied, replayed, and presented again
// after the epoch it describes has ended, and it names no target. So
// one saved OPEN receipt authorized an unbounded number of rewrites —
// including, after the witness had closed the epoch and resumed
// admitting submissions, rewrites of targets the custodian never froze.
//
// v2 replaces "present a receipt" with "redeem one permit exactly
// once":
//
//   - PrepareMigration is an online, witness-serialized admission. The
//     witness checks the frozen head has not moved, records an ADMITTED
//     transaction bound to deployment/fence/epoch/grant/base/target, and
//     issues a signed permit naming that single transaction.
//   - The local migration transaction marks the permit consumed in the
//     same SQL transaction as the suffix mutation, the journal entry and
//     the signed proof. There is no local commit without the marker and
//     no marker without the commit.
//   - FinalizeMigration binds the witness record to the exact local
//     journal digest. The witness leaves the epoch PREPARED until the
//     operator closes it, so a batch of targets stays inside one frozen
//     epoch while each target gets its own one-shot permit.
//   - AbortMigration refuses while any transaction is ADMITTED or
//     COMMITTED, and requires a durable local revocation first. The
//     witness cannot inspect the remote database, so "no local commit"
//     is kernel-attested evidence, never witness-verified proof; the
//     ordering requirement is what makes the attestation meaningful.

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/openclaw/crabbox/internal/custody"
	"github.com/openclaw/crabbox/internal/evidence"
)

// v2 protocol ops.
const (
	OpFencePrepare  = "fence-prepare"
	OpFenceFinalize = "fence-finalize"
)

// v2 schemas and signature domains. Distinct from every v1 domain so a
// v1 record can never be presented as a v2 permit or a v2 terminal
// result.
const (
	FencePermitSchema        = "custody-fence-permit-v2"
	FencePrepareSchema       = "custody-fence-prepare-v2"
	FenceFinalizeSchema      = "custody-fence-finalize-v2"
	FenceResultSchema        = "custody-fence-result-v2"
	FencePermitDomain        = "custody-witness-fence-permit-v2\x00"
	FencePrepareDomain       = "custody-witness-fence-prepare-v2\x00"
	FenceFinalizeDomain      = "custody-witness-fence-finalize-v2\x00"
	FenceResultDomain        = "custody-witness-fence-result-v2\x00"
)

// Fence transaction states. ADMITTED is the only state that authorizes
// a local mutation; COMMITTED is a transaction whose local journal the
// witness has recorded but whose epoch is still open.
const (
	MigrationTxAdmitted  = "ADMITTED"
	MigrationTxCommitted = "COMMITTED"
	MigrationTxAborted   = "ABORTED"
)

// Local transaction states. The local row is the one-shot guard: the
// mutation, the journal entry and the LOCAL_COMMITTED transition share
// one SQL transaction.
const (
	LocalTxAdmitted       = "ADMITTED"
	LocalTxLocalCommitted = "LOCAL_COMMITTED"
	LocalTxFinalized      = "FINALIZED"
	LocalTxAborted        = "ABORTED"
	LocalTxRevoked        = "REVOKED"
)

// Typed v2 refusals. Each is a refusal, never a retryable transport
// failure.
var (
	// ErrPermitMissing — the migration presents no v2 permit. A v1
	// receipt is historical evidence and authorizes nothing.
	ErrPermitMissing = errors.New("witness: migration presents no v2 permit")
	// ErrPermitConsumed — the permit's transaction is no longer
	// ADMITTED locally, so the one-shot authority is spent.
	ErrPermitConsumed = errors.New("witness: migration permit already consumed")
	// ErrMigrationOutcomeUnknown — the transaction has a committed or
	// unresolved local outcome and the epoch must not be released.
	ErrMigrationOutcomeUnknown = errors.New("witness: migration outcome unresolved")
	// ErrFenceRecoveryRequired — the epoch cannot be resolved by the
	// ordinary path and needs an authorized recovery.
	ErrFenceRecoveryRequired = errors.New("witness: fence requires recovery")
	// ErrWrongTerminalReceipt — a terminal response did not carry the
	// state and bindings the request implied.
	ErrWrongTerminalReceipt = errors.New("witness: terminal receipt does not match the request")
)

// FencePermit is the custodian's signed admission of exactly one
// migration transaction. It names the target and the preimage it was
// admitted against, so a permit for one row cannot authorize another.
type FencePermit struct {
	Schema         string `json:"schema"`
	DeploymentID   string `json:"deployment_id"`
	FenceID        string `json:"fence_id"`
	Epoch          int64  `json:"epoch"`
	TxID           string `json:"tx_id"`
	GrantDigest    string `json:"grant_digest"`
	BaseSeq        int64  `json:"base_seq"`
	BaseHash       string `json:"base_hash"`
	TargetSeq      int64  `json:"target_seq"`
	PreimageDigest string `json:"preimage_digest"`
	WitnessFP      string `json:"witness_fp"`
	SignerEpoch    int64  `json:"signer_epoch"`
	IssuedAt       string `json:"issued_at"`
	Signature      string `json:"signature,omitempty"`
}

func fencePermitFields(p *FencePermit) []string {
	return []string{
		p.Schema, p.DeploymentID, p.FenceID, strconv.FormatInt(p.Epoch, 10), p.TxID,
		p.GrantDigest, strconv.FormatInt(p.BaseSeq, 10), p.BaseHash,
		strconv.FormatInt(p.TargetSeq, 10), p.PreimageDigest,
		p.WitnessFP, strconv.FormatInt(p.SignerEpoch, 10), p.IssuedAt,
	}
}

// SignFencePermit countersigns one admission.
func SignFencePermit(signer *evidence.Signer, signerEpoch int64, p *FencePermit) (*FencePermit, error) {
	if signer == nil {
		return nil, fmt.Errorf("fence permit: no custodian signer")
	}
	p.Schema = FencePermitSchema
	p.WitnessFP = signer.Fingerprint()
	p.SignerEpoch = signerEpoch
	sig, err := signer.SignRecord(FencePermitDomain, fencePermitFields(p)...)
	if err != nil {
		return nil, err
	}
	p.Signature = sig
	return p, nil
}

// VerifyFencePermit checks the permit under the pinned custodian set
// with current-authority semantics: a retired key cannot admit a new
// migration, even though the permits it signed historically remain
// verifiable evidence.
func VerifyFencePermit(p *FencePermit, deploymentID string, trust *custody.TrustSet) error {
	if p == nil {
		return ErrPermitMissing
	}
	if p.Schema != FencePermitSchema {
		return fmt.Errorf("fence permit: unsupported schema %q", p.Schema)
	}
	if p.DeploymentID != deploymentID {
		return fmt.Errorf("fence permit: bound to deployment %q, this kernel serves %q", p.DeploymentID, deploymentID)
	}
	if p.TxID == "" || p.FenceID == "" || p.GrantDigest == "" {
		return fmt.Errorf("fence permit: transaction, fence and grant identity are mandatory")
	}
	if p.Epoch < 1 {
		return fmt.Errorf("fence permit: epoch %d is not a real epoch", p.Epoch)
	}
	if p.TargetSeq < 1 || p.TargetSeq <= p.BaseSeq {
		return fmt.Errorf("fence permit: target %d is not above the frozen base %d", p.TargetSeq, p.BaseSeq)
	}
	if trust.Empty() {
		return fmt.Errorf("fence permit: no pinned custodian trust set — a self-declared permit is not evidence")
	}
	pub, err := trust.Resolve(custody.RoleCustodian, deploymentID, p.WitnessFP, p.BaseSeq+1)
	if err != nil {
		return fmt.Errorf("fence permit: %w", err)
	}
	return evidence.VerifyRecordSignature(pub, FencePermitDomain, p.Signature, fencePermitFields(p)...)
}

// VerifyFencePermitHistorical verifies a permit as stored evidence. The
// key must be pinned and the record authentic, but its validity window
// is not re-imposed on history — a permit that was valid when it was
// issued remains verifiable evidence of what was authorized.
func VerifyFencePermitHistorical(p *FencePermit, deploymentID string, trust *custody.TrustSet) error {
	if p == nil {
		return ErrPermitMissing
	}
	if p.Schema != FencePermitSchema {
		return fmt.Errorf("fence permit: unsupported schema %q", p.Schema)
	}
	if p.DeploymentID != deploymentID {
		return fmt.Errorf("fence permit: bound to deployment %q", p.DeploymentID)
	}
	if trust.Empty() {
		return fmt.Errorf("fence permit: no pinned custodian trust set")
	}
	pub, err := trust.ResolveAny(custody.RoleCustodian, deploymentID, p.WitnessFP)
	if err != nil {
		return fmt.Errorf("fence permit: %w", err)
	}
	return evidence.VerifyRecordSignature(pub, FencePermitDomain, p.Signature, fencePermitFields(p)...)
}

// PermitDigest is the stable identity of a fully signed permit — what
// the local transaction stores and what the mutation re-checks.
func PermitDigest(p *FencePermit) (string, error) {
	raw, err := canonicalJSON(p)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// FenceResult is the custodian's signed terminal statement for one
// admitted transaction: it binds the transaction, the local journal
// digest and the epoch's result.
type FenceResult struct {
	Schema       string `json:"schema"`
	State        string `json:"state"`
	DeploymentID string `json:"deployment_id"`
	FenceID      string `json:"fence_id"`
	Epoch        int64  `json:"epoch"`
	TxID         string `json:"tx_id"`
	GrantDigest  string `json:"grant_digest"`
	BaseSeq      int64  `json:"base_seq"`
	ProofDigest  string `json:"proof_digest"`
	JournalSeq   int64  `json:"journal_seq"`
	BeforeDigest string `json:"before_digest"`
	AfterDigest  string `json:"after_digest"`
	ResultDigest string `json:"result_digest"`
	WitnessFP    string `json:"witness_fp"`
	SignerEpoch  int64  `json:"signer_epoch"`
	ClosedAt     string `json:"closed_at"`
	Signature    string `json:"signature,omitempty"`
}

func fenceResultFields(r *FenceResult) []string {
	return []string{
		r.Schema, r.State, r.DeploymentID, r.FenceID, strconv.FormatInt(r.Epoch, 10),
		r.TxID, r.GrantDigest, strconv.FormatInt(r.BaseSeq, 10), r.ProofDigest, strconv.FormatInt(r.JournalSeq, 10),
		r.BeforeDigest, r.AfterDigest, r.ResultDigest, r.WitnessFP,
		strconv.FormatInt(r.SignerEpoch, 10), r.ClosedAt,
	}
}

// SignFenceResult countersigns one finalized transaction.
func SignFenceResult(signer *evidence.Signer, signerEpoch int64, r *FenceResult) (*FenceResult, error) {
	if signer == nil {
		return nil, fmt.Errorf("fence result: no custodian signer")
	}
	r.Schema = FenceResultSchema
	r.WitnessFP = signer.Fingerprint()
	r.SignerEpoch = signerEpoch
	sig, err := signer.SignRecord(FenceResultDomain, fenceResultFields(r)...)
	if err != nil {
		return nil, err
	}
	r.Signature = sig
	return r, nil
}

// VerifyFenceResult checks a finalized transaction under the pinned
// custodian set. A terminal response is accepted only when it carries
// the exact state and bindings the caller's request implied.
func VerifyFenceResult(r *FenceResult, deploymentID string, trust *custody.TrustSet) error {
	if r == nil {
		return ErrWrongTerminalReceipt
	}
	if r.Schema != FenceResultSchema {
		return fmt.Errorf("%w: unsupported schema %q", ErrWrongTerminalReceipt, r.Schema)
	}
	if r.State != MigrationTxCommitted {
		return fmt.Errorf("%w: state %q is not %s", ErrWrongTerminalReceipt, r.State, MigrationTxCommitted)
	}
	if r.DeploymentID != deploymentID {
		return fmt.Errorf("%w: bound to deployment %q, this kernel serves %q", ErrWrongTerminalReceipt, r.DeploymentID, deploymentID)
	}
	if r.TxID == "" || r.FenceID == "" || r.GrantDigest == "" || r.ProofDigest == "" {
		return fmt.Errorf("%w: terminal result does not bind transaction, fence, grant and proof", ErrWrongTerminalReceipt)
	}
	if r.BeforeDigest == "" || r.AfterDigest == "" || r.JournalSeq < 1 {
		return fmt.Errorf("%w: terminal result does not bind the local journal", ErrWrongTerminalReceipt)
	}
	if trust.Empty() {
		return fmt.Errorf("fence result: no pinned custodian trust set")
	}
	pub, err := trust.Resolve(custody.RoleCustodian, deploymentID, r.WitnessFP, r.BaseSeq+1)
	if err != nil {
		return fmt.Errorf("fence result: %w", err)
	}
	return evidence.VerifyRecordSignature(pub, FenceResultDomain, r.Signature, fenceResultFields(r)...)
}

// PrepareRequest asks the witness to admit one migration transaction.
type PrepareRequest struct {
	Schema         string `json:"schema"`
	DeploymentID   string `json:"deployment_id"`
	FenceID        string `json:"fence_id"`
	Epoch          int64  `json:"epoch"`
	GrantDigest    string `json:"grant_digest"`
	BaseSeq        int64  `json:"base_seq"`
	BaseHash       string `json:"base_hash"`
	TargetSeq      int64  `json:"target_seq"`
	PreimageDigest string `json:"preimage_digest"`
	TxID           string `json:"tx_id"`
	KernelFP       string `json:"kernel_fp"`
	IssuedAt       string `json:"issued_at"`
	Signature      string `json:"signature,omitempty"`
}

func prepareRequestFields(r *PrepareRequest) []string {
	return []string{
		r.Schema, r.DeploymentID, r.FenceID, strconv.FormatInt(r.Epoch, 10),
		r.GrantDigest, strconv.FormatInt(r.BaseSeq, 10), r.BaseHash,
		strconv.FormatInt(r.TargetSeq, 10), r.PreimageDigest, r.TxID,
		r.KernelFP, r.IssuedAt,
	}
}

// SignPrepareRequest fills the kernel identity and signature.
func SignPrepareRequest(signer *evidence.Signer, r *PrepareRequest) error {
	if signer == nil {
		return fmt.Errorf("fence prepare: no kernel-relay signer")
	}
	if r.IssuedAt == "" {
		r.IssuedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	r.Schema = FencePrepareSchema
	r.KernelFP = signer.Fingerprint()
	sig, err := signer.SignRecord(FencePrepareDomain, prepareRequestFields(r)...)
	if err != nil {
		return err
	}
	r.Signature = sig
	return nil
}

// VerifyPrepareRequest checks a prepare request under the pinned
// kernel-relay set with current-authority semantics.
func VerifyPrepareRequest(r *PrepareRequest, deploymentID string, trust *custody.TrustSet) error {
	if r == nil {
		return fmt.Errorf("fence prepare: none supplied")
	}
	if r.Schema != FencePrepareSchema {
		return fmt.Errorf("fence prepare: unsupported schema %q", r.Schema)
	}
	if r.DeploymentID != deploymentID {
		return fmt.Errorf("fence prepare: scoped to deployment %q, this witness custodies %q", r.DeploymentID, deploymentID)
	}
	if r.FenceID == "" || r.TxID == "" || r.GrantDigest == "" {
		return fmt.Errorf("fence prepare: fence, transaction and grant identity are mandatory")
	}
	if trust.Empty() {
		return fmt.Errorf("fence prepare: no pinned kernel-relay trust set")
	}
	pub, err := trust.Resolve(custody.RoleKernelRelay, deploymentID, r.KernelFP, r.BaseSeq+1)
	if err != nil {
		return fmt.Errorf("fence prepare: %w", err)
	}
	return evidence.VerifyRecordSignature(pub, FencePrepareDomain, r.Signature, prepareRequestFields(r)...)
}

// FinalizeRequest reports one transaction's committed local outcome.
// Abort carries NoLocalCommit and no digests; finalize carries the full
// journal binding.
type FinalizeRequest struct {
	Schema        string `json:"schema"`
	DeploymentID  string `json:"deployment_id"`
	FenceID       string `json:"fence_id"`
	Epoch         int64  `json:"epoch"`
	TxID          string `json:"tx_id"`
	GrantDigest   string `json:"grant_digest"`
	BaseSeq       int64  `json:"base_seq"`
	NoLocalCommit bool   `json:"no_local_commit,omitempty"`
	ProofDigest   string `json:"proof_digest,omitempty"`
	JournalSeq    int64  `json:"journal_seq,omitempty"`
	BeforeDigest  string `json:"before_digest,omitempty"`
	AfterDigest   string `json:"after_digest,omitempty"`
	ResultDigest  string `json:"result_digest,omitempty"`
	KernelFP      string `json:"kernel_fp"`
	IssuedAt      string `json:"issued_at"`
	Signature     string `json:"signature,omitempty"`
}

func finalizeRequestFields(r *FinalizeRequest) []string {
	noCommit := "0"
	if r.NoLocalCommit {
		noCommit = "1"
	}
	return []string{
		r.Schema, r.DeploymentID, r.FenceID, strconv.FormatInt(r.Epoch, 10), r.TxID,
		r.GrantDigest, strconv.FormatInt(r.BaseSeq, 10), noCommit, r.ProofDigest, strconv.FormatInt(r.JournalSeq, 10),
		r.BeforeDigest, r.AfterDigest, r.ResultDigest, r.KernelFP, r.IssuedAt,
	}
}

// SignFinalizeRequest fills the kernel identity and signature.
func SignFinalizeRequest(signer *evidence.Signer, r *FinalizeRequest) error {
	if signer == nil {
		return fmt.Errorf("fence finalize: no kernel-relay signer")
	}
	if r.IssuedAt == "" {
		r.IssuedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	r.Schema = FenceFinalizeSchema
	r.KernelFP = signer.Fingerprint()
	sig, err := signer.SignRecord(FenceFinalizeDomain, finalizeRequestFields(r)...)
	if err != nil {
		return err
	}
	r.Signature = sig
	return nil
}

// VerifyFinalizeRequest checks a finalize/abort report under the pinned
// kernel-relay set.
func VerifyFinalizeRequest(r *FinalizeRequest, deploymentID string, trust *custody.TrustSet) error {
	if r == nil {
		return fmt.Errorf("fence finalize: none supplied")
	}
	if r.Schema != FenceFinalizeSchema {
		return fmt.Errorf("fence finalize: unsupported schema %q", r.Schema)
	}
	if r.DeploymentID != deploymentID {
		return fmt.Errorf("fence finalize: scoped to deployment %q, this witness custodies %q", r.DeploymentID, deploymentID)
	}
	if r.TxID == "" || r.FenceID == "" || r.GrantDigest == "" {
		return fmt.Errorf("fence finalize: fence, transaction and grant identity are mandatory")
	}
	if trust.Empty() {
		return fmt.Errorf("fence finalize: no pinned kernel-relay trust set")
	}
	pub, err := trust.Resolve(custody.RoleKernelRelay, deploymentID, r.KernelFP, r.BaseSeq+1)
	if err != nil {
		return fmt.Errorf("fence finalize: %w", err)
	}
	return evidence.VerifyRecordSignature(pub, FenceFinalizeDomain, r.Signature, finalizeRequestFields(r)...)
}

// ─── Durable witness-side transaction state ──────────────────────────

const fenceTxDDL = `CREATE TABLE IF NOT EXISTS custody_fence_tx (
	tx_id TEXT PRIMARY KEY,
	deployment_id TEXT NOT NULL,
	fence_id TEXT NOT NULL,
	epoch INTEGER NOT NULL,
	grant_digest TEXT NOT NULL,
	permit_digest TEXT NOT NULL,
	base_seq INTEGER NOT NULL,
	base_hash TEXT NOT NULL,
	target_seq INTEGER NOT NULL,
	preimage_digest TEXT NOT NULL,
	before_digest TEXT NOT NULL DEFAULT '',
	after_digest TEXT NOT NULL DEFAULT '',
	journal_seq INTEGER NOT NULL DEFAULT 0,
	proof_digest TEXT NOT NULL DEFAULT '',
	permit_json TEXT NOT NULL DEFAULT '',
	state TEXT NOT NULL,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	UNIQUE (deployment_id, fence_id, tx_id)
)`

// fenceTxLiveIndex is the schema-level statement of "one admitted
// migration per deployment". The barrier query and the transition
// switches enforce the same rule; the index is what makes it true even
// if a future caller forgets both.
const fenceTxLiveIndex = `CREATE UNIQUE INDEX IF NOT EXISTS custody_fence_tx_one_live
	ON custody_fence_tx(deployment_id) WHERE state = 'ADMITTED'`

// fenceOneLiveIndex is the equivalent rule for epochs.
const fenceOneLiveIndex = `CREATE UNIQUE INDEX IF NOT EXISTS custody_fence_one_live
	ON custody_fence(deployment_id) WHERE state NOT IN ('CLOSED','ABORTED')`

// FenceTx is one admitted migration transaction on the witness side.
type FenceTx struct {
	TxID           string
	DeploymentID   string
	FenceID        string
	Epoch          int64
	GrantDigest    string
	PermitDigest   string
	BaseSeq        int64
	BaseHash       string
	TargetSeq      int64
	PreimageDigest string
	BeforeDigest   string
	AfterDigest    string
	JournalSeq     int64
	ProofDigest    string
	PermitJSON     string
	State          string
	CreatedAt      string
	UpdatedAt      string
}

func fenceTxFrom(ctx context.Context, q fenceQueryer, txID string) (FenceTx, bool, error) {
	var t FenceTx
	err := q.QueryRowContext(ctx,
		`SELECT tx_id, deployment_id, fence_id, epoch, grant_digest, permit_digest,
		        base_seq, base_hash, target_seq, preimage_digest, before_digest,
		        after_digest, journal_seq, proof_digest, permit_json, state, created_at, updated_at
		 FROM custody_fence_tx WHERE tx_id = $1`, txID).
		Scan(&t.TxID, &t.DeploymentID, &t.FenceID, &t.Epoch, &t.GrantDigest, &t.PermitDigest,
			&t.BaseSeq, &t.BaseHash, &t.TargetSeq, &t.PreimageDigest, &t.BeforeDigest,
			&t.AfterDigest, &t.JournalSeq, &t.ProofDigest, &t.PermitJSON, &t.State, &t.CreatedAt, &t.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return FenceTx{}, false, nil
	}
	if err != nil {
		return FenceTx{}, false, err
	}
	return t, true, nil
}

func liveFenceTxFrom(ctx context.Context, q fenceQueryer, deploymentID string) (FenceTx, bool, error) {
	var t FenceTx
	err := q.QueryRowContext(ctx,
		`SELECT tx_id, deployment_id, fence_id, epoch, grant_digest, permit_digest,
		        base_seq, base_hash, target_seq, preimage_digest, before_digest,
		        after_digest, journal_seq, proof_digest, permit_json, state, created_at, updated_at
		 FROM custody_fence_tx WHERE deployment_id = $1 AND state = $2
		 ORDER BY created_at DESC LIMIT 1`, deploymentID, MigrationTxAdmitted).
		Scan(&t.TxID, &t.DeploymentID, &t.FenceID, &t.Epoch, &t.GrantDigest, &t.PermitDigest,
			&t.BaseSeq, &t.BaseHash, &t.TargetSeq, &t.PreimageDigest, &t.BeforeDigest,
			&t.AfterDigest, &t.JournalSeq, &t.ProofDigest, &t.PermitJSON, &t.State, &t.CreatedAt, &t.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return FenceTx{}, false, nil
	}
	if err != nil {
		return FenceTx{}, false, err
	}
	return t, true, nil
}

// PrepareMigration admits one transaction against a live epoch. It is
// the only path that mints mutation authority in v2.
func (l *Ledger) PrepareMigration(ctx context.Context, signer *evidence.Signer, signerEpoch int64, req *PrepareRequest) (*FencePermit, error) {
	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	rec, found, err := fenceFrom(ctx, tx, req.DeploymentID, req.FenceID)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("%w: no fence %s", ErrFenceState, req.FenceID)
	}
	if terminalFenceState(rec.State) {
		return nil, fmt.Errorf("%w: fence %s is %s", ErrFenceState, req.FenceID, rec.State)
	}
	if rec.GrantDigest != req.GrantDigest {
		return nil, fmt.Errorf("%w: fence %s was opened under a different grant", ErrContradiction, req.FenceID)
	}
	if rec.BaseSeq != req.BaseSeq || rec.BaseHash != req.BaseHash {
		return nil, fmt.Errorf("%w: fence froze seq %d (%s), prepare names seq %d (%s)",
			ErrContradiction, rec.BaseSeq, rec.BaseHash, req.BaseSeq, req.BaseHash)
	}
	head, headHash, _, err := headFrom(ctx, tx, req.DeploymentID)
	if err != nil {
		return nil, err
	}
	if head != rec.BaseSeq || headHash != rec.BaseHash {
		return nil, fmt.Errorf("%w: custody moved to seq %d inside fenced epoch %d — the epoch is no longer the state it froze",
			ErrContradiction, head, rec.Epoch)
	}

	// Idempotent re-entry: the same transaction with the same
	// commitments returns the recorded admission. Anything else is a
	// contradiction, never a second authority.
	if existing, ok, err := fenceTxFrom(ctx, tx, req.TxID); err != nil {
		return nil, err
	} else if ok {
		if existing.FenceID != req.FenceID || existing.TargetSeq != req.TargetSeq ||
			existing.PreimageDigest != req.PreimageDigest || existing.GrantDigest != req.GrantDigest {
			return nil, fmt.Errorf("%w: transaction %s exists with different commitments", ErrContradiction, req.TxID)
		}
		if existing.State != MigrationTxAdmitted {
			return nil, fmt.Errorf("%w: transaction %s is %s", ErrPermitConsumed, req.TxID, existing.State)
		}
		// Re-entry returns the recorded permit byte-for-byte. Re-signing
		// would mint a different IssuedAt (and, after a rotation, a
		// different epoch), so a retry would carry a permit digest the
		// local transaction never admitted.
		var permit FencePermit
		if existing.PermitJSON == "" {
			return nil, fmt.Errorf("%w: transaction %s carries no recorded permit", ErrContradiction, req.TxID)
		}
		if err := json.Unmarshal([]byte(existing.PermitJSON), &permit); err != nil {
			return nil, fmt.Errorf("%w: transaction %s permit does not parse: %v", ErrContradiction, req.TxID, err)
		}
		if d, derr := PermitDigest(&permit); derr != nil || d != existing.PermitDigest {
			return nil, fmt.Errorf("%w: transaction %s permit does not match its recorded digest", ErrContradiction, req.TxID)
		}
		return &permit, tx.Commit()
	}

	if live, ok, err := liveFenceTxFrom(ctx, tx, req.DeploymentID); err != nil {
		return nil, err
	} else if ok {
		return nil, fmt.Errorf("%w: transaction %s is already admitted for this deployment", ErrMigrationOutcomeUnknown, live.TxID)
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	permit := &FencePermit{
		DeploymentID: rec.DeploymentID, FenceID: rec.FenceID, Epoch: rec.Epoch,
		TxID: req.TxID, GrantDigest: rec.GrantDigest, BaseSeq: rec.BaseSeq,
		BaseHash: rec.BaseHash, TargetSeq: req.TargetSeq,
		PreimageDigest: req.PreimageDigest, IssuedAt: now,
	}
	if _, err := SignFencePermit(signer, signerEpoch, permit); err != nil {
		return nil, err
	}
	permitRaw, err := json.Marshal(permit)
	if err != nil {
		return nil, err
	}
	permitJSON := string(permitRaw)
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO custody_fence_tx (tx_id, deployment_id, fence_id, epoch, grant_digest,
		 permit_digest, base_seq, base_hash, target_seq, preimage_digest, before_digest,
		 after_digest, journal_seq, proof_digest, permit_json, state, created_at, updated_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'','',0,'',$11,$12,$13,$13)`,
		permit.TxID, permit.DeploymentID, permit.FenceID, permit.Epoch, permit.GrantDigest,
		mustPermitDigest(permit), permit.BaseSeq, permit.BaseHash, permit.TargetSeq,
		permit.PreimageDigest, permitJSON, MigrationTxAdmitted, now); err != nil {
		return nil, fmt.Errorf("fence prepare insert: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE custody_fence SET state = $1 WHERE deployment_id = $2 AND fence_id = $3`,
		FencePrepared, rec.DeploymentID, rec.FenceID); err != nil {
		return nil, fmt.Errorf("fence prepare transition: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return permit, nil
}

func permitFromTx(t FenceTx) *FencePermit {
	return &FencePermit{
		DeploymentID: t.DeploymentID, FenceID: t.FenceID, Epoch: t.Epoch,
		TxID: t.TxID, GrantDigest: t.GrantDigest, BaseSeq: t.BaseSeq,
		BaseHash: t.BaseHash, TargetSeq: t.TargetSeq, PreimageDigest: t.PreimageDigest,
	}
}

func mustPermitDigest(p *FencePermit) string {
	d, err := PermitDigest(p)
	if err != nil {
		return ""
	}
	return d
}

// MarkRecoveryRequired quarantines an epoch whose outcome the ordinary
// path cannot reconcile. It never releases the submission barrier: the
// state is non-terminal on purpose, so custody stays frozen until an
// authorized recovery resolves it.
func (l *Ledger) MarkRecoveryRequired(ctx context.Context, deploymentID, fenceID, reason string) error {
	_, err := l.db.ExecContext(ctx,
		`UPDATE custody_fence SET state = $1 WHERE deployment_id = $2 AND fence_id = $3
		 AND state NOT IN ($4, $5)`,
		FenceRecoveryRequired, deploymentID, fenceID, FenceClosed, FenceAborted)
	if err != nil {
		return fmt.Errorf("fence recovery marker: %w", err)
	}
	return nil
}

// FinalizeMigration records one transaction's committed local outcome
// and returns the signed terminal result. It is idempotent for the same
// journal binding and a contradiction for a different one.
func (l *Ledger) FinalizeMigration(ctx context.Context, signer *evidence.Signer, signerEpoch int64, req *FinalizeRequest) (*FenceResult, error) {
	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	rec, found, err := fenceFrom(ctx, tx, req.DeploymentID, req.FenceID)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("%w: no fence %s", ErrFenceState, req.FenceID)
	}
	if rec.State == FenceAborted {
		return nil, fmt.Errorf("%w: fence %s was aborted", ErrFenceState, req.FenceID)
	}
	if rec.State == FenceClosed && rec.ResultDigest != req.ResultDigest {
		return nil, fmt.Errorf("%w: fence %s closed with a different result", ErrContradiction, req.FenceID)
	}
	t, ok, err := fenceTxFrom(ctx, tx, req.TxID)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("%w: transaction %s was never admitted", ErrPermitMissing, req.TxID)
	}
	if t.FenceID != req.FenceID || t.GrantDigest != req.GrantDigest {
		return nil, fmt.Errorf("%w: transaction %s is bound to a different fence or grant", ErrContradiction, req.TxID)
	}
	if t.State == MigrationTxAborted {
		return nil, fmt.Errorf("%w: transaction %s was aborted", ErrFenceState, req.TxID)
	}
	if t.State == MigrationTxCommitted {
		if t.ProofDigest != req.ProofDigest || t.AfterDigest != req.AfterDigest {
			return nil, fmt.Errorf("%w: transaction %s already committed a different journal", ErrContradiction, req.TxID)
		}
		result, err := SignFenceResult(signer, signerEpoch, resultFromTx(t, rec.ResultDigest))
		if err != nil {
			return nil, err
		}
		return result, tx.Commit()
	}
	if req.ProofDigest == "" || req.BeforeDigest == "" || req.AfterDigest == "" || req.JournalSeq < 1 {
		return nil, fmt.Errorf("%w: finalize must bind the local journal and proof", ErrMigrationOutcomeUnknown)
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx,
		`UPDATE custody_fence_tx SET state = $1, before_digest = $2, after_digest = $3,
		 journal_seq = $4, proof_digest = $5, updated_at = $6 WHERE tx_id = $7 AND state = $8`,
		MigrationTxCommitted, req.BeforeDigest, req.AfterDigest, req.JournalSeq,
		req.ProofDigest, now, req.TxID, MigrationTxAdmitted); err != nil {
		return nil, fmt.Errorf("fence finalize transition: %w", err)
	}
	t.State, t.BeforeDigest, t.AfterDigest = MigrationTxCommitted, req.BeforeDigest, req.AfterDigest
	t.JournalSeq, t.ProofDigest = req.JournalSeq, req.ProofDigest
	result, err := SignFenceResult(signer, signerEpoch, resultFromTx(t, req.ResultDigest))
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

func resultFromTx(t FenceTx, resultDigest string) *FenceResult {
	return &FenceResult{
		State: MigrationTxCommitted, DeploymentID: t.DeploymentID, FenceID: t.FenceID,
		Epoch: t.Epoch, TxID: t.TxID, GrantDigest: t.GrantDigest, BaseSeq: t.BaseSeq,
		ProofDigest: t.ProofDigest, JournalSeq: t.JournalSeq,
		BeforeDigest: t.BeforeDigest, AfterDigest: t.AfterDigest,
		ResultDigest: resultDigest,
	}
}

// AbortMigration releases one admitted transaction that provably never
// committed locally. The local permit must already be revoked, and the
// witness refuses while any transaction is COMMITTED or the epoch
// carries an unresolved outcome.
func (l *Ledger) AbortMigration(ctx context.Context, req *FinalizeRequest) (FenceRecord, error) {
	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return FenceRecord{}, err
	}
	defer tx.Rollback()

	rec, found, err := fenceFrom(ctx, tx, req.DeploymentID, req.FenceID)
	if err != nil {
		return FenceRecord{}, err
	}
	if !found {
		return FenceRecord{}, fmt.Errorf("%w: no fence %s", ErrFenceState, req.FenceID)
	}
	if terminalFenceState(rec.State) {
		return FenceRecord{}, fmt.Errorf("%w: fence %s is %s", ErrFenceState, req.FenceID, rec.State)
	}
	if rec.GrantDigest != req.GrantDigest {
		return FenceRecord{}, fmt.Errorf("%w: fence %s was opened under a different grant", ErrFenceState, req.FenceID)
	}
	t, ok, err := fenceTxFrom(ctx, tx, req.TxID)
	if err != nil {
		return FenceRecord{}, err
	}
	if !ok {
		return FenceRecord{}, fmt.Errorf("%w: transaction %s was never admitted", ErrPermitMissing, req.TxID)
	}
	if t.State == MigrationTxCommitted {
		return FenceRecord{}, fmt.Errorf("%w: transaction %s committed a local rewrite — close the epoch, never abort it",
			ErrMigrationOutcomeUnknown, req.TxID)
	}
	if t.State == MigrationTxAborted {
		return rec, tx.Commit()
	}
	if !req.NoLocalCommit {
		return FenceRecord{}, fmt.Errorf("%w: abort requires the kernel's no-local-commit attestation", ErrMigrationOutcomeUnknown)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx,
		`UPDATE custody_fence_tx SET state = $1, updated_at = $2 WHERE tx_id = $3 AND state = $4`,
		MigrationTxAborted, now, req.TxID, MigrationTxAdmitted); err != nil {
		return FenceRecord{}, fmt.Errorf("fence abort transition: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE custody_fence SET state = $1, closed_at = $2 WHERE deployment_id = $3 AND fence_id = $4`,
		FenceAborted, now, req.DeploymentID, req.FenceID); err != nil {
		return FenceRecord{}, fmt.Errorf("fence abort: %w", err)
	}
	rec.State, rec.ClosedAt = FenceAborted, now
	if err := tx.Commit(); err != nil {
		return FenceRecord{}, err
	}
	return rec, nil
}

// ─── Local one-shot permit state ─────────────────────────────────────

const migrationTxDDL = `CREATE TABLE IF NOT EXISTS custody_migration_tx (
	tx_id TEXT PRIMARY KEY,
	deployment_id TEXT NOT NULL,
	fence_id TEXT NOT NULL,
	witness_epoch INTEGER NOT NULL,
	grant_digest TEXT NOT NULL,
	permit_digest TEXT NOT NULL,
	base_seq INTEGER NOT NULL,
	base_hash TEXT NOT NULL,
	target_seq INTEGER NOT NULL,
	preimage_digest TEXT NOT NULL,
	before_digest TEXT NOT NULL DEFAULT '',
	after_digest TEXT NOT NULL DEFAULT '',
	journal_seq INTEGER NOT NULL DEFAULT 0,
	proof_digest TEXT NOT NULL DEFAULT '',
	state TEXT NOT NULL,
	last_error TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
)`

const migrationTxLiveIndex = `CREATE UNIQUE INDEX IF NOT EXISTS custody_migration_tx_one_live
	ON custody_migration_tx(deployment_id) WHERE state IN ('ADMITTED','LOCAL_COMMITTED')`

// MigrationTx is the kernel's durable record of one admitted permit.
type MigrationTx struct {
	TxID           string `json:"tx_id"`
	DeploymentID   string `json:"deployment_id"`
	FenceID        string `json:"fence_id"`
	WitnessEpoch   int64  `json:"witness_epoch"`
	GrantDigest    string `json:"grant_digest"`
	PermitDigest   string `json:"permit_digest"`
	BaseSeq        int64  `json:"base_seq"`
	BaseHash       string `json:"base_hash"`
	TargetSeq      int64  `json:"target_seq"`
	PreimageDigest string `json:"preimage_digest"`
	BeforeDigest   string `json:"before_digest,omitempty"`
	AfterDigest    string `json:"after_digest,omitempty"`
	JournalSeq     int64  `json:"journal_seq,omitempty"`
	ProofDigest    string `json:"proof_digest,omitempty"`
	State          string `json:"state"`
	LastError      string `json:"last_error,omitempty"`
	CreatedAt      string `json:"created_at"`
	UpdatedAt      string `json:"updated_at"`
}

// AdmitMigration records the permit durably before any mutation runs.
// A crash after the witness admitted and before this row exists leaves
// a witness-only transaction that recovery can abort; a crash after
// this row exists leaves a local ADMITTED transaction recovery must
// revoke before asking the witness to abort.
func (o *Outbox) AdmitMigration(ctx context.Context, permit *FencePermit) (MigrationTx, error) {
	if permit == nil {
		return MigrationTx{}, ErrPermitMissing
	}
	digest, err := PermitDigest(permit)
	if err != nil {
		return MigrationTx{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := o.db.ExecContext(ctx,
		`INSERT INTO custody_migration_tx (tx_id, deployment_id, fence_id, witness_epoch,
		 grant_digest, permit_digest, base_seq, base_hash, target_seq, preimage_digest,
		 state, created_at, updated_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$12)
		 ON CONFLICT(tx_id) DO NOTHING`,
		permit.TxID, permit.DeploymentID, permit.FenceID, permit.Epoch, permit.GrantDigest,
		digest, permit.BaseSeq, permit.BaseHash, permit.TargetSeq, permit.PreimageDigest,
		LocalTxAdmitted, now); err != nil {
		return MigrationTx{}, fmt.Errorf("migration tx admit: %w", err)
	}
	rec, err := o.MigrationTx(ctx, permit.TxID)
	if err != nil {
		return MigrationTx{}, err
	}
	// A second admission of the same identity is idempotent only when it
	// is the same admission. Different commitments are a contradiction,
	// never a silent no-op.
	if rec.PermitDigest != digest {
		return MigrationTx{}, fmt.Errorf("%w: local transaction %s was admitted under a different permit",
			ErrContradiction, permit.TxID)
	}
	return rec, nil
}

// MigrationTx reads one local transaction row.
func (o *Outbox) MigrationTx(ctx context.Context, txID string) (MigrationTx, error) {
	var t MigrationTx
	err := o.db.QueryRowContext(ctx,
		`SELECT tx_id, deployment_id, fence_id, witness_epoch, grant_digest, permit_digest,
		        base_seq, base_hash, target_seq, preimage_digest, before_digest, after_digest,
		        journal_seq, proof_digest, state, last_error, created_at, updated_at
		 FROM custody_migration_tx WHERE tx_id = $1`, txID).
		Scan(&t.TxID, &t.DeploymentID, &t.FenceID, &t.WitnessEpoch, &t.GrantDigest,
			&t.PermitDigest, &t.BaseSeq, &t.BaseHash, &t.TargetSeq, &t.PreimageDigest,
			&t.BeforeDigest, &t.AfterDigest, &t.JournalSeq, &t.ProofDigest, &t.State,
			&t.LastError, &t.CreatedAt, &t.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return MigrationTx{}, fmt.Errorf("%w: no local transaction %s", ErrPermitMissing, txID)
	}
	if err != nil {
		return MigrationTx{}, err
	}
	return t, nil
}

// MigrationTxs lists local transactions, newest first — the operator
// surface for deciding whether a migration is still in flight.
func (o *Outbox) MigrationTxs(ctx context.Context, limit int) ([]MigrationTx, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := o.db.QueryContext(ctx,
		`SELECT tx_id, deployment_id, fence_id, witness_epoch, grant_digest, permit_digest,
		        base_seq, base_hash, target_seq, preimage_digest, before_digest, after_digest,
		        journal_seq, proof_digest, state, last_error, created_at, updated_at
		 FROM custody_migration_tx ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MigrationTx
	for rows.Next() {
		var t MigrationTx
		if err := rows.Scan(&t.TxID, &t.DeploymentID, &t.FenceID, &t.WitnessEpoch,
			&t.GrantDigest, &t.PermitDigest, &t.BaseSeq, &t.BaseHash, &t.TargetSeq,
			&t.PreimageDigest, &t.BeforeDigest, &t.AfterDigest, &t.JournalSeq,
			&t.ProofDigest, &t.State, &t.LastError, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// MigrationTxsForFence lists the local transactions of one epoch.
func (o *Outbox) MigrationTxsForFence(ctx context.Context, fenceID string) ([]MigrationTx, error) {
	rows, err := o.db.QueryContext(ctx,
		`SELECT tx_id, deployment_id, fence_id, witness_epoch, grant_digest, permit_digest,
		        base_seq, base_hash, target_seq, preimage_digest, before_digest, after_digest,
		        journal_seq, proof_digest, state, last_error, created_at, updated_at
		 FROM custody_migration_tx WHERE fence_id = $1 ORDER BY created_at`, fenceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MigrationTx
	for rows.Next() {
		var t MigrationTx
		if err := rows.Scan(&t.TxID, &t.DeploymentID, &t.FenceID, &t.WitnessEpoch,
			&t.GrantDigest, &t.PermitDigest, &t.BaseSeq, &t.BaseHash, &t.TargetSeq,
			&t.PreimageDigest, &t.BeforeDigest, &t.AfterDigest, &t.JournalSeq,
			&t.ProofDigest, &t.State, &t.LastError, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// RevokePermit durably withdraws an admitted permit before the witness
// is asked to abort. It refuses a permit whose local commit already
// happened: that transaction must be finalized, never revoked.
func (o *Outbox) RevokePermit(ctx context.Context, txID, reason string) error {
	res, err := o.db.ExecContext(ctx,
		`UPDATE custody_migration_tx SET state = $1, last_error = $2, updated_at = $3
		 WHERE tx_id = $4 AND state = $5`,
		LocalTxRevoked, reason, time.Now().UTC().Format(time.RFC3339Nano), txID, LocalTxAdmitted)
	if err != nil {
		return fmt.Errorf("migration tx revoke: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("%w: transaction %s is not in an abortable local state", ErrPermitConsumed, txID)
	}
	return nil
}

// CompleteMigrationTx records the witness's terminal result locally.
func (o *Outbox) CompleteMigrationTx(ctx context.Context, result *FenceResult) error {
	if result == nil {
		return fmt.Errorf("migration tx complete: no result")
	}
	state := LocalTxFinalized
	if result.State != MigrationTxCommitted {
		state = LocalTxAborted
	}
	res, err := o.db.ExecContext(ctx,
		`UPDATE custody_migration_tx SET state = $1, after_digest = $2, proof_digest = $3,
		 updated_at = $4 WHERE tx_id = $5`,
		state, result.AfterDigest, result.ProofDigest,
		time.Now().UTC().Format(time.RFC3339Nano), result.TxID)
	if err != nil {
		return fmt.Errorf("migration tx complete: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("migration tx complete: unknown transaction %s", result.TxID)
	}
	return nil
}

// ─── Kernel-side v2 client ───────────────────────────────────────────

// Prepare asks the witness to admit one target and returns the verified
// permit. The permit is never returned unverified.
func (f *FenceClient) Prepare(ctx context.Context, fence FenceReceipt, targetSeq int64, preimageDigest string) (FencePermit, error) {
	if f.Client == nil || f.Signer == nil {
		return FencePermit{}, fmt.Errorf("fence prepare: client and kernel signer are required")
	}
	if fence.FenceID == "" {
		return FencePermit{}, fmt.Errorf("fence prepare: no open epoch supplied")
	}
	txID := FenceTxIDFor(f.DeploymentID, fence.FenceID, targetSeq, preimageDigest)
	req := &PrepareRequest{
		DeploymentID: f.DeploymentID, FenceID: fence.FenceID, Epoch: fence.Epoch,
		GrantDigest: f.GrantDigest, BaseSeq: fence.BaseSeq, BaseHash: fence.BaseHash,
		TargetSeq: targetSeq, PreimageDigest: preimageDigest, TxID: txID,
	}
	if err := SignPrepareRequest(f.Signer, req); err != nil {
		return FencePermit{}, err
	}
	permit, err := f.Client.PrepareFence(ctx, req)
	if err != nil {
		return FencePermit{}, err
	}
	if err := VerifyFencePermit(permit, f.DeploymentID, f.CustodianTrust); err != nil {
		return FencePermit{}, fmt.Errorf("fence prepare: permit unverifiable: %w", err)
	}
	if permit.TxID != txID || permit.TargetSeq != targetSeq || permit.PreimageDigest != preimageDigest {
		return FencePermit{}, fmt.Errorf("%w: permit does not bind the requested transaction", ErrWrongTerminalReceipt)
	}
	if permit.GrantDigest != f.GrantDigest {
		return FencePermit{}, fmt.Errorf("%w: permit binds grant %s, this run holds %s", ErrWrongTerminalReceipt, permit.GrantDigest, f.GrantDigest)
	}
	if permit.FenceID != fence.FenceID || permit.BaseSeq != fence.BaseSeq || permit.BaseHash != fence.BaseHash {
		return FencePermit{}, fmt.Errorf("%w: permit does not bind this epoch", ErrWrongTerminalReceipt)
	}
	return *permit, nil
}

// Finalize reports a committed local journal and returns the verified
// terminal result.
func (f *FenceClient) Finalize(ctx context.Context, permit FencePermit, in FinalizeReport) (FenceResult, error) {
	if f.Client == nil || f.Signer == nil {
		return FenceResult{}, fmt.Errorf("fence finalize: client and kernel signer are required")
	}
	req := &FinalizeRequest{
		DeploymentID: permit.DeploymentID, FenceID: permit.FenceID, Epoch: permit.Epoch,
		TxID: permit.TxID, GrantDigest: permit.GrantDigest, BaseSeq: permit.BaseSeq,
		ProofDigest: in.ProofDigest, JournalSeq: in.JournalSeq,
		BeforeDigest: in.BeforeDigest, AfterDigest: in.AfterDigest,
		ResultDigest: in.ResultDigest,
	}
	if err := SignFinalizeRequest(f.Signer, req); err != nil {
		return FenceResult{}, err
	}
	result, err := f.Client.FinalizeFence(ctx, req)
	if err != nil {
		return FenceResult{}, err
	}
	if err := VerifyFenceResult(result, f.DeploymentID, f.CustodianTrust); err != nil {
		return FenceResult{}, err
	}
	if result.TxID != permit.TxID || result.ProofDigest != in.ProofDigest ||
		result.AfterDigest != in.AfterDigest || result.JournalSeq != in.JournalSeq {
		return FenceResult{}, fmt.Errorf("%w: result does not bind the reported journal", ErrWrongTerminalReceipt)
	}
	return *result, nil
}

// UnfinalizedMigrationTx returns the local transaction of a fence whose
// rewrite committed but whose witness record was never finalized. That
// is the state a crash between the local commit and the finalize RPC
// leaves, and it must be resolved by finalizing, never by aborting.
func (o *Outbox) UnfinalizedMigrationTx(ctx context.Context, fenceID string) (MigrationTx, bool, error) {
	txs, err := o.MigrationTxsForFence(ctx, fenceID)
	if err != nil {
		return MigrationTx{}, false, err
	}
	for _, t := range txs {
		if t.State == LocalTxLocalCommitted {
			return t, true, nil
		}
	}
	return MigrationTx{}, false, nil
}

// FinalizeLocal reports a locally committed transaction from its
// durable row. It is the resume path: the permit document may be gone
// (or its grant expired), but the transaction identity and the journal
// binding are durable, and the witness finalizes on those.
func (f *FenceClient) FinalizeLocal(ctx context.Context, tx MigrationTx) (FenceResult, error) {
	if f.Client == nil || f.Signer == nil {
		return FenceResult{}, fmt.Errorf("fence finalize: client and kernel signer are required")
	}
	req := &FinalizeRequest{
		DeploymentID: tx.DeploymentID, FenceID: tx.FenceID, Epoch: tx.WitnessEpoch,
		TxID: tx.TxID, GrantDigest: tx.GrantDigest, BaseSeq: tx.BaseSeq,
		ProofDigest: tx.ProofDigest, JournalSeq: tx.JournalSeq,
		BeforeDigest: tx.BeforeDigest, AfterDigest: tx.AfterDigest,
	}
	if err := SignFinalizeRequest(f.Signer, req); err != nil {
		return FenceResult{}, err
	}
	result, err := f.Client.FinalizeFence(ctx, req)
	if err != nil {
		return FenceResult{}, err
	}
	if err := VerifyFenceResult(result, f.DeploymentID, f.CustodianTrust); err != nil {
		return FenceResult{}, err
	}
	if result.TxID != tx.TxID || result.ProofDigest != tx.ProofDigest || result.AfterDigest != tx.AfterDigest {
		return FenceResult{}, fmt.Errorf("%w: result does not bind the local transaction", ErrWrongTerminalReceipt)
	}
	return *result, nil
}

// AbortMigration asks the witness to release an admitted transaction
// that provably never committed locally.
func (f *FenceClient) AbortMigration(ctx context.Context, permit FencePermit, reason string) (FenceReceipt, error) {
	if f.Client == nil || f.Signer == nil {
		return FenceReceipt{}, fmt.Errorf("fence abort: client and kernel signer are required")
	}
	req := &FinalizeRequest{
		DeploymentID: permit.DeploymentID, FenceID: permit.FenceID, Epoch: permit.Epoch,
		TxID: permit.TxID, GrantDigest: permit.GrantDigest, BaseSeq: permit.BaseSeq, NoLocalCommit: true,
	}
	if err := SignFinalizeRequest(f.Signer, req); err != nil {
		return FenceReceipt{}, err
	}
	rec, err := f.Client.AbortMigrationFence(ctx, req)
	if err != nil {
		return FenceReceipt{}, err
	}
	if err := VerifyFenceReceipt(rec, f.DeploymentID, f.CustodianTrust); err != nil {
		return FenceReceipt{}, err
	}
	if rec.State != FenceAborted {
		return FenceReceipt{}, fmt.Errorf("%w: abort returned state %q", ErrWrongTerminalReceipt, rec.State)
	}
	if rec.FenceID != permit.FenceID {
		return FenceReceipt{}, fmt.Errorf("%w: abort returned fence %q", ErrWrongTerminalReceipt, rec.FenceID)
	}
	return *rec, nil
}

// FinalizeReport is the local journal binding a finalize carries.
type FinalizeReport struct {
	ProofDigest  string
	JournalSeq   int64
	BeforeDigest string
	AfterDigest  string
	ResultDigest string
}

// FenceTxIDFor is the deterministic identity of one admitted
// transaction. It binds the epoch, the target and the preimage the
// target held when the permit was minted, so a retry addresses the same
// transaction and a different preimage is a different transaction.
func FenceTxIDFor(deploymentID, fenceID string, targetSeq int64, preimageDigest string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%d\x00%s", deploymentID, fenceID, targetSeq, preimageDigest)))
	return hex.EncodeToString(sum[:])
}
