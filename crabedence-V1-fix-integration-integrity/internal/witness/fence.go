package witness

// RC8.3 integrity closure — witness-fenced migration epochs.
//
// A signed witness checkpoint proves the custodian's state at one
// instant. It does not prove that no submission is still in flight:
// the sender may already have put an older envelope on the wire, and
// the witness will accept it as long as it extends its own head. A
// migration that rewrites a suffix under such a checkpoint can commit
// a rewrite of rows the witness is about to custody under their old
// bytes — the two stores then hold different records at the same
// sequence, and custody is permanently forked.
//
// The fence closes that window structurally rather than by timing:
//
//   - The kernel asks the witness to open a migration epoch, naming the
//     custody head it observed and the operator grant it acts under.
//   - The witness admits the fence only if the observed head still
//     equals its own, atomically, and then refuses every submission for
//     that deployment until the fence closes.
//   - The witness returns a signed fence receipt. That receipt — not the
//     bare checkpoint — is what the migration library binds into its
//     proof and journal, so a migration can only exist under an epoch
//     the custodian itself declared frozen.
//   - Closing the fence requires the same grant, so a fence cannot be
//     released by an unrelated actor, and an aborted fence is refused
//     if custody moved while it was open.
//
// A fence is durable: a witness restart leaves it open, so a crashed
// kernel cannot silently resume submitting while a half-finished
// rewrite exists on the other side.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/openclaw/crabbox/internal/custody"
	"github.com/openclaw/crabbox/internal/evidence"
)

// Fence protocol ops.
const (
	OpFenceBegin  = "fence-begin"
	OpFenceEnd    = "fence-end"
	OpFenceAbort  = "fence-abort"
	OpFenceStatus = "fence-status"
	// OpFenceAbortTx releases one admitted v2 transaction.
	OpFenceAbortTx = "fence-abort-tx"
)

// Fence record schemas.
const (
	FenceRequestSchema = "custody-fence-request-v1"
	FenceReceiptSchema = "custody-fence-receipt-v1"
)

// Signed-record domains — distinct from the ack, checkpoint, envelope,
// grant, and migration-proof domains, so a fence record can never be
// presented as any of them.
const (
	FenceRequestDomain = "custody-witness-fence-request-v1\x00"
	FenceReceiptDomain = "custody-witness-fence-receipt-v1\x00"
)

// Fence states. OPEN is the v1 epoch a fence-begin creates; PREPARED
// and FINALIZING are the v2 states an admitted transaction passes
// through; RECOVERY_REQUIRED is the quarantined state an unreconciled
// outcome lands in. CLOSED and ABORTED are terminal and immutable.
const (
	FenceOpen             = "OPEN"
	FencePrepared         = "PREPARED"
	FenceFinalizing       = "FINALIZING"
	FenceClosed           = "CLOSED"
	FenceAborted          = "ABORTED"
	FenceRecoveryRequired = "RECOVERY_REQUIRED"
)

// terminalFenceState reports whether an epoch admits no further work.
// Every barrier and transition consults this rather than an allowlist
// of live states, so a state added later is non-terminal by default.
func terminalFenceState(state string) bool {
	return state == FenceClosed || state == FenceAborted
}

// Typed fence refusals. Callers must treat each as a refusal, never as
// a retryable transport failure.
var (
	// ErrFenced — the deployment is inside a migration epoch and admits
	// no submissions.
	ErrFenced = errors.New("witness: deployment is fenced for migration")
	// ErrFenceActive — a different migration epoch is already open.
	ErrFenceActive = errors.New("witness: a migration fence is already open for this deployment")
	// ErrStaleFenceBase — the head the caller observed is no longer the
	// custody head, so the fence would freeze a state the caller has not
	// seen.
	ErrStaleFenceBase = errors.New("witness: fence base does not match the custody head")
	// ErrFenceState — the fence is not in the state the operation
	// requires.
	ErrFenceState = errors.New("witness: fence state violation")
)

// FenceRequest is the kernel's signed request to open, close, or abort
// a migration epoch. It is signed by the deployment's kernel-relay key,
// so the witness knows which kernel identity is asking, and it carries
// the operator grant digest so the epoch is bound to one authorization.
type FenceRequest struct {
	Schema       string `json:"schema"`
	Op           string `json:"op"`
	DeploymentID string `json:"deployment_id"`
	FenceID      string `json:"fence_id"`
	GrantDigest  string `json:"grant_digest"`
	BaseSeq      int64  `json:"base_seq"`
	BaseHash     string `json:"base_hash"`
	ResultDigest string `json:"result_digest,omitempty"`
	KernelFP     string `json:"kernel_fp"`
	IssuedAt     string `json:"issued_at"`
	Signature    string `json:"signature,omitempty"`
}

func fenceRequestFields(r *FenceRequest) []string {
	return []string{
		r.Schema,
		r.Op,
		r.DeploymentID,
		r.FenceID,
		r.GrantDigest,
		strconv.FormatInt(r.BaseSeq, 10),
		r.BaseHash,
		r.ResultDigest,
		r.KernelFP,
		r.IssuedAt,
	}
}

// FenceIDFor is the deterministic identity of one migration epoch. It
// binds the deployment, the operator authorization, and the exact
// custody head the epoch freezes, so a retry under the same grant
// addresses the same fence and cannot silently freeze a different head.
func FenceIDFor(deploymentID, grantDigest string, baseSeq int64, baseHash string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%d\x00%s", deploymentID, grantDigest, baseSeq, baseHash)))
	return hex.EncodeToString(sum[:])
}

// SignFenceRequest fills the kernel identity and signature.
func SignFenceRequest(signer *evidence.Signer, r *FenceRequest) error {
	if signer == nil {
		return fmt.Errorf("fence request: no kernel-relay signer")
	}
	if r.IssuedAt == "" {
		r.IssuedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	r.Schema = FenceRequestSchema
	r.KernelFP = signer.Fingerprint()
	sig, err := signer.SignRecord(FenceRequestDomain, fenceRequestFields(r)...)
	if err != nil {
		return err
	}
	r.Signature = sig
	return nil
}

// VerifyFenceRequest checks a fence request under the pinned
// kernel-relay set for this deployment. A request from an unpinned key
// is not a kernel act.
func VerifyFenceRequest(r *FenceRequest, deploymentID string, kernelTrust *custody.TrustSet) error {
	if r == nil {
		return fmt.Errorf("fence request: none supplied")
	}
	if r.Schema != FenceRequestSchema {
		return fmt.Errorf("fence request: unsupported schema %q", r.Schema)
	}
	switch r.Op {
	case OpFenceBegin, OpFenceEnd, OpFenceAbort:
	default:
		return fmt.Errorf("fence request: unsupported op %q", r.Op)
	}
	if r.DeploymentID != deploymentID {
		return fmt.Errorf("fence request: scoped to deployment %q, this witness custodies %q", r.DeploymentID, deploymentID)
	}
	if r.FenceID == "" || r.GrantDigest == "" {
		return fmt.Errorf("fence request: fence identity and grant digest are mandatory")
	}
	if kernelTrust.Empty() {
		return fmt.Errorf("fence request: no pinned kernel-relay trust set — a self-declared kernel is not evidence")
	}
	pub, err := kernelTrust.Resolve(custody.RoleKernelRelay, deploymentID, r.KernelFP, r.BaseSeq+1)
	if err != nil {
		return fmt.Errorf("fence request: %w", err)
	}
	return evidence.VerifyRecordSignature(pub, FenceRequestDomain, r.Signature, fenceRequestFields(r)...)
}

// FenceReceipt is the witness's signed statement that a migration
// epoch is (or was) open at a specific custody head. This is the
// authority a migration binds — a bare checkpoint cannot make the same
// claim, because it says nothing about what may still arrive.
type FenceReceipt struct {
	Schema       string `json:"schema"`
	State        string `json:"state"`
	DeploymentID string `json:"deployment_id"`
	FenceID      string `json:"fence_id"`
	Epoch        int64  `json:"epoch"`
	BaseSeq      int64  `json:"base_seq"`
	BaseHash     string `json:"base_hash"`
	GrantDigest  string `json:"grant_digest"`
	ResultDigest string `json:"result_digest,omitempty"`
	WitnessFP    string `json:"witness_fp"`
	SignerEpoch  int64  `json:"signer_epoch"`
	OpenedAt     string `json:"opened_at"`
	ClosedAt     string `json:"closed_at,omitempty"`
	// LiveTxID is set only on an inspection response: it names the
	// transaction currently admitted in the epoch, if any. It is not
	// covered by the receipt signature because a status reply is not an
	// authority.
	LiveTxID  string `json:"live_tx_id,omitempty"`
	Signature string `json:"signature,omitempty"`
}

func fenceReceiptFields(r *FenceReceipt) []string {
	return []string{
		r.Schema,
		r.State,
		r.DeploymentID,
		r.FenceID,
		strconv.FormatInt(r.Epoch, 10),
		strconv.FormatInt(r.BaseSeq, 10),
		r.BaseHash,
		r.GrantDigest,
		r.ResultDigest,
		r.WitnessFP,
		strconv.FormatInt(r.SignerEpoch, 10),
		r.OpenedAt,
		r.ClosedAt,
	}
}

// SignFenceReceipt produces the custodian's countersignature over a
// fence state.
func SignFenceReceipt(signer *evidence.Signer, signerEpoch int64, r *FenceReceipt) (*FenceReceipt, error) {
	if signer == nil {
		return nil, fmt.Errorf("fence receipt: no custodian signer")
	}
	r.Schema = FenceReceiptSchema
	r.WitnessFP = signer.Fingerprint()
	r.SignerEpoch = signerEpoch
	sig, err := signer.SignRecord(FenceReceiptDomain, fenceReceiptFields(r)...)
	if err != nil {
		return nil, err
	}
	r.Signature = sig
	return r, nil
}

// VerifyFenceReceipt verifies a fence receipt under the pinned
// custodian set for this deployment. This is the library-boundary
// check: a migration must never bind a fence it did not verify.
func VerifyFenceReceipt(r *FenceReceipt, deploymentID string, custodianTrust *custody.TrustSet) error {
	if r == nil {
		return fmt.Errorf("fence receipt: none supplied")
	}
	if r.Schema != FenceReceiptSchema {
		return fmt.Errorf("fence receipt: unsupported schema %q", r.Schema)
	}
	switch r.State {
	case FenceOpen, FenceClosed, FenceAborted:
	default:
		return fmt.Errorf("fence receipt: unknown state %q", r.State)
	}
	if r.DeploymentID != deploymentID {
		return fmt.Errorf("fence receipt: bound to deployment %q, this kernel serves %q", r.DeploymentID, deploymentID)
	}
	if r.FenceID == "" {
		return fmt.Errorf("fence receipt: no fence identity")
	}
	if r.GrantDigest == "" {
		return fmt.Errorf("fence receipt: no operator grant binding")
	}
	if r.Epoch < 1 {
		return fmt.Errorf("fence receipt: epoch %d is not a real epoch", r.Epoch)
	}
	if custodianTrust.Empty() {
		return fmt.Errorf("fence receipt: no pinned custodian trust set — a self-declared fence is not evidence")
	}
	pub, err := custodianTrust.Resolve(custody.RoleCustodian, deploymentID, r.WitnessFP, r.BaseSeq+1)
	if err != nil {
		return fmt.Errorf("fence receipt: %w", err)
	}
	return evidence.VerifyRecordSignature(pub, FenceReceiptDomain, r.Signature, fenceReceiptFields(r)...)
}

// VerifyFenceReceiptHistorical verifies a fence receipt as stored
// evidence: the key must have been pinned and authentic, and the record
// must verify, but the key's validity window is not re-imposed on
// history. Live acceptance must use VerifyFenceReceipt.
func VerifyFenceReceiptHistorical(r *FenceReceipt, deploymentID string, custodianTrust *custody.TrustSet) error {
	if r == nil {
		return fmt.Errorf("fence receipt: none supplied")
	}
	if r.Schema != FenceReceiptSchema {
		return fmt.Errorf("fence receipt: unsupported schema %q", r.Schema)
	}
	if r.DeploymentID != deploymentID {
		return fmt.Errorf("fence receipt: bound to deployment %q, this kernel serves %q", r.DeploymentID, deploymentID)
	}
	if custodianTrust.Empty() {
		return fmt.Errorf("fence receipt: no pinned custodian trust set")
	}
	pub, err := custodianTrust.ResolveAny(custody.RoleCustodian, deploymentID, r.WitnessFP)
	if err != nil {
		return fmt.Errorf("fence receipt: %w", err)
	}
	return evidence.VerifyRecordSignature(pub, FenceReceiptDomain, r.Signature, fenceReceiptFields(r)...)
}

// CheckpointRef is a witness checkpoint as it crosses the library
// boundary. Every field is covered by the custodian's signature, and
// Verify refuses a reference that does not carry one.
type CheckpointRef struct {
	Seq             int64  `json:"seq"`
	Hash            string `json:"hash"`
	LastExecutionID string `json:"last_execution_id,omitempty"`
	WitnessFP       string `json:"witness_fp"`
	SignerEpoch     int64  `json:"signer_epoch"`
	Signature       string `json:"signature,omitempty"`
}

// CheckpointFromHead converts a signed head into its boundary form.
func CheckpointFromHead(h *CheckpointHead) CheckpointRef {
	if h == nil {
		return CheckpointRef{}
	}
	return CheckpointRef{
		Seq: h.Seq, Hash: h.Hash, LastExecutionID: h.LastExecutionID,
		WitnessFP: h.WitnessFP, SignerEpoch: h.SignerEpoch, Signature: h.Signature,
	}
}

// Verify checks the checkpoint under the pinned custodian set. A
// checkpoint with no signature, or one signed by an unpinned key, is
// not a realignment authority.
func (c CheckpointRef) Verify(deploymentID string, trust *custody.TrustSet) error {
	if c.WitnessFP == "" || c.Signature == "" {
		return fmt.Errorf("witness checkpoint is unsigned — an unverified head cannot authorize a rewrite")
	}
	return VerifyCheckpoint(&CheckpointHead{
		Seq: c.Seq, Hash: c.Hash, LastExecutionID: c.LastExecutionID,
		SignerEpoch: c.SignerEpoch, WitnessFP: c.WitnessFP, Signature: c.Signature,
	}, deploymentID, trust)
}

// FenceRecord is the durable witness-side state of one epoch.
type FenceRecord struct {
	DeploymentID string
	FenceID      string
	Epoch        int64
	BaseSeq      int64
	BaseHash     string
	GrantDigest  string
	KernelFP     string
	State        string
	ResultDigest string
	OpenedAt     string
	ClosedAt     string
}

func (r FenceRecord) receipt() *FenceReceipt {
	return &FenceReceipt{
		State: r.State, DeploymentID: r.DeploymentID, FenceID: r.FenceID,
		Epoch: r.Epoch, BaseSeq: r.BaseSeq, BaseHash: r.BaseHash,
		GrantDigest: r.GrantDigest, ResultDigest: r.ResultDigest,
		OpenedAt: r.OpenedAt, ClosedAt: r.ClosedAt,
	}
}

// ─── Durable witness-side fence state ────────────────────────────────

const fenceDDL = `CREATE TABLE IF NOT EXISTS custody_fence (
	deployment_id TEXT NOT NULL,
	fence_id TEXT NOT NULL,
	epoch INTEGER NOT NULL,
	base_seq INTEGER NOT NULL,
	base_hash TEXT NOT NULL,
	grant_digest TEXT NOT NULL,
	kernel_fp TEXT NOT NULL,
	state TEXT NOT NULL,
	result_digest TEXT NOT NULL DEFAULT '',
	opened_at TEXT NOT NULL,
	closed_at TEXT NOT NULL DEFAULT '',
	PRIMARY KEY (deployment_id, fence_id)
)`

type fenceQueryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func fenceFrom(ctx context.Context, q fenceQueryer, deploymentID, fenceID string) (FenceRecord, bool, error) {
	var r FenceRecord
	err := q.QueryRowContext(ctx,
		`SELECT deployment_id, fence_id, epoch, base_seq, base_hash, grant_digest,
		        kernel_fp, state, result_digest, opened_at, closed_at
		 FROM custody_fence WHERE deployment_id = $1 AND fence_id = $2`,
		deploymentID, fenceID).
		Scan(&r.DeploymentID, &r.FenceID, &r.Epoch, &r.BaseSeq, &r.BaseHash, &r.GrantDigest,
			&r.KernelFP, &r.State, &r.ResultDigest, &r.OpenedAt, &r.ClosedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return FenceRecord{}, false, nil
	}
	if err != nil {
		return FenceRecord{}, false, err
	}
	return r, true, nil
}

func activeFenceFrom(ctx context.Context, q fenceQueryer, deploymentID string) (FenceRecord, bool, error) {
	var r FenceRecord
	err := q.QueryRowContext(ctx,
		`SELECT deployment_id, fence_id, epoch, base_seq, base_hash, grant_digest,
		        kernel_fp, state, result_digest, opened_at, closed_at
		 FROM custody_fence WHERE deployment_id = $1 AND state NOT IN ($2, $3)
		 ORDER BY epoch DESC LIMIT 1`, deploymentID, FenceClosed, FenceAborted).
		Scan(&r.DeploymentID, &r.FenceID, &r.Epoch, &r.BaseSeq, &r.BaseHash, &r.GrantDigest,
			&r.KernelFP, &r.State, &r.ResultDigest, &r.OpenedAt, &r.ClosedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return FenceRecord{}, false, nil
	}
	if err != nil {
		return FenceRecord{}, false, err
	}
	return r, true, nil
}

// ActiveFence reports the open migration epoch for a deployment, if
// any. The sender uses it to explain a refusal; the service uses it to
// refuse submissions.
func (l *Ledger) ActiveFence(ctx context.Context, deploymentID string) (*FenceRecord, error) {
	r, ok, err := activeFenceFrom(ctx, l.db, deploymentID)
	if err != nil || !ok {
		return nil, err
	}
	return &r, nil
}

// Fence returns one recorded epoch.
func (l *Ledger) Fence(ctx context.Context, deploymentID, fenceID string) (*FenceRecord, error) {
	r, ok, err := fenceFrom(ctx, l.db, deploymentID, fenceID)
	if err != nil || !ok {
		return nil, err
	}
	return &r, nil
}

// OpenFence freezes the deployment at the head the caller observed.
// The head comparison and the fence insert share one immediate
// transaction, so no submission can slip between the check and the
// freeze — that atomicity is the whole point of the epoch.
func (l *Ledger) OpenFence(ctx context.Context, req *FenceRequest) (FenceRecord, error) {
	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return FenceRecord{}, err
	}
	defer tx.Rollback()

	if existing, found, err := fenceFrom(ctx, tx, req.DeploymentID, req.FenceID); err != nil {
		return FenceRecord{}, err
	} else if found {
		if existing.GrantDigest != req.GrantDigest || existing.BaseSeq != req.BaseSeq || existing.BaseHash != req.BaseHash {
			return FenceRecord{}, fmt.Errorf("%w: fence %s exists with different parameters", ErrFenceState, req.FenceID)
		}
		if existing.State != FenceOpen {
			return FenceRecord{}, fmt.Errorf("%w: fence %s is %s", ErrFenceState, req.FenceID, existing.State)
		}
		return existing, tx.Commit()
	}

	if active, found, err := activeFenceFrom(ctx, tx, req.DeploymentID); err != nil {
		return FenceRecord{}, err
	} else if found {
		return FenceRecord{}, fmt.Errorf("%w: fence %s (epoch %d, grant %s) is open", ErrFenceActive, active.FenceID, active.Epoch, active.GrantDigest)
	}

	head, headHash, _, err := headFrom(ctx, tx, req.DeploymentID)
	if err != nil {
		return FenceRecord{}, err
	}
	if head != req.BaseSeq || headHash != req.BaseHash {
		return FenceRecord{}, fmt.Errorf("%w: custody head is seq %d (%s), fence requested seq %d (%s)",
			ErrStaleFenceBase, head, headHash, req.BaseSeq, req.BaseHash)
	}

	var maxEpoch sql.NullInt64
	if err := tx.QueryRowContext(ctx,
		`SELECT MAX(epoch) FROM custody_fence WHERE deployment_id = $1`, req.DeploymentID).Scan(&maxEpoch); err != nil {
		return FenceRecord{}, err
	}
	epoch := int64(1)
	if maxEpoch.Valid {
		epoch = maxEpoch.Int64 + 1
	}
	openedAt := time.Now().UTC().Format(time.RFC3339Nano)
	rec := FenceRecord{
		DeploymentID: req.DeploymentID, FenceID: req.FenceID, Epoch: epoch,
		BaseSeq: req.BaseSeq, BaseHash: req.BaseHash, GrantDigest: req.GrantDigest,
		KernelFP: req.KernelFP, State: FenceOpen, OpenedAt: openedAt,
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO custody_fence (deployment_id, fence_id, epoch, base_seq, base_hash,
		 grant_digest, kernel_fp, state, result_digest, opened_at, closed_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'',$9,'')`,
		rec.DeploymentID, rec.FenceID, rec.Epoch, rec.BaseSeq, rec.BaseHash,
		rec.GrantDigest, rec.KernelFP, rec.State, rec.OpenedAt); err != nil {
		return FenceRecord{}, fmt.Errorf("fence insert: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return FenceRecord{}, err
	}
	return rec, nil
}

// CloseFence releases the epoch after a migration committed its
// result. Only the grant that opened the fence may close it, and a
// close with a different result than one already recorded is a
// contradiction, never an overwrite.
func (l *Ledger) CloseFence(ctx context.Context, req *FenceRequest) (FenceRecord, error) {
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
	if rec.GrantDigest != req.GrantDigest {
		return FenceRecord{}, fmt.Errorf("%w: fence %s was opened under a different grant", ErrFenceState, req.FenceID)
	}
	switch rec.State {
	case FenceClosed:
		if rec.ResultDigest != req.ResultDigest {
			return FenceRecord{}, fmt.Errorf("%w: fence %s closed with result %s, close presents %s",
				ErrContradiction, req.FenceID, rec.ResultDigest, req.ResultDigest)
		}
		return rec, tx.Commit()
	case FenceAborted:
		return FenceRecord{}, fmt.Errorf("%w: fence %s was aborted", ErrFenceState, req.FenceID)
	case FenceOpen, FencePrepared, FenceFinalizing:
	default:
		return FenceRecord{}, fmt.Errorf("%w: fence %s is %s — close is not a transition from this state",
			ErrFenceState, req.FenceID, rec.State)
	}
	// An admitted transaction has an unresolved local outcome. Releasing
	// the epoch now would resume submissions against a suffix that may
	// already be rewritten.
	if live, ok, err := liveFenceTxFrom(ctx, tx, req.DeploymentID); err != nil {
		return FenceRecord{}, err
	} else if ok {
		return FenceRecord{}, fmt.Errorf("%w: transaction %s is still admitted — finalize or abort it before closing the epoch",
			ErrMigrationOutcomeUnknown, live.TxID)
	}
	if req.ResultDigest == "" {
		return FenceRecord{}, fmt.Errorf("%w: closing a fence requires the migration result digest", ErrFenceState)
	}
	closedAt := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx,
		`UPDATE custody_fence SET state = $1, result_digest = $2, closed_at = $3
		 WHERE deployment_id = $4 AND fence_id = $5`,
		FenceClosed, req.ResultDigest, closedAt, req.DeploymentID, req.FenceID); err != nil {
		return FenceRecord{}, fmt.Errorf("fence close: %w", err)
	}
	rec.State, rec.ResultDigest, rec.ClosedAt = FenceClosed, req.ResultDigest, closedAt
	if err := tx.Commit(); err != nil {
		return FenceRecord{}, err
	}
	return rec, nil
}

// AbortFence releases an epoch without a migration result. It is
// refused if custody advanced while the fence was open: that would
// mean a submission was admitted inside a frozen epoch, which is an
// integrity fault rather than a reason to resume.
func (l *Ledger) AbortFence(ctx context.Context, req *FenceRequest) (FenceRecord, error) {
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
	if rec.GrantDigest != req.GrantDigest {
		return FenceRecord{}, fmt.Errorf("%w: fence %s was opened under a different grant", ErrFenceState, req.FenceID)
	}
	switch rec.State {
	case FenceAborted:
		return rec, tx.Commit()
	case FenceClosed:
		return FenceRecord{}, fmt.Errorf("%w: fence %s already closed a migration", ErrFenceState, req.FenceID)
	case FenceOpen, FencePrepared, FenceFinalizing:
	default:
		return FenceRecord{}, fmt.Errorf("%w: fence %s is %s — abort is not a transition from this state",
			ErrFenceState, req.FenceID, rec.State)
	}
	// Any transaction with a committed local outcome blocks the abort:
	// releasing the epoch would resume submissions against a rewritten
	// suffix. An admitted transaction must be aborted through
	// AbortMigration, which carries the kernel's no-commit attestation.
	var committed int64
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM custody_fence_tx WHERE deployment_id = $1 AND fence_id = $2 AND state = $3`,
		req.DeploymentID, req.FenceID, MigrationTxCommitted).Scan(&committed); err != nil {
		return FenceRecord{}, err
	}
	if committed > 0 {
		return FenceRecord{}, fmt.Errorf("%w: epoch %d carries %d committed migration(s) — close it, never abort it",
			ErrMigrationOutcomeUnknown, rec.Epoch, committed)
	}
	if live, ok, err := liveFenceTxFrom(ctx, tx, req.DeploymentID); err != nil {
		return FenceRecord{}, err
	} else if ok {
		return FenceRecord{}, fmt.Errorf("%w: transaction %s is still admitted — abort it through AbortMigration",
			ErrMigrationOutcomeUnknown, live.TxID)
	}
	head, headHash, _, err := headFrom(ctx, tx, req.DeploymentID)
	if err != nil {
		return FenceRecord{}, err
	}
	if head != rec.BaseSeq || headHash != rec.BaseHash {
		return FenceRecord{}, fmt.Errorf("%w: custody advanced to seq %d inside fenced epoch %d — escalated, never aborted",
			ErrContradiction, head, rec.Epoch)
	}
	closedAt := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx,
		`UPDATE custody_fence SET state = $1, closed_at = $2 WHERE deployment_id = $3 AND fence_id = $4`,
		FenceAborted, closedAt, req.DeploymentID, req.FenceID); err != nil {
		return FenceRecord{}, fmt.Errorf("fence abort: %w", err)
	}
	rec.State, rec.ClosedAt = FenceAborted, closedAt
	if err := tx.Commit(); err != nil {
		return FenceRecord{}, err
	}
	return rec, nil
}

// ─── Kernel-side fence protocol ──────────────────────────────────────

// FenceClient drives the migration-epoch handshake from the kernel.
// Every receipt it returns has been verified under the pinned
// custodian set — an unverified receipt is never handed to the
// migration library.
type FenceClient struct {
	Client         *Client
	Signer         *evidence.Signer
	DeploymentID   string
	GrantDigest    string
	KernelTrust    *custody.TrustSet
	CustodianTrust *custody.TrustSet
	// MaxBaseRetries bounds how often Begin re-reads the head after a
	// concurrent submission moved it. A deployment that cannot be
	// fenced because submissions never stop is reported, not waited
	// out.
	MaxBaseRetries int
}

func (f *FenceClient) retries() int {
	if f.MaxBaseRetries <= 0 {
		return 8
	}
	return f.MaxBaseRetries
}

// Plan reads the custodian's signed head, verifies it, and returns the
// signed request that would freeze exactly that head. Nothing is sent:
// the caller records its own durable intent first, so a crash between
// "we asked" and "we were answered" leaves a trace it can resume from.
func (f *FenceClient) Plan(ctx context.Context) (*FenceRequest, error) {
	if f.Client == nil || f.Signer == nil {
		return nil, fmt.Errorf("fence: client and kernel signer are required")
	}
	head, err := f.Client.Checkpoint(ctx, f.DeploymentID)
	if err != nil {
		return nil, fmt.Errorf("fence: witness checkpoint: %w", err)
	}
	cp := CheckpointFromHead(head)
	if err := cp.Verify(f.DeploymentID, f.CustodianTrust); err != nil {
		return nil, fmt.Errorf("fence: witness checkpoint unverifiable: %w", err)
	}
	req := &FenceRequest{
		Op:           OpFenceBegin,
		DeploymentID: f.DeploymentID,
		FenceID:      FenceIDFor(f.DeploymentID, f.GrantDigest, cp.Seq, cp.Hash),
		GrantDigest:  f.GrantDigest,
		BaseSeq:      cp.Seq,
		BaseHash:     cp.Hash,
	}
	if err := SignFenceRequest(f.Signer, req); err != nil {
		return nil, err
	}
	return req, nil
}

// Open sends a planned fence request and verifies the receipt.
func (f *FenceClient) Open(ctx context.Context, req *FenceRequest) (FenceReceipt, error) {
	receipt, err := f.Client.BeginFence(ctx, req)
	if err != nil {
		return FenceReceipt{}, err
	}
	return f.accept(req, receipt)
}

func (f *FenceClient) accept(req *FenceRequest, receipt *FenceReceipt) (FenceReceipt, error) {
	if err := VerifyFenceReceipt(receipt, f.DeploymentID, f.CustodianTrust); err != nil {
		return FenceReceipt{}, fmt.Errorf("fence: receipt unverifiable: %w", err)
	}
	if receipt.State != FenceOpen {
		return FenceReceipt{}, fmt.Errorf("fence: receipt state %s is not OPEN", receipt.State)
	}
	if receipt.FenceID != req.FenceID {
		return FenceReceipt{}, fmt.Errorf("fence: receipt names fence %s, request named %s", receipt.FenceID, req.FenceID)
	}
	if receipt.BaseSeq != req.BaseSeq || receipt.BaseHash != req.BaseHash {
		return FenceReceipt{}, fmt.Errorf("fence: receipt froze seq %d (%s), the request named seq %d (%s)",
			receipt.BaseSeq, receipt.BaseHash, req.BaseSeq, req.BaseHash)
	}
	if receipt.GrantDigest != f.GrantDigest {
		return FenceReceipt{}, fmt.Errorf("fence: receipt binds grant %s, this run holds %s", receipt.GrantDigest, f.GrantDigest)
	}
	return *receipt, nil
}

// Begin opens the migration epoch at the current custody head. If a
// submission moved the head between the checkpoint read and the fence
// request, the witness refuses the stale base and Begin retries against
// the new head. When Begin returns, no submission for this deployment
// can be admitted until End or Abort.
func (f *FenceClient) Begin(ctx context.Context) (FenceReceipt, error) {
	var last error
	for attempt := 0; attempt < f.retries(); attempt++ {
		req, err := f.Plan(ctx)
		if err != nil {
			return FenceReceipt{}, err
		}
		receipt, err := f.Open(ctx, req)
		if err == nil {
			return receipt, nil
		}
		if !errors.Is(err, ErrStaleFenceBase) {
			return FenceReceipt{}, err
		}
		last = err
	}
	return FenceReceipt{}, fmt.Errorf("fence: custody head kept moving across %d attempts — submissions must quiesce before a migration epoch can open: %w",
		f.retries(), last)
}

// Reenter re-sends a fence-begin for an epoch this grant already
// planned. The witness treats an identical fence as idempotent, so a
// kernel that crashed after freezing the custodian resumes the same
// epoch rather than opening a second one.
func (f *FenceClient) Reenter(ctx context.Context, fenceID string, baseSeq int64, baseHash string) (FenceReceipt, error) {
	if f.Client == nil || f.Signer == nil {
		return FenceReceipt{}, fmt.Errorf("fence: client and kernel signer are required")
	}
	req := &FenceRequest{
		Op:           OpFenceBegin,
		DeploymentID: f.DeploymentID,
		FenceID:      fenceID,
		GrantDigest:  f.GrantDigest,
		BaseSeq:      baseSeq,
		BaseHash:     baseHash,
	}
	if err := SignFenceRequest(f.Signer, req); err != nil {
		return FenceReceipt{}, err
	}
	return f.Open(ctx, req)
}

// End closes the epoch with the migration result digest.
func (f *FenceClient) End(ctx context.Context, fence FenceReceipt, resultDigest string) (FenceReceipt, error) {
	return f.finish(ctx, OpFenceEnd, fence, resultDigest)
}

// Abort releases the epoch without a migration result.
func (f *FenceClient) Abort(ctx context.Context, fence FenceReceipt) (FenceReceipt, error) {
	return f.finish(ctx, OpFenceAbort, fence, "")
}

func (f *FenceClient) finish(ctx context.Context, op string, fence FenceReceipt, resultDigest string) (FenceReceipt, error) {
	if f.Client == nil || f.Signer == nil {
		return FenceReceipt{}, fmt.Errorf("fence: client and kernel signer are required")
	}
	// The epoch this run holds is the authority for which grant to act
	// under. A receipt presented by a caller names a grant, but it is an
	// untrusted document: taking its grant digest would let any receipt
	// close any epoch under a grant this run does not hold.
	if fence.GrantDigest != f.GrantDigest {
		return FenceReceipt{}, fmt.Errorf("%w: receipt binds grant %s, this run holds %s",
			ErrWrongTerminalReceipt, fence.GrantDigest, f.GrantDigest)
	}
	want := FenceClosed
	if op == OpFenceAbort {
		want = FenceAborted
	}
	if op == OpFenceEnd && resultDigest == "" {
		return FenceReceipt{}, fmt.Errorf("%w: closing an epoch requires the migration result digest", ErrWrongTerminalReceipt)
	}
	req := &FenceRequest{
		Op:           op,
		DeploymentID: f.DeploymentID,
		FenceID:      fence.FenceID,
		GrantDigest:  f.GrantDigest,
		BaseSeq:      fence.BaseSeq,
		BaseHash:     fence.BaseHash,
		ResultDigest: resultDigest,
	}
	if err := SignFenceRequest(f.Signer, req); err != nil {
		return FenceReceipt{}, err
	}
	receipt, err := f.Client.EndFence(ctx, req)
	if err != nil {
		return FenceReceipt{}, err
	}
	if err := VerifyFenceReceipt(receipt, f.DeploymentID, f.CustodianTrust); err != nil {
		return FenceReceipt{}, fmt.Errorf("fence: receipt unverifiable: %w", err)
	}
	if receipt.State != want {
		return FenceReceipt{}, fmt.Errorf("%w: %s returned state %q, want %q",
			ErrWrongTerminalReceipt, op, receipt.State, want)
	}
	if receipt.FenceID != fence.FenceID || receipt.GrantDigest != f.GrantDigest {
		return FenceReceipt{}, fmt.Errorf("%w: terminal receipt does not bind this epoch and grant", ErrWrongTerminalReceipt)
	}
	if op == OpFenceEnd && receipt.ResultDigest != resultDigest {
		return FenceReceipt{}, fmt.Errorf("%w: terminal receipt binds result %s, the request carried %s",
			ErrWrongTerminalReceipt, receipt.ResultDigest, resultDigest)
	}
	if op == OpFenceAbort && receipt.ResultDigest != "" {
		return FenceReceipt{}, fmt.Errorf("%w: an abort receipt must not carry a result digest", ErrWrongTerminalReceipt)
	}
	return *receipt, nil
}

// ─── Durable kernel-side fence intent ────────────────────────────────

// fenceIntentDDL records the kernel's own view of a migration epoch.
// It is written before the witness is asked to freeze, so a kernel that
// crashes mid-migration can tell on restart that an epoch may exist and
// resume the same fence instead of opening a second one — or, worse,
// draining submissions into a frozen custodian.
const fenceIntentDDL = `CREATE TABLE IF NOT EXISTS custody_fence_intent (
	fence_id TEXT PRIMARY KEY,
	deployment_id TEXT NOT NULL,
	grant_digest TEXT NOT NULL,
	base_seq INTEGER NOT NULL,
	base_hash TEXT NOT NULL,
	state TEXT NOT NULL,
	result_digest TEXT NOT NULL DEFAULT '',
	opened_at TEXT NOT NULL,
	closed_at TEXT NOT NULL DEFAULT ''
)`

// FenceIntent is the kernel-side durable record of one migration epoch.
type FenceIntent struct {
	FenceID      string `json:"fence_id"`
	DeploymentID string `json:"deployment_id"`
	GrantDigest  string `json:"grant_digest"`
	BaseSeq      int64  `json:"base_seq"`
	BaseHash     string `json:"base_hash"`
	State        string `json:"state"`
	ResultDigest string `json:"result_digest,omitempty"`
	OpenedAt     string `json:"opened_at"`
	ClosedAt     string `json:"closed_at,omitempty"`
}

// RecordFenceIntent durably notes the epoch the kernel is about to
// open. It is idempotent: re-running the same grant rewrites nothing.
func (o *Outbox) RecordFenceIntent(ctx context.Context, in FenceIntent) error {
	if in.FenceID == "" || in.GrantDigest == "" {
		return fmt.Errorf("fence intent: identity and grant digest are mandatory")
	}
	res, err := o.db.ExecContext(ctx,
		`INSERT INTO custody_fence_intent (fence_id, deployment_id, grant_digest, base_seq, base_hash, state, result_digest, opened_at, closed_at)
		 VALUES ($1,$2,$3,$4,$5,$6,'',$7,'')
		 ON CONFLICT(fence_id) DO NOTHING`,
		in.FenceID, in.DeploymentID, in.GrantDigest, in.BaseSeq, in.BaseHash, FenceOpen, in.OpenedAt)
	if err != nil {
		return fmt.Errorf("fence intent: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 1 {
		return nil
	}
	// The identity already exists. Re-recording the same commitments is
	// idempotent; recording different ones is a contradiction, never a
	// silent no-op.
	existing, err := o.FenceIntent(ctx, in.FenceID)
	if err != nil {
		return err
	}
	if existing.DeploymentID != in.DeploymentID || existing.GrantDigest != in.GrantDigest ||
		existing.BaseSeq != in.BaseSeq || existing.BaseHash != in.BaseHash {
		return fmt.Errorf("%w: fence intent %s exists with different commitments (base %d/%s, this record names %d/%s)",
			ErrContradiction, in.FenceID, existing.BaseSeq, existing.BaseHash, in.BaseSeq, in.BaseHash)
	}
	return nil
}

// FenceIntent reads one recorded epoch intent.
func (o *Outbox) FenceIntent(ctx context.Context, fenceID string) (FenceIntent, error) {
	var in FenceIntent
	err := o.db.QueryRowContext(ctx,
		`SELECT fence_id, deployment_id, grant_digest, base_seq, base_hash, state, result_digest, opened_at, closed_at
		 FROM custody_fence_intent WHERE fence_id = $1`, fenceID).
		Scan(&in.FenceID, &in.DeploymentID, &in.GrantDigest, &in.BaseSeq, &in.BaseHash,
			&in.State, &in.ResultDigest, &in.OpenedAt, &in.ClosedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return FenceIntent{}, fmt.Errorf("%w: no fence intent %s", ErrFenceState, fenceID)
	}
	if err != nil {
		return FenceIntent{}, err
	}
	return in, nil
}

// PendingFenceIntent returns an epoch this grant opened and never
// closed. A resumed migration uses it to re-enter the same fence
// instead of minting a new authorization.
func (o *Outbox) PendingFenceIntent(ctx context.Context, deploymentID, grantDigest string) (*FenceIntent, error) {
	var in FenceIntent
	err := o.db.QueryRowContext(ctx,
		`SELECT fence_id, deployment_id, grant_digest, base_seq, base_hash, state, result_digest, opened_at, closed_at
		 FROM custody_fence_intent
		 WHERE deployment_id = $1 AND grant_digest = $2 AND state = $3
		 ORDER BY opened_at DESC LIMIT 1`, deploymentID, grantDigest, FenceOpen).
		Scan(&in.FenceID, &in.DeploymentID, &in.GrantDigest, &in.BaseSeq, &in.BaseHash,
			&in.State, &in.ResultDigest, &in.OpenedAt, &in.ClosedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("fence intent read: %w", err)
	}
	return &in, nil
}

// CompleteFenceIntent records the epoch's terminal state locally. It
// is called after the witness has acknowledged the close, so the local
// record never claims a state the custodian did not sign.
func (o *Outbox) CompleteFenceIntent(ctx context.Context, fenceID, state, resultDigest string) error {
	_, err := o.db.ExecContext(ctx,
		`UPDATE custody_fence_intent SET state = $1, result_digest = $2, closed_at = $3 WHERE fence_id = $4`,
		state, resultDigest, time.Now().UTC().Format(time.RFC3339Nano), fenceID)
	if err != nil {
		return fmt.Errorf("fence intent complete: %w", err)
	}
	return nil
}

// FenceIntents lists recorded epochs, newest first — the operator
// surface for deciding whether a migration is still in flight. A
// pre-upgrade outbox has no intent table and no epochs, which is a
// truthful empty answer rather than a read failure.
func (o *Outbox) FenceIntents(ctx context.Context, limit int) ([]FenceIntent, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := o.db.QueryContext(ctx,
		`SELECT fence_id, deployment_id, grant_digest, base_seq, base_hash, state, result_digest, opened_at, closed_at
		 FROM custody_fence_intent ORDER BY opened_at DESC LIMIT $1`, limit)
	if err != nil {
		if strings.Contains(err.Error(), "no such table") {
			return nil, nil
		}
		return nil, err
	}
	defer rows.Close()
	var out []FenceIntent
	for rows.Next() {
		var in FenceIntent
		if err := rows.Scan(&in.FenceID, &in.DeploymentID, &in.GrantDigest, &in.BaseSeq, &in.BaseHash,
			&in.State, &in.ResultDigest, &in.OpenedAt, &in.ClosedAt); err != nil {
			return nil, err
		}
		out = append(out, in)
	}
	return out, rows.Err()
}
