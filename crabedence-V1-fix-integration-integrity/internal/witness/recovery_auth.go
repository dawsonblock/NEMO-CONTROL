package witness

// RC8.4 PR-03 — authenticated recovery and grant-expiry handover.
//
// An epoch that outlives its initiating grant used to be stranded. The
// resume path re-verifies that grant against the wall clock on every
// call, and the local lookup filtered on the grant digest, so a
// replacement authorization could not even find the epoch it was meant
// to resolve. The only way out was manual database surgery.
//
// Recovery is a separate authority, not an extension of the migration
// grant. A repair authority signs a `custody-recovery-grant-v1` that
// names one fence, one transaction, one action and the exact local
// state it was issued against. It binds the original grant digest but
// never has to equal it, so a replacement authorization can finish work
// the expired one started — and cannot start anything new, because the
// action set is FINALIZE, ABORT and COMPLETE only.
//
// The witness cannot inspect the remote database. "No local commit"
// therefore stays a kernel attestation; what makes it meaningful is the
// ordering: the permit is durably revoked locally *before* the abort
// RPC, so a resumed kernel finds the permit dead rather than racing the
// release.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openclaw/crabbox/internal/custody"
	"github.com/openclaw/crabbox/internal/evidence"
)

// Recovery grant schema and signature domain.
const (
	RecoveryGrantSchema = "custody-recovery-grant-v1"
	RecoveryGrantDomain = "custody-recovery-grant-v1\x00"
)

// Recovery actions. Each names one terminal resolution of an admitted
// transaction; none of them admits new work.
const (
	RecoveryFinalize = "RECOVER_FINALIZE"
	RecoveryAbort    = "RECOVER_ABORT"
	RecoveryComplete = "RECOVER_COMPLETE"
)

// ErrRecoveryAuthorization marks every recovery-authorization refusal.
var ErrRecoveryAuthorization = errors.New("custody recovery authorization")

// RecoveryGrant is a detached, signed authorization to resolve one
// already-admitted transaction. Every field is covered by the
// signature; the observed state is what makes a replay against a
// different situation a contradiction rather than a retry.
type RecoveryGrant struct {
	Schema              string `json:"schema"`
	Subject             string `json:"subject"`
	Role                string `json:"role"`
	DeploymentID        string `json:"deployment_id"`
	FenceID             string `json:"fence_id"`
	Epoch               int64  `json:"epoch"`
	TxID                string `json:"tx_id"`
	OriginalGrantDigest string `json:"original_grant_digest"`
	BaseSeq             int64  `json:"base_seq"`
	BaseHash            string `json:"base_hash"`
	Action              string `json:"action"`
	ObservedLocalState  string `json:"observed_local_state"`
	ObservedJournalSeq  int64  `json:"observed_journal_seq"`
	ObservedAfterDigest string `json:"observed_after_digest"`
	Nonce               string `json:"nonce"`
	NotBefore           string `json:"not_before"`
	ExpiresAt           string `json:"expires_at"`
	IssuerKeyID         string `json:"issuer_key_id"`
	Audience            string `json:"audience"`
	Signature           string `json:"signature,omitempty"`
}

func recoveryCanonical(g *RecoveryGrant) ([]byte, error) {
	cp := *g
	cp.Signature = ""
	raw, err := json.Marshal(cp)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(m); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// SignRecoveryGrant fills the issuer identity and signature.
func SignRecoveryGrant(signer *evidence.Signer, g *RecoveryGrant) error {
	if signer == nil {
		return fmt.Errorf("%w: no signing key", ErrRecoveryAuthorization)
	}
	g.Schema = RecoveryGrantSchema
	g.Role = custody.RoleRepairAuthority
	g.IssuerKeyID = signer.Fingerprint()
	canon, err := recoveryCanonical(g)
	if err != nil {
		return err
	}
	sig, err := signer.SignRecord(RecoveryGrantDomain, string(canon))
	if err != nil {
		return err
	}
	g.Signature = sig
	return nil
}

// RecoveryGrantDigest is the stable identity of a fully signed grant.
func RecoveryGrantDigest(g *RecoveryGrant) (string, error) {
	raw, err := json.Marshal(g)
	if err != nil {
		return "", err
	}
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		return "", err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(m); err != nil {
		return "", err
	}
	sum := sha256.Sum256(bytes.TrimRight(buf.Bytes(), "\n"))
	return hex.EncodeToString(sum[:]), nil
}

// VerifyRecoveryGrant checks signature, role, audience, scope, action
// and validity window. It does not consult the nonce ledger: replay
// state is durable and checked separately, atomically with acceptance.
func VerifyRecoveryGrant(g *RecoveryGrant, trust *custody.TrustSet, deploymentID, audience string, now time.Time) error {
	if g == nil {
		return fmt.Errorf("%w: no recovery grant supplied", ErrRecoveryAuthorization)
	}
	if g.Schema != RecoveryGrantSchema {
		return fmt.Errorf("%w: unsupported recovery schema %q", ErrRecoveryAuthorization, g.Schema)
	}
	if strings.TrimSpace(g.Subject) == "" {
		return fmt.Errorf("%w: recovery grant has no subject", ErrRecoveryAuthorization)
	}
	if g.Role != custody.RoleRepairAuthority {
		return fmt.Errorf("%w: recovery grant role %q is not %s", ErrRecoveryAuthorization, g.Role, custody.RoleRepairAuthority)
	}
	if deploymentID == "" || g.DeploymentID != deploymentID {
		return fmt.Errorf("%w: recovery grant is scoped to deployment %q, this outbox serves %q", ErrRecoveryAuthorization, g.DeploymentID, deploymentID)
	}
	if g.Audience != audience {
		return fmt.Errorf("%w: recovery grant audience %q, this operator is %q", ErrRecoveryAuthorization, g.Audience, audience)
	}
	switch g.Action {
	case RecoveryFinalize, RecoveryAbort, RecoveryComplete:
	default:
		return fmt.Errorf("%w: action %q is not a recovery action", ErrRecoveryAuthorization, g.Action)
	}
	if g.FenceID == "" || g.TxID == "" {
		return fmt.Errorf("%w: recovery grant must name a fence and a transaction", ErrRecoveryAuthorization)
	}
	if g.Epoch < 1 || g.OriginalGrantDigest == "" {
		return fmt.Errorf("%w: recovery grant must bind the epoch and the original grant", ErrRecoveryAuthorization)
	}
	if len(strings.TrimSpace(g.Nonce)) < 16 {
		return fmt.Errorf("%w: recovery nonce is missing or too short", ErrRecoveryAuthorization)
	}
	notBefore, err := time.Parse(time.RFC3339, g.NotBefore)
	if err != nil {
		return fmt.Errorf("%w: recovery not_before is not RFC3339: %v", ErrRecoveryAuthorization, err)
	}
	expires, err := time.Parse(time.RFC3339, g.ExpiresAt)
	if err != nil {
		return fmt.Errorf("%w: recovery expires_at is not RFC3339: %v", ErrRecoveryAuthorization, err)
	}
	if !expires.After(notBefore) {
		return fmt.Errorf("%w: recovery validity window is empty", ErrRecoveryAuthorization)
	}
	if now.Before(notBefore) {
		return fmt.Errorf("%w: recovery grant is not valid before %s", ErrRecoveryAuthorization, g.NotBefore)
	}
	if !now.Before(expires) {
		return fmt.Errorf("%w: recovery grant expired at %s", ErrRecoveryAuthorization, g.ExpiresAt)
	}
	if trust.Empty() {
		return fmt.Errorf("%w: no pinned repair-authority trust set", ErrRecoveryAuthorization)
	}
	pub, err := trust.ResolveAny(custody.RoleRepairAuthority, deploymentID, g.IssuerKeyID)
	if err != nil {
		return fmt.Errorf("%w: recovery issuer is not a pinned repair authority: %v", ErrRecoveryAuthorization, err)
	}
	canon, err := recoveryCanonical(g)
	if err != nil {
		return err
	}
	if err := evidence.VerifyRecordSignature(pub, RecoveryGrantDomain, g.Signature, string(canon)); err != nil {
		return fmt.Errorf("%w: recovery signature invalid: %v", ErrRecoveryAuthorization, err)
	}
	return nil
}

// ConsumeRecoveryNonce durably records one recovery use. The nonce
// ledger's PRIMARY KEY admits exactly one consumption, and the insert
// is the same statement that establishes acceptance, so a captured
// grant cannot be replayed and a failed operation cannot be silently
// retried under the same authorization.
func (o *Outbox) ConsumeRecoveryNonce(ctx context.Context, g *RecoveryGrant) error {
	digest, err := RecoveryGrantDigest(g)
	if err != nil {
		return err
	}
	res, err := o.db.ExecContext(ctx,
		`INSERT INTO operator_nonce_ledger (nonce, subject, operation, grant_digest, used_at)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT(nonce) DO NOTHING`,
		g.Nonce, g.Subject, "recovery:"+g.Action, digest, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("recovery nonce ledger: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("%w: recovery nonce %q was already consumed", ErrRecoveryAuthorization, g.Nonce)
	}
	return nil
}

// RecoveryPlan is the derived resolution of one epoch, computed from
// the local outbox and the custodian's view. It is advisory until a
// recovery grant authorizes the action it names.
type RecoveryPlan struct {
	DeploymentID string `json:"deployment_id"`
	FenceID      string `json:"fence_id"`
	TxID         string `json:"tx_id"`
	Epoch        int64  `json:"epoch"`
	BaseSeq      int64  `json:"base_seq"`
	BaseHash     string `json:"base_hash"`
	GrantDigest  string `json:"grant_digest"`
	LocalState   string `json:"local_state"`
	// HasLocalTx reports whether this outbox holds a row for TxID. A
	// witness-only admission — the kernel crashed between prepare and
	// AdmitMigration — has no local permit to revoke, and the abort
	// path must not try.
	HasLocalTx   bool     `json:"has_local_tx"`
	WitnessState string   `json:"witness_state"`
	Action       string   `json:"action"`
	Reason       string   `json:"reason"`
	JournalSeq   int64    `json:"journal_seq,omitempty"`
	AfterDigest  string   `json:"after_digest,omitempty"`
	ProofDigest  string   `json:"proof_digest,omitempty"`
	BeforeDigest string   `json:"before_digest,omitempty"`
	Quarantined  bool     `json:"quarantined"`
	Findings     []string `json:"findings,omitempty"`
}

// PlanRecovery reads the local transaction and the custodian's fence
// state and derives the only safe action. Any disagreement between the
// two, or any state it cannot account for, is quarantined rather than
// guessed.
func PlanRecovery(ctx context.Context, o *Outbox, c *Client, deploymentID, fenceID string) (RecoveryPlan, error) {
	plan := RecoveryPlan{DeploymentID: deploymentID, FenceID: fenceID, Quarantined: true}

	local, err := o.MigrationTxsForFence(ctx, fenceID)
	if err != nil {
		return plan, err
	}
	status, err := c.FenceStatus(ctx, deploymentID, fenceID)
	if err != nil {
		return plan, err
	}
	plan.WitnessState = status.State
	plan.Epoch = status.Epoch
	plan.BaseSeq, plan.BaseHash = status.BaseSeq, status.BaseHash
	plan.GrantDigest = status.GrantDigest

	var live []MigrationTx
	for _, t := range local {
		switch t.State {
		case LocalTxAdmitted, LocalTxLocalCommitted:
			live = append(live, t)
		}
	}
	if len(live) == 0 {
		// No local transaction. The witness may still hold an admitted
		// one from a kernel that crashed between prepare and admission.
		if status.State == FenceClosed {
			plan.Action = RecoveryComplete
			plan.Reason = "the epoch is closed and this outbox holds no transaction for it"
			plan.Quarantined = false
			return plan, nil
		}
		plan.Action = RecoveryAbort
		plan.Reason = "no local transaction exists, so nothing can have committed here"
		plan.TxID = status.LiveTxID
		plan.Quarantined = false
		return plan, nil
	}
	if len(live) > 1 {
		plan.Findings = append(plan.Findings, fmt.Sprintf("%d local transactions are unresolved; only one may exist", len(live)))
		return plan, nil
	}
	t := live[0]
	plan.TxID, plan.Epoch, plan.BaseSeq, plan.BaseHash = t.TxID, t.WitnessEpoch, t.BaseSeq, t.BaseHash
	plan.GrantDigest = t.GrantDigest
	plan.LocalState = t.State
	plan.HasLocalTx = true
	plan.JournalSeq, plan.AfterDigest, plan.ProofDigest, plan.BeforeDigest = t.JournalSeq, t.AfterDigest, t.ProofDigest, t.BeforeDigest

	switch {
	case t.State == LocalTxLocalCommitted && status.State == FenceClosed:
		plan.Action = RecoveryComplete
		plan.Reason = "the witness already closed the epoch and the local journal records the commit"
		plan.Quarantined = false
	case t.State == LocalTxLocalCommitted:
		plan.Action = RecoveryFinalize
		plan.Reason = "the local rewrite committed and the witness has not recorded it"
		plan.Quarantined = false
	case t.State == LocalTxAdmitted && status.State == FenceClosed:
		plan.Findings = append(plan.Findings, "the witness closed the epoch while the local permit is still ADMITTED: a commit may exist without its marker")
	case t.State == LocalTxAdmitted:
		plan.Action = RecoveryAbort
		plan.Reason = "the permit was admitted but no local commit exists"
		plan.Quarantined = false
	}
	return plan, nil
}

// ExecuteRecovery performs the planned action under a verified recovery
// grant. The permit is revoked locally before the witness is asked to
// abort, so a resumed kernel finds it dead rather than racing the
// release.
func ExecuteRecovery(ctx context.Context, o *Outbox, fc *FenceClient, trust *custody.TrustSet, g *RecoveryGrant, plan RecoveryPlan, now time.Time) (map[string]any, error) {
	if plan.Quarantined {
		return nil, fmt.Errorf("%w: plan is quarantined: %s", ErrFenceRecoveryRequired, strings.Join(plan.Findings, "; "))
	}
	if err := VerifyRecoveryGrant(g, trust, plan.DeploymentID, "custodyctl", now); err != nil {
		return nil, err
	}
	if g.FenceID != plan.FenceID || g.Action != plan.Action {
		return nil, fmt.Errorf("%w: grant authorizes %s on %s, the plan requires %s on %s",
			ErrRecoveryAuthorization, g.Action, g.FenceID, plan.Action, plan.FenceID)
	}
	if plan.TxID != "" && g.TxID != plan.TxID {
		return nil, fmt.Errorf("%w: grant names transaction %s, the plan resolves %s", ErrRecoveryAuthorization, g.TxID, plan.TxID)
	}
	if g.OriginalGrantDigest != plan.GrantDigest {
		return nil, fmt.Errorf("%w: grant binds original grant %s, the epoch was opened under %s",
			ErrRecoveryAuthorization, g.OriginalGrantDigest, plan.GrantDigest)
	}
	if g.Epoch != plan.Epoch || g.BaseSeq != plan.BaseSeq || g.BaseHash != plan.BaseHash {
		return nil, fmt.Errorf("%w: grant was issued against a different epoch state", ErrRecoveryAuthorization)
	}
	if g.ObservedLocalState != plan.LocalState {
		return nil, fmt.Errorf("%w: grant observed local state %q, the outbox now reports %q",
			ErrRecoveryAuthorization, g.ObservedLocalState, plan.LocalState)
	}
	if err := o.ConsumeRecoveryNonce(ctx, g); err != nil {
		return nil, err
	}

	out := map[string]any{"fence_id": plan.FenceID, "action": plan.Action, "tx_id": plan.TxID, "subject": g.Subject}
	// Every request this authorization issues is a recovery request, and
	// the witness requires the marker before it will let one resolve a
	// quarantined epoch. The grant has been verified above, so the flag
	// is set only on this path.
	fc.Recovery = true
	switch plan.Action {
	case RecoveryFinalize:
		tx, err := o.MigrationTx(ctx, plan.TxID)
		if err != nil {
			return nil, err
		}
		result, err := fc.FinalizeLocal(ctx, tx)
		if err != nil {
			return nil, err
		}
		if err := o.CompleteMigrationTx(ctx, &result); err != nil {
			return nil, err
		}
		out["state"] = result.State
		out["proof_digest"] = result.ProofDigest
	case RecoveryAbort:
		if plan.TxID != "" {
			// Revoke first, but only when this outbox actually holds
			// the permit. A witness-only admission has no local row to
			// revoke, and requiring one here stranded exactly the
			// crash this action exists to resolve. Nothing is lost by
			// skipping it: the witness transition below leaves the
			// transaction ABORTED, so a resumed kernel's Prepare is
			// refused rather than re-admitted. This is the ordering
			// that makes the kernel's no-commit attestation
			// meaningful: a resumed kernel cannot commit under a
			// permit that is already dead.
			if plan.HasLocalTx {
				if err := o.RevokePermit(ctx, plan.TxID, "recovery abort: "+g.Subject); err != nil {
					return nil, err
				}
			}
			permit := FencePermit{
				DeploymentID: plan.DeploymentID, FenceID: plan.FenceID, Epoch: plan.Epoch,
				TxID: plan.TxID, GrantDigest: plan.GrantDigest,
				BaseSeq: plan.BaseSeq, BaseHash: plan.BaseHash, TargetSeq: plan.BaseSeq + 1,
			}
			if _, err := fc.AbortMigration(ctx, permit, "recovery abort"); err != nil {
				return nil, err
			}
		}
		receipt, err := fc.Abort(ctx, FenceReceipt{
			FenceID: plan.FenceID, GrantDigest: plan.GrantDigest,
			BaseSeq: plan.BaseSeq, BaseHash: plan.BaseHash,
		})
		if err != nil {
			return nil, err
		}
		out["state"] = receipt.State
	case RecoveryComplete:
		if plan.TxID != "" {
			tx, err := o.MigrationTx(ctx, plan.TxID)
			if err != nil {
				return nil, err
			}
			if tx.State != LocalTxFinalized {
				result := FenceResult{
					State: MigrationTxCommitted, DeploymentID: tx.DeploymentID, FenceID: tx.FenceID,
					Epoch: tx.WitnessEpoch, TxID: tx.TxID, GrantDigest: tx.GrantDigest,
					BaseSeq: tx.BaseSeq, ProofDigest: tx.ProofDigest, JournalSeq: tx.JournalSeq,
					BeforeDigest: tx.BeforeDigest, AfterDigest: tx.AfterDigest,
				}
				if err := o.CompleteMigrationTx(ctx, &result); err != nil {
					return nil, err
				}
			}
		}
		out["state"] = FenceClosed
	default:
		return nil, fmt.Errorf("%w: action %q has no executor", ErrRecoveryAuthorization, plan.Action)
	}
	return out, nil
}

// FenceStatus reads one epoch's state by identity. The response is a
// witness statement for inspection, not a signature: authority for any
// state change still comes from a signed permit, terminal receipt or
// recovery grant.
func (c *Client) FenceStatus(ctx context.Context, deploymentID, fenceID string) (*FenceReceipt, error) {
	resp, err := c.call(ctx, Request{Op: OpFenceStatus, DeploymentID: deploymentID,
		Fence: &FenceRequest{Op: OpFenceStatus, DeploymentID: deploymentID, FenceID: fenceID}})
	if err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, fmt.Errorf("witness fence status refused: %s", resp.Error)
	}
	if resp.Fence == nil {
		return nil, fmt.Errorf("%w: no fence %s", ErrFenceState, fenceID)
	}
	return resp.Fence, nil
}
