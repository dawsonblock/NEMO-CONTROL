// Package witness implements the independent evidence-custody service
// for the receipt family and the kernel-side custody outbox.
//
// The custody boundary exists so the execution kernel cannot be the
// sole author of the evidence that qualifies it: terminal receipts are
// wrapped in custody-envelope-v1 records, submitted to a separately
// administered witness that keeps an append-only per-deployment log,
// countersigns an acknowledgement, and refuses replays, gaps, foreign
// deployments, contradictory checkpoints, and forged receipts. The
// kernel keeps a durable outbox so witness loss never silently loses
// evidence — pending submissions redeliver on reconnect, and a signed
// checkpoint exchange realigns both sides after restore.
//
// This is the receipt-family protocol (length-prefixed JSON frames).
// It is deliberately NOT wire-compatible with the sandboxcustody NDJSON
// protocol (sandbox_archive/recovery_checkpoint families); the two are
// joined only through the typed custody envelope — never re-encoded.
package witness

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/openclaw/crabbox/internal/custody"
	"github.com/openclaw/crabbox/internal/evidence"
)

// Protocol ops.
const (
	OpSubmit     = "submit"
	OpCheckpoint = "checkpoint"
	OpStatus     = "status"
)

// Signed-record domains — distinct from the sandboxcustody
// "archive-custody-ack/v3" protocol and from the envelope signature
// domain, so records cannot cross protocols.
const (
	ackDomain        = "custody-witness-ack-v1\x00"
	checkpointDomain = "custody-witness-checkpoint-v1\x00"
)

// Request is one custody operation on the wire.
type Request struct {
	Op           string `json:"op"`
	DeploymentID string `json:"deployment_id"`
	// Envelope is the custody-envelope-v1 record for OpSubmit — the
	// native receipt bytes travel verbatim inside content.bytes_b64.
	// A submission without an envelope is refused: capability
	// negotiation is explicit, never a silent downgrade.
	Envelope *custody.Envelope `json:"envelope,omitempty"`
}

// Response carries the operation result: a signed acknowledgement on
// submit, the signed custody head on checkpoint, or service counters
// on status.
type Response struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`

	Ack *Ack `json:"ack,omitempty"`

	// Checkpoint fields — the custody head, signed so a forged or
	// replayed checkpoint cannot realign the sender.
	Head            int64  `json:"head,omitempty"`
	HeadHash        string `json:"head_hash,omitempty"`
	LastExecutionID string `json:"last_execution_id,omitempty"`
	SignerEpoch     int64  `json:"signer_epoch,omitempty"`
	CheckpointSig   string `json:"checkpoint_sig,omitempty"`

	// Status fields.
	WitnessFP    string `json:"witness_fp,omitempty"`
	DeploymentID string `json:"deployment_id,omitempty"`
	Records      int64  `json:"records,omitempty"`
}

// Ack is the witness's countersignature — independent proof that a
// specific envelope for a specific execution reached custody at a
// specific sequence under a specific deployment identity, signed by
// the witness's custodian key at a specific signer epoch.
type Ack struct {
	WitnessFP    string `json:"witness_fp"`
	SignerEpoch  int64  `json:"signer_epoch"`
	DeploymentID string `json:"deployment_id"`
	Family       string `json:"family"`
	Seq          int64  `json:"seq"`
	ExecutionID  string `json:"execution_id"`
	EnvelopeHash string `json:"envelope_hash"`
	Signature    string `json:"signature"`
}

func ackFields(a *Ack) []string {
	return []string{
		a.WitnessFP,
		strconv.FormatInt(a.SignerEpoch, 10),
		a.DeploymentID,
		a.Family,
		strconv.FormatInt(a.Seq, 10),
		a.ExecutionID,
		a.EnvelopeHash,
	}
}

// SignAck produces the witness's countersignature over the custody
// position it just committed.
func SignAck(signer *evidence.Signer, signerEpoch int64, env *custody.Envelope, envelopeHash string) (*Ack, error) {
	a := &Ack{
		WitnessFP:    signer.Fingerprint(),
		SignerEpoch:  signerEpoch,
		DeploymentID: env.DeploymentID,
		Family:       env.Family,
		Seq:          env.Sequence.Index,
		ExecutionID:  env.Subject.ExecutionID,
		EnvelopeHash: envelopeHash,
	}
	sig, err := signer.SignRecord(ackDomain, ackFields(a)...)
	if err != nil {
		return nil, err
	}
	a.Signature = sig
	return a, nil
}

// VerifyAck is the recording boundary's own check on an
// acknowledgement — independent of whatever the transport peer
// claimed. The ack must bind the exact envelope submitted (hash,
// sequence, execution, deployment, family) and verify under a
// custodian key pinned in the trust set for that sequence index —
// so a forged ack, an ack under an unpinned key, or an ack replayed
// against different evidence all refuse here.
func VerifyAck(a *Ack, env *custody.Envelope, trust *custody.TrustSet) error {
	if a == nil {
		return fmt.Errorf("custody witness returned no acknowledgement")
	}
	if trust.Empty() {
		return fmt.Errorf("no custodian trust set declared — a self-declared acknowledgement is not evidence")
	}
	envHash, err := env.Hash()
	if err != nil {
		return err
	}
	if a.EnvelopeHash != envHash || a.Seq != env.Sequence.Index ||
		a.ExecutionID != env.Subject.ExecutionID || a.DeploymentID != env.DeploymentID ||
		a.Family != env.Family {
		return fmt.Errorf("custody acknowledgement does not bind this envelope (hash, sequence, execution, deployment, or family differs)")
	}
	pub, err := trust.Resolve(custody.RoleCustodian, a.DeploymentID, a.WitnessFP, a.Seq)
	if err != nil {
		return err
	}
	return evidence.VerifyRecordSignature(pub, ackDomain, a.Signature, ackFields(a)...)
}

// CheckpointHead is the signed custody head the sender realigns to.
type CheckpointHead struct {
	Seq             int64
	Hash            string
	LastExecutionID string
	SignerEpoch     int64
	WitnessFP       string
	Signature       string
}

func checkpointFields(deploymentID string, h *CheckpointHead) []string {
	return []string{
		h.WitnessFP,
		strconv.FormatInt(h.SignerEpoch, 10),
		deploymentID,
		strconv.FormatInt(h.Seq, 10),
		h.Hash,
		h.LastExecutionID,
	}
}

// SignCheckpoint signs the custody head the service reports.
func SignCheckpoint(signer *evidence.Signer, deploymentID string, h *CheckpointHead) (*CheckpointHead, error) {
	h.WitnessFP = signer.Fingerprint()
	sig, err := signer.SignRecord(checkpointDomain, checkpointFields(deploymentID, h)...)
	if err != nil {
		return nil, err
	}
	h.Signature = sig
	return h, nil
}

// VerifyCheckpoint checks a reported custody head under a pinned
// custodian key. A checkpoint signed by anything else — or binding a
// different deployment — is not a realignment authority: the sender
// degrades rather than trusting it.
func VerifyCheckpoint(h *CheckpointHead, deploymentID string, trust *custody.TrustSet) error {
	if trust.Empty() {
		return fmt.Errorf("no custodian trust set declared — a self-declared checkpoint is not evidence")
	}
	pub, err := trust.ResolveAny(custody.RoleCustodian, deploymentID, h.WitnessFP)
	if err != nil {
		return err
	}
	return evidence.VerifyRecordSignature(pub, checkpointDomain, h.Signature, checkpointFields(deploymentID, h)...)
}

// EnvelopeFromFrame decodes a submission envelope back to its native
// receipt bytes — the adapter boundary between the typed contract and
// the receipt family's native record.
func EnvelopeFromFrame(env *custody.Envelope) ([]byte, error) {
	return env.ContentBytes()
}

// MaxRequestBytes bounds one framed request — submissions carry a
// receipt envelope (~tens of KiB); a generous cap with headroom.
const maxRequestBytes = 4 * 1024 * 1024

// decodeAck re-parses a stored acknowledgement.
func decodeAck(raw string) (*Ack, error) {
	a := &Ack{}
	if err := json.Unmarshal([]byte(raw), a); err != nil {
		return nil, fmt.Errorf("stored acknowledgement does not parse: %w", err)
	}
	return a, nil
}
