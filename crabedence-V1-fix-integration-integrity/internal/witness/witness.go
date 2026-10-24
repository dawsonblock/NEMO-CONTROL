// Package witness implements the independent evidence-custody service
// and the kernel-side custody outbox.
//
// The custody boundary exists so the execution kernel cannot be the
// sole author of the evidence that qualifies it: terminal receipts are
// submitted to a separately administered witness that keeps an
// append-only per-deployment log, countersigns an acknowledgement, and
// refuses replays, gaps, foreign deployments, and forged receipts.
// The kernel keeps a durable outbox so witness loss never silently
// loses evidence — pending submissions redeliver on reconnect, and a
// checkpoint exchange at startup realigns both sides after restore.
package witness

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/openclaw/crabbox/internal/evidence"
)

// Protocol ops.
const (
	OpSubmit     = "submit"
	OpCheckpoint = "checkpoint"
	OpStatus     = "status"
)

const ackDomain = "crabedence-witness-ack-v1"

// Request is one custody operation on the wire.
type Request struct {
	Op            string `json:"op"`
	DeploymentFP  string `json:"deployment_fp"`
	Seq           int64  `json:"seq,omitempty"`
	ExecutionID   string `json:"execution_id,omitempty"`
	ReceiptDigest string `json:"receipt_digest,omitempty"`
	// Payload is the signed evidence receipt for CRITICAL resolutions
	// (a ReceiptV3 the witness verifies against the pinned deployment
	// signer). Empty for non-CRITICAL receipts — the custody object is
	// then the digest + sequence binding itself.
	Payload json.RawMessage `json:"payload,omitempty"`
}

// Response carries the operation result: an acknowledgement on submit,
// the custody head on checkpoint, or service counters on status.
type Response struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`

	Ack *Ack `json:"ack,omitempty"`

	// Checkpoint fields: the deployment's custody head — the highest
	// contiguous sequence the witness holds.
	Head              int64  `json:"head,omitempty"`
	LastExecutionID   string `json:"last_execution_id,omitempty"`
	LastReceiptDigest string `json:"last_receipt_digest,omitempty"`

	// Status fields.
	WitnessFP    string `json:"witness_fp,omitempty"`
	DeploymentFP string `json:"deployment_fp,omitempty"`
	Records      int64  `json:"records,omitempty"`
}

// Ack is the witness's countersignature — independent proof that a
// specific receipt for a specific execution reached custody at a
// specific sequence under a specific deployment identity.
type Ack struct {
	WitnessFP     string `json:"witness_fp"`
	DeploymentFP  string `json:"deployment_fp"`
	Seq           int64  `json:"seq"`
	ExecutionID   string `json:"execution_id"`
	ReceiptDigest string `json:"receipt_digest"`
	Signature     string `json:"signature"`
}

// ackSigningBytes builds the canonical signing payload — a domain
// separation prefix plus length-prefixed field values, the same
// construction evidence receipts use.
func ackSigningBytes(deploymentFP string, seq int64, executionID, receiptDigest string) []byte {
	var payload bytes.Buffer
	payload.WriteString(ackDomain)
	var length [4]byte
	put := func(s string) {
		binary.BigEndian.PutUint32(length[:], uint32(len(s)))
		payload.Write(length[:])
		payload.WriteString(s)
	}
	put(deploymentFP)
	put(fmt.Sprintf("%d", seq))
	put(executionID)
	put(receiptDigest)
	return payload.Bytes()
}

// SignAck produces the witness's signature over the ack fields.
func SignAck(signer *evidence.Signer, deploymentFP string, seq int64, executionID, receiptDigest string) *Ack {
	return &Ack{
		WitnessFP:     signer.Fingerprint(),
		DeploymentFP:  deploymentFP,
		Seq:           seq,
		ExecutionID:   executionID,
		ReceiptDigest: receiptDigest,
		Signature: base64.StdEncoding.EncodeToString(
			signer.SignBytes(ackSigningBytes(deploymentFP, seq, executionID, receiptDigest))),
	}
}

// VerifyAck checks an acknowledgement against the witness public key.
func VerifyAck(a *Ack, pub []byte) error {
	sig, err := base64.StdEncoding.DecodeString(a.Signature)
	if err != nil {
		return fmt.Errorf("ack signature is not base64: %w", err)
	}
	if len(pub) != 32 {
		return fmt.Errorf("witness public key is %d bytes, want 32", len(pub))
	}
	if a.Signature == "" || len(sig) != 64 {
		return fmt.Errorf("ack signature is %d bytes, want 64", len(sig))
	}
	payload := ackSigningBytes(a.DeploymentFP, a.Seq, a.ExecutionID, a.ReceiptDigest)
	if !ed25519.Verify(ed25519.PublicKey(pub), payload, sig) {
		return fmt.Errorf("ack signature does not verify under the witness key")
	}
	return nil
}
