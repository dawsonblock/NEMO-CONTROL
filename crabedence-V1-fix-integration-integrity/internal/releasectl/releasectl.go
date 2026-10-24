// Package releasectl implements the operator release-control ledger:
// a signed, append-only record of control events (halt, resume, revoke,
// unrevoke, stage, stage-clear) whose fold produces the effective
// release-control state for a deployment.
//
// Design (docs/rc8/ADRs/0002-operator-controls.md):
//
//   - The ledger is the sole source of control truth. No marker file,
//     no in-memory flag, no rm/unlink clears a restriction — state is
//     reconstructed from the event chain on every open.
//   - Tightening events (halt, revoke) may be unsigned: emergency stop
//     never waits on key availability, and an unsigned event can only
//     tighten state. If a signature is present it must verify.
//   - Relaxing events (resume, unrevoke, stage, stage-clear) require a
//     valid Ed25519 signature whose signer fingerprint is in the
//     externally provisioned trust root. An empty trust root fails
//     closed — nothing relaxes.
//   - The public key travels inside the event for verification
//     convenience, but trust is decided ONLY by fingerprint membership
//     in the externally supplied allowlist — keys are never learned
//     from the data being verified.
//   - Ordering is sequence/checkpoint, not wall clock: each event
//     carries sequence = prior+1 and prev_event_hash = SHA-256 of the
//     prior record's canonical bytes. Timestamps are audit-only.
//   - A monotonic checkpoint (sequence + head hash + epoch), held at a
//     deployment-configurable path so it can live outside the writable
//     runtime's authority, anchors which relaxations are authorized.
//     Relaxations not covered by the checkpoint never take effect.
//     Checkpoint-vs-ledger conflicts refuse to open (fail closed).
//   - Epoch is the trust-root generation: events at an epoch older
//     than the ledger's maximum are stale and rejected.
package releasectl

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/openclaw/crabbox/internal/evidence"
)

// SchemaVersion is the only accepted control-event schema version.
const SchemaVersion = 1

// SigningDomain is the domain-separation prefix for event signatures.
// It is deliberately distinct from every other signed object in the
// system — a control signature can never be presented as an evidence
// receipt, custody acknowledgement, or anything else.
const SigningDomain = "nemo/releasectl/v1"

// Event kinds.
const (
	KindHalt       = "halt"        // tighten: stop new effect admissions
	KindResume     = "resume"      // relax: clear halt (signed)
	KindRevoke     = "revoke"      // tighten: revoke release authorization
	KindUnrevoke   = "unrevoke"    // relax: clear revoke (signed)
	KindStage      = "stage"       // relax: promote to a stage level (signed, evidence-bound)
	KindStageClear = "stage-clear" // relax: clear staged level (signed)
)

// RoleOperator is the signer role authorized for all event kinds.
// breakglass recovery operators use the same trust-root mechanism with
// role "breakglass"; both roles must be allowlisted, and the role is
// bound into the signed preimage so a signature cannot be replayed
// across roles.
const (
	RoleOperator   = "operator"
	RoleBreakGlass = "breakglass"
)

// Event is a canonical ControlEventV1 record. All fields except
// Signature are covered by the signature preimage. PublicKey is
// integrity-bound by signer_key_id (its SHA-256 fingerprint) but is
// never a trust source.
type Event struct {
	SchemaVersion int      `json:"schema_version"`
	EventID       string   `json:"event_id"`
	Kind          string   `json:"kind"`
	Deployment    string   `json:"deployment"`
	ReleaseDigest string   `json:"release_digest"`
	PolicyDigest  string   `json:"policy_digest"`
	SignerRole    string   `json:"signer_role"`
	SignerKeyID   string   `json:"signer_key_id"`
	Sequence      uint64   `json:"sequence"`
	Epoch         uint64   `json:"epoch"`
	PrevEventHash string   `json:"prev_event_hash"`
	PrevStateHash string   `json:"prev_state_hash"`
	Timestamp     string   `json:"timestamp"`
	Reason        string   `json:"reason"`
	EvidenceRefs  []string `json:"evidence_refs,omitempty"`
	Stage         int      `json:"stage,omitempty"`
	PublicKey     string   `json:"public_key,omitempty"`
	Signature     string   `json:"signature,omitempty"`
}

// KindTightens reports whether the event kind restricts state. Only
// tightening kinds may be unsigned.
func KindTightens(kind string) bool {
	return kind == KindHalt || kind == KindRevoke
}

// validKind reports whether kind is a known event kind.
func validKind(kind string) bool {
	switch kind {
	case KindHalt, KindResume, KindRevoke, KindUnrevoke, KindStage, KindStageClear:
		return true
	}
	return false
}

// genesisHash is the prev_event_hash of sequence-0 events — a domain-
// separated constant, not "" or an arbitrary value.
var genesisHash = hex.EncodeToString(func() []byte {
	sum := sha256.Sum256([]byte(SigningDomain + "\x00genesis"))
	return sum[:]
}())

// GenesisHash exposes the chain's anchor value.
func GenesisHash() string { return genesisHash }

// EventHash is the canonical identity of a stored event: SHA-256 over
// the deterministic JSON encoding of the complete record (signature
// included), so the chain binds the exact bytes that were appended.
func EventHash(e Event) string {
	data, _ := json.Marshal(e)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// signingValues is the ordered field list bound by the signature.
func (e Event) signingValues() []string {
	return []string{
		fmt.Sprint(e.SchemaVersion),
		e.EventID,
		e.Kind,
		e.Deployment,
		e.ReleaseDigest,
		e.PolicyDigest,
		e.SignerRole,
		e.SignerKeyID,
		fmt.Sprint(e.Sequence),
		fmt.Sprint(e.Epoch),
		e.PrevEventHash,
		e.PrevStateHash,
		e.Timestamp,
		e.Reason,
		strings.Join(e.EvidenceRefs, "\x1f"),
		fmt.Sprint(e.Stage),
	}
}

// SignEvent signs the event's canonical fields with signer and fills
// PublicKey, SignerKeyID, and Signature. The caller sets semantic
// fields first; SignerRole should normally be set to RoleOperator
// before calling.
func SignEvent(signer *evidence.Signer, e *Event) error {
	pub := signer.PublicKey()
	e.PublicKey = base64.StdEncoding.EncodeToString(pub)
	e.SignerKeyID = evidence.Fingerprint(pub)
	sig, err := signer.SignRecord(SigningDomain, e.signingValues()...)
	if err != nil {
		return err
	}
	e.Signature = sig
	return nil
}

// decodePublicKey returns the event's declared Ed25519 public key,
// verifying it matches signer_key_id. The caller decides trust via the
// allowlist — this only proves the key is self-consistent.
func (e Event) decodePublicKey() (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(e.PublicKey)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid event public_key")
	}
	if e.SignerKeyID != evidence.Fingerprint(ed25519.PublicKey(raw)) {
		return nil, fmt.Errorf("signer_key_id does not match public_key")
	}
	return ed25519.PublicKey(raw), nil
}

// HasSignature reports whether the event carries a signature.
func (e Event) HasSignature() bool { return e.Signature != "" }

// VerifySignature checks the event signature against its declared
// public key. It does NOT check trust-root membership — that is the
// verifier's job, applied separately so "cryptographically valid" can
// never substitute for "authorized".
func (e Event) VerifySignature() error {
	pub, err := e.decodePublicKey()
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(e.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("invalid event signature encoding")
	}
	payload, err := recordSigningBytes(e.signingValues())
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, payload, sig) {
		return fmt.Errorf("event signature invalid")
	}
	return nil
}

// recordSigningBytes mirrors evidence.recordSigningBytes for this
// domain — identical length-prefixed construction so a verifier
// implementation can be audited against a single framing.
func recordSigningBytes(values []string) ([]byte, error) {
	var payload bytes.Buffer
	payload.WriteString(SigningDomain)
	payload.WriteByte(0)
	var length [4]byte
	for _, value := range values {
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		payload.Write(length[:])
		payload.WriteString(value)
	}
	return payload.Bytes(), nil
}

// validateSchema enforces the ControlEventV1 contract independent of
// signature/trust: field shapes, kind vocabulary, kind-specific
// requirements (stage needs a level and evidence refs), and the
// digest formats.
func (e Event) validateSchema() error {
	if e.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported schema_version %d", e.SchemaVersion)
	}
	if !validKind(e.Kind) {
		return fmt.Errorf("unknown event kind %q", e.Kind)
	}
	for name, v := range map[string]string{
		"event_id":    e.EventID,
		"deployment":  e.Deployment,
		"signer_role": e.SignerRole,
		"reason":      e.Reason,
		"timestamp":   e.Timestamp,
	} {
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("invalid %s", name)
		}
	}
	if e.SignerRole != RoleOperator && e.SignerRole != RoleBreakGlass {
		return fmt.Errorf("unknown signer_role %q", e.SignerRole)
	}
	if e.ReleaseDigest != "" && !isHexDigest(e.ReleaseDigest) {
		return fmt.Errorf("invalid release_digest")
	}
	if e.PolicyDigest != "" && !isHexDigest(e.PolicyDigest) {
		return fmt.Errorf("invalid policy_digest")
	}
	if _, err := time.Parse(time.RFC3339Nano, e.Timestamp); err != nil {
		return fmt.Errorf("invalid timestamp")
	}
	if e.Kind == KindStage {
		if e.Stage <= 0 {
			return fmt.Errorf("stage event requires stage level")
		}
		if len(e.EvidenceRefs) == 0 {
			// Stage transitions bind qualification evidence — an
			// absent record is never read as approval (ADR-0002.7).
			return fmt.Errorf("stage event requires evidence_refs")
		}
	}
	if e.Kind != KindStage && e.Stage != 0 {
		return fmt.Errorf("stage level only valid on stage events")
	}
	return nil
}

// ParseEvent decodes one JSON record with strict handling: unknown
// fields rejected, duplicate keys rejected, single JSON value.
func ParseEvent(data []byte) (Event, error) {
	var e Event
	if len(data) == 0 {
		return e, fmt.Errorf("empty event record")
	}
	if len(data) > 64*1024 {
		return e, fmt.Errorf("event record exceeds 64KiB")
	}
	if dup, err := hasDuplicateKeys(bytes.NewReader(data)); err != nil {
		return e, err
	} else if dup {
		return e, fmt.Errorf("event record contains duplicate keys")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&e); err != nil {
		return e, err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return e, fmt.Errorf("multiple JSON values in record")
		}
		return e, err
	}
	return e, nil
}

func isHexDigest(s string) bool {
	if len(s) != sha256.Size*2 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// hasDuplicateKeys reports whether the top-level JSON object has
// duplicate keys.
func hasDuplicateKeys(r *bytes.Reader) (bool, error) {
	dec := json.NewDecoder(r)
	tok, err := dec.Token()
	if err != nil {
		return false, err
	}
	delim, ok := tok.(json.Delim)
	if !ok || delim != '{' {
		return false, fmt.Errorf("event record must be a JSON object")
	}
	seen := map[string]bool{}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return false, err
		}
		key := keyTok.(string)
		if seen[key] {
			return true, nil
		}
		seen[key] = true
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return false, err
		}
	}
	return false, nil
}
