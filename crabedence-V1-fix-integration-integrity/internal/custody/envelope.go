// Package custody implements the custody-envelope-v1 contract: the
// versioned typed envelope that unifies verification semantics for the
// receipt, sandbox-archive, and recovery-checkpoint evidence families
// without collapsing their distinct native wire protocols.
//
// Producers keep their native formats (internal/witness length-prefixed
// JSON frames, internal/sandboxcustody newline-delimited JSON); adapters
// wrap each native record in an envelope for verification, indexing, and
// cross-checking. The signature preimage is domain-separated per family,
// so a receipt signature can never verify as a sandbox-archive record.
package custody

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/openclaw/crabbox/internal/evidence"
)

// EnvelopeVersion is the contract version string. A record that does
// not declare it is refused — capability negotiation is explicit and a
// peer that cannot speak the contract is never silently downgraded.
const EnvelopeVersion = "custody-envelope-v1"

// Evidence families. Each family is a separate signature domain and an
// independent sequence domain.
const (
	FamilyReceipt            = "receipt"
	FamilySandboxArchive     = "sandbox_archive"
	FamilyRecoveryCheckpoint = "recovery_checkpoint"
)

// Native content encodings — the wire format the wrapped bytes came
// from, retained so the original record is never re-encoded.
const (
	EncodingWitnessFrame = "witness-frame-v1"
	EncodingNDJSON       = "sandboxcustody-ndjson-v1"
)

// Signer roles. Keys are pinned per role: a key trusted for one role
// cannot vouch under another.
const (
	RoleCustodian   = "custodian"
	RoleKernelRelay = "kernel-relay"
)

// families is the family allowlist — an unknown family is a typed
// rejection, never a fallback interpretation.
var families = map[string]bool{
	FamilyReceipt:            true,
	FamilySandboxArchive:     true,
	FamilyRecoveryCheckpoint: true,
}

// Typed verification rejections (spec §8). Every verify failure maps to
// exactly one of these — there is no downgrade path.
var (
	ErrVersion      = errors.New("custody envelope: unsupported contract version")
	ErrFamily       = errors.New("custody envelope: unknown or disallowed family")
	ErrDeployment   = errors.New("custody envelope: foreign deployment")
	ErrRelease      = errors.New("custody envelope: release identity mismatch")
	ErrPolicyDigest = errors.New("custody envelope: policy digest mismatch")
	ErrSequence     = errors.New("custody envelope: sequence violation")
	ErrContentHash  = errors.New("custody envelope: content hash does not match bytes")
	ErrEncoding     = errors.New("custody envelope: unknown content encoding")
	ErrUntrustedKey = errors.New("custody envelope: signer key is not pinned in the trust set")
	ErrSignature    = errors.New("custody envelope: signature invalid")
	ErrMalformed    = errors.New("custody envelope: malformed fields")
)

// ReleaseIdentity binds the envelope to a specific source/artifact
// identity. Fields are optional individually — the verifier pins the
// subset it requires.
type ReleaseIdentity struct {
	SourceCommit   string `json:"source_commit,omitempty"`
	Version        string `json:"version,omitempty"`
	ArtifactSHA256 string `json:"artifact_sha256,omitempty"`
}

// Subject names what the wrapped record attests. Receipt-family records
// carry effect_id/execution_id; sandbox families carry job_id and
// sandbox_uid.
type Subject struct {
	EffectID    string `json:"effect_id,omitempty"`
	ExecutionID string `json:"execution_id,omitempty"`
	JobID       string `json:"job_id,omitempty"`
	SandboxUID  string `json:"sandbox_uid,omitempty"`
}

// Sequence is the envelope's position in its family-scoped domain.
// Index is strictly monotone per (family, deployment, subject-stream);
// Epoch advances only by signed epoch-advance events; PreviousCheckpointHash
// chains the record to the prior head of the stream.
type Sequence struct {
	Domain                 string `json:"domain"`
	Epoch                  int64  `json:"epoch"`
	Index                  int64  `json:"index"`
	PreviousCheckpointHash string `json:"previous_checkpoint_hash,omitempty"`
}

// Content carries the native record opaquely: its hash, the native
// encoding tag, and the verbatim bytes.
type Content struct {
	Hash     string `json:"hash"`
	Encoding string `json:"encoding"`
	BytesB64 string `json:"bytes_b64"`
}

// SignerRef names the signing role and key the envelope claims. The key
// is only ever resolved against pinned trust configuration — key
// material presented inside a record is ignored.
type SignerRef struct {
	Role  string `json:"role"`
	KeyID string `json:"key_id"`
}

// Envelope is the custody-envelope-v1 record.
type Envelope struct {
	Envelope        string          `json:"envelope"`
	Family          string          `json:"family"`
	DeploymentID    string          `json:"deployment_id"`
	ReleaseIdentity ReleaseIdentity `json:"release_identity"`
	PolicyDigest    string          `json:"policy_digest"`
	Subject         Subject         `json:"subject"`
	Sequence        Sequence        `json:"sequence"`
	Content         Content         `json:"content"`
	Signer          SignerRef       `json:"signer"`
	Signature       string          `json:"signature,omitempty"`
}

// New builds an envelope over native record bytes: the content hash and
// bytes are derived from the record, never asserted.
func New(family, deploymentID string, rel ReleaseIdentity, policyDigest string, subj Subject, seq Sequence, encoding string, native []byte) *Envelope {
	sum := sha256.Sum256(native)
	return &Envelope{
		Envelope:        EnvelopeVersion,
		Family:          family,
		DeploymentID:    deploymentID,
		ReleaseIdentity: rel,
		PolicyDigest:    policyDigest,
		Subject:         subj,
		Sequence:        seq,
		Content: Content{
			Hash:     hex.EncodeToString(sum[:]),
			Encoding: encoding,
			BytesB64: base64.StdEncoding.EncodeToString(native),
		},
	}
}

// Hash is the envelope's content-independent identity — SHA-256 over
// the canonical signed form without the signature. Two envelopes are
// the same record iff their hashes are equal.
func (e *Envelope) Hash() (string, error) {
	canon, err := canonical(e)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canon)
	return hex.EncodeToString(sum[:]), nil
}

// ContentBytes decodes the verbatim native record.
func (e *Envelope) ContentBytes() ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(e.Content.BytesB64)
	if err != nil {
		return nil, fmt.Errorf("%w: bytes_b64 does not decode", ErrMalformed)
	}
	return raw, nil
}

// canonical returns the canonical JSON (RFC 8785 profile for this
// schema: sorted keys, no insignificant whitespace, no HTML escaping)
// of the envelope minus the signature field — the bytes the signature
// commits to. Strings, integers, and nested objects are the only
// value kinds the schema permits, for which Go's sorted-key compact
// emission with escaping disabled is JCS-equivalent.
func canonical(e *Envelope) ([]byte, error) {
	without := *e
	without.Signature = ""
	raw, err := json.Marshal(without)
	if err != nil {
		return nil, fmt.Errorf("canonicalize envelope: %w", err)
	}
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("canonicalize envelope: %w", err)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(m); err != nil {
		return nil, fmt.Errorf("canonicalize envelope: %w", err)
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// SigningBytes builds the domain-separated signature preimage:
//
//	"custody-envelope-v1" || 0x00 || family || 0x00 || jcs(envelope-sans-signature)
//
// The family is literal and mandatory — a signature minted under one
// family can never verify under another.
func SigningBytes(e *Envelope) ([]byte, error) {
	canon, err := canonical(e)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.WriteString(EnvelopeVersion)
	buf.WriteByte(0)
	buf.WriteString(e.Family)
	buf.WriteByte(0)
	buf.Write(canon)
	return buf.Bytes(), nil
}

// Sign fills the signer reference and signature on the envelope. The
// key_id is the signer's fingerprint; trust resolution at verification
// decides whether that key may vouch.
func Sign(e *Envelope, role string, signer *evidence.Signer) error {
	e.Signer = SignerRef{Role: role, KeyID: signer.Fingerprint()}
	pre, err := SigningBytes(e)
	if err != nil {
		return err
	}
	e.Signature = base64.StdEncoding.EncodeToString(signer.SignBytes(pre))
	return nil
}

// SeqExpect is the optional sequence-state check a verifier applies:
// the record must land exactly at the expected index and chain to the
// expected previous checkpoint hash, at an epoch no older than
// witnessed before.
type SeqExpect struct {
	Index    int64  // exact index required; 0 means "no index check"
	PrevHash string // expected previous_checkpoint_hash when Index > 0
	MinEpoch int64  // minimum acceptable epoch
}

// VerifyOptions carries the externally pinned verification policy. No
// field here is learned from the record under verification.
type VerifyOptions struct {
	// DeploymentID is the required deployment identity. Empty means
	// any deployment is accepted (development posture only).
	DeploymentID string
	// ReleaseIdentity, when set, pins the non-empty fields: a record
	// whose release identity disagrees is rejected.
	ReleaseIdentity *ReleaseIdentity
	// PolicyDigest, when set, must equal the record's policy digest.
	PolicyDigest string
	// AllowFamilies restricts the family allowlist further. Nil admits
	// every contract family.
	AllowFamilies map[string]bool
	// Trust is the pinned key set. Empty fails closed.
	Trust *TrustSet
	// Seq, when set, is the sequence-state expectation.
	Seq *SeqExpect
}

// Verify runs the spec §8 verification pipeline, in order: version →
// family allowlist → deployment → release binding → policy digest →
// sequence → content hash vs bytes → signature under the family domain
// with a pinned key. Every failure is a typed rejection.
func Verify(e *Envelope, o VerifyOptions) error {
	if e == nil {
		return fmt.Errorf("%w: nil envelope", ErrMalformed)
	}
	if e.Envelope != EnvelopeVersion {
		return fmt.Errorf("%w: got %q", ErrVersion, e.Envelope)
	}
	if !families[e.Family] || (o.AllowFamilies != nil && !o.AllowFamilies[e.Family]) {
		return fmt.Errorf("%w: %q", ErrFamily, e.Family)
	}
	if o.DeploymentID != "" && e.DeploymentID != o.DeploymentID {
		return fmt.Errorf("%w: record names %q, this boundary custodies %q", ErrDeployment, e.DeploymentID, o.DeploymentID)
	}
	if rel := o.ReleaseIdentity; rel != nil {
		if rel.SourceCommit != "" && e.ReleaseIdentity.SourceCommit != rel.SourceCommit {
			return fmt.Errorf("%w: source_commit %q != pinned %q", ErrRelease, e.ReleaseIdentity.SourceCommit, rel.SourceCommit)
		}
		if rel.Version != "" && e.ReleaseIdentity.Version != rel.Version {
			return fmt.Errorf("%w: version %q != pinned %q", ErrRelease, e.ReleaseIdentity.Version, rel.Version)
		}
		if rel.ArtifactSHA256 != "" && e.ReleaseIdentity.ArtifactSHA256 != rel.ArtifactSHA256 {
			return fmt.Errorf("%w: artifact_sha256 %q != pinned %q", ErrRelease, e.ReleaseIdentity.ArtifactSHA256, rel.ArtifactSHA256)
		}
	}
	if o.PolicyDigest != "" && e.PolicyDigest != o.PolicyDigest {
		return fmt.Errorf("%w: record %q != pinned %q", ErrPolicyDigest, e.PolicyDigest, o.PolicyDigest)
	}
	if e.Sequence.Index < 1 || e.Sequence.Domain == "" {
		return fmt.Errorf("%w: index %d, empty domain", ErrSequence, e.Sequence.Index)
	}
	if seq := o.Seq; seq != nil {
		if seq.Index > 0 && e.Sequence.Index != seq.Index {
			return fmt.Errorf("%w: index %d does not extend the custody head %d", ErrSequence, e.Sequence.Index, seq.Index-1)
		}
		if e.Sequence.Epoch < seq.MinEpoch {
			return fmt.Errorf("%w: epoch %d is behind witnessed epoch %d — prior-epoch replay", ErrSequence, e.Sequence.Epoch, seq.MinEpoch)
		}
		if seq.Index > 0 && e.Sequence.PreviousCheckpointHash != seq.PrevHash {
			return fmt.Errorf("%w: checkpoint linkage broken — previous_checkpoint_hash does not match the stored head", ErrSequence)
		}
	}
	if e.Content.Hash == "" || e.Content.BytesB64 == "" {
		return fmt.Errorf("%w: empty content", ErrMalformed)
	}
	switch e.Content.Encoding {
	case EncodingWitnessFrame, EncodingNDJSON:
	default:
		return fmt.Errorf("%w: %q", ErrEncoding, e.Content.Encoding)
	}
	raw, err := e.ContentBytes()
	if err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != e.Content.Hash {
		return fmt.Errorf("%w: declared %q, bytes derive %q", ErrContentHash, e.Content.Hash, hex.EncodeToString(sum[:]))
	}
	if e.Signer.Role == "" || e.Signer.KeyID == "" || e.Signature == "" {
		return fmt.Errorf("%w: unsigned or unscoped signer", ErrMalformed)
	}
	if o.Trust.Empty() {
		return fmt.Errorf("%w: empty trust set — no record is verifiable", ErrUntrustedKey)
	}
	pub, err := o.Trust.Resolve(e.Signer.Role, e.DeploymentID, e.Signer.KeyID, e.Sequence.Index)
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(e.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%w: signature is not a 64-byte base64 value", ErrSignature)
	}
	pre, err := SigningBytes(e)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, pre, sig) {
		return fmt.Errorf("%w under key %s (role %s)", ErrSignature, e.Signer.KeyID, e.Signer.Role)
	}
	return nil
}
