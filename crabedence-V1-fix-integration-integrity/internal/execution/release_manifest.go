package execution

// F-04: the signed release manifest — the trusted release identity
// every custody envelope binds. The manifest is produced by the
// release pipeline and signed by an authorized release key; the
// runtime verifies it against a pinned signer set and binds the
// verified identity into every receipt-family envelope. The artifact
// digest is bound externally (the manifest declares it; the running
// binary proves membership by hashing itself) — never a circular
// archive-inside-archive hash.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/openclaw/crabbox/internal/evidence"
)

// ReleaseManifestSchema is the only accepted manifest schema tag.
const ReleaseManifestSchema = "release-manifest-v1"

// releaseManifestDomain is the signature domain — distinct from the
// effect-receipt and custody domains, so a manifest signature can
// never be replayed as another record class.
const releaseManifestDomain = "release-manifest-v1\x00"

// Artifact kinds the manifest may declare. "binary" is verified
// against the running executable's own SHA-256; "source-archive"
// binds a distribution archive digest that cannot be self-verified by
// the running process and is therefore admitted only below the
// high-assurance profile.
const (
	ArtifactKindBinary        = "binary"
	ArtifactKindSourceArchive = "source-archive"
)

// ReleaseManifest is the signed release-manifest-v1 document.
type ReleaseManifest struct {
	Schema            string `json:"schema"`
	Version           string `json:"version"`
	SourceCommit      string `json:"source_commit"`
	ArtifactSHA256    string `json:"artifact_sha256"`
	ArtifactKind      string `json:"artifact_kind"`
	PolicyDigest      string `json:"policy_digest"`
	RegistryDigest    string `json:"registry_digest,omitempty"`
	CustodyProtocol   string `json:"custody_protocol"`
	SignerFingerprint string `json:"signer_fingerprint"`
	Signature         string `json:"signature"`
}

// signingFields is the exact field vector the signature commits to,
// in order. Any mutation of a signed field invalidates the signature.
func (m *ReleaseManifest) signingFields() []string {
	return []string{
		m.Schema,
		m.Version,
		m.SourceCommit,
		m.ArtifactSHA256,
		m.ArtifactKind,
		m.PolicyDigest,
		m.RegistryDigest,
		m.CustodyProtocol,
		m.SignerFingerprint,
	}
}

// SignReleaseManifest produces the signed manifest bytes for an
// authorized release key — the producer half the release pipeline
// uses. Fields are taken from m verbatim.
func SignReleaseManifest(signer *evidence.Signer, m *ReleaseManifest) ([]byte, error) {
	m.SignerFingerprint = signer.Fingerprint()
	sig, err := signer.SignRecord(releaseManifestDomain, m.signingFields()...)
	if err != nil {
		return nil, err
	}
	m.Signature = sig
	return json.Marshal(m)
}

// ReleaseSigners is the pinned release-authority key set — the only
// keys whose signatures make a manifest trustworthy. Loaded from a
// JSON file provisioned outside the runtime's authority:
//
//	{"version":1,"signers":[{"fingerprint":"<hex>","public_key":"<b64 ed25519>"}]}
type ReleaseSigners map[string][]byte

// LoadReleaseSigners parses the pinned signer file.
func LoadReleaseSigners(path string) (ReleaseSigners, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("release signers: %w", err)
	}
	var doc struct {
		Version int `json:"version"`
		Signers []struct {
			Fingerprint string `json:"fingerprint"`
			PublicKey   string `json:"public_key"`
		} `json:"signers"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("release signers parse: %w", err)
	}
	if doc.Version != 1 || len(doc.Signers) == 0 {
		return nil, fmt.Errorf("release signers: version 1 with at least one signer required")
	}
	out := ReleaseSigners{}
	for _, s := range doc.Signers {
		pub, err := base64.StdEncoding.DecodeString(s.PublicKey)
		if err != nil || len(pub) != 32 {
			return nil, fmt.Errorf("release signers: signer %s has a malformed public key", s.Fingerprint)
		}
		fp := strings.ToLower(strings.TrimSpace(s.Fingerprint))
		// The declared fingerprint must be the key's real fingerprint —
		// a trust file that names a different identity for these bytes
		// is itself a fault.
		if want := releaseKeyFingerprint(pub); fp != want {
			return nil, fmt.Errorf("release signers: declared fingerprint %s does not match key bytes (%s)", fp, want)
		}
		out[fp] = pub
	}
	return out, nil
}

// releaseKeyFingerprint derives the evidence fingerprint of a raw
// Ed25519 public key — same construction the signer's Fingerprint()
// reports.
func releaseKeyFingerprint(pub []byte) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

// LoadReleaseManifest reads and verifies a signed manifest against
// the pinned release signer set. Verification order: schema → field
// shape → signer membership → signature. A manifest that parses but
// fails any check is refused — an attacker-controlled manifest is
// never a release identity.
func LoadReleaseManifest(path string, signers ReleaseSigners) (*ReleaseManifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("release manifest: %w", err)
	}
	return ParseReleaseManifest(raw, signers)
}

// ParseReleaseManifest verifies manifest bytes against the pinned
// signer set.
func ParseReleaseManifest(raw []byte, signers ReleaseSigners) (*ReleaseManifest, error) {
	if len(signers) == 0 {
		return nil, fmt.Errorf("release manifest: no pinned release signers — nothing can be verified")
	}
	var m ReleaseManifest
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("release manifest parse: %w", err)
	}
	if err := m.validateShape(); err != nil {
		return nil, err
	}
	pub, ok := signers[strings.ToLower(m.SignerFingerprint)]
	if !ok {
		return nil, fmt.Errorf("release manifest: signer %s is not an authorized release identity", m.SignerFingerprint)
	}
	if err := evidence.VerifyRecordSignature(pub, releaseManifestDomain, m.Signature, m.signingFields()...); err != nil {
		return nil, fmt.Errorf("release manifest: %v", err)
	}
	return &m, nil
}

// validateShape enforces the manifest's field invariants before the
// signature check — a well-signed but malformed manifest is still a
// fault, not an identity.
func (m *ReleaseManifest) validateShape() error {
	if m.Schema != ReleaseManifestSchema {
		return fmt.Errorf("release manifest: schema %q, want %s", m.Schema, ReleaseManifestSchema)
	}
	if m.Version == "" {
		return fmt.Errorf("release manifest: empty version")
	}
	if !isHex(m.SourceCommit, 40) && !isHex(m.SourceCommit, 64) {
		return fmt.Errorf("release manifest: source_commit %q is not a commit (40-hex) or source-tree identity (64-hex)", m.SourceCommit)
	}
	if !isHex(m.ArtifactSHA256, 64) {
		return fmt.Errorf("release manifest: artifact_sha256 %q is not a 64-hex digest", m.ArtifactSHA256)
	}
	switch m.ArtifactKind {
	case ArtifactKindBinary, ArtifactKindSourceArchive:
	default:
		return fmt.Errorf("release manifest: artifact_kind %q is not %s or %s", m.ArtifactKind, ArtifactKindBinary, ArtifactKindSourceArchive)
	}
	if m.PolicyDigest == "" {
		return fmt.Errorf("release manifest: empty policy digest — high-assurance custody requires the exact policy identity")
	}
	if m.CustodyProtocol != "" && m.CustodyProtocol != "custody-envelope-v1" {
		return fmt.Errorf("release manifest: custody_protocol %q is not custody-envelope-v1", m.CustodyProtocol)
	}
	if m.SignerFingerprint == "" {
		return fmt.Errorf("release manifest: empty signer fingerprint")
	}
	return nil
}

func isHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// selfArtifactPath is the path whose SHA-256 must equal the manifest's
// artifact digest for a binary artifact — the deployment attestation.
// Package-level so tests can point it at fixture bytes.
var selfArtifactPath = func() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(exe)
}

// VerifyDeployment checks the manifest's deployment attestation: for a
// binary artifact the running executable's own SHA-256 must equal the
// declared artifact digest — the running code proves it IS the
// authorized release rather than asserting a version. For a
// source-archive artifact no self-verification exists; the caller
// decides whether its profile accepts the weaker binding.
func (m *ReleaseManifest) VerifyDeployment() error {
	if m.ArtifactKind != ArtifactKindBinary {
		return fmt.Errorf("artifact kind %q cannot self-verify — binary artifact required", m.ArtifactKind)
	}
	path, err := selfArtifactPath()
	if err != nil {
		return fmt.Errorf("deployment artifact: %w", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("deployment artifact read: %w", err)
	}
	sum := sha256.Sum256(raw)
	got := hex.EncodeToString(sum[:])
	if got != m.ArtifactSHA256 {
		return fmt.Errorf("deployment artifact sha256 %s does not match authorized release %s — this binary is not the signed release", got, m.ArtifactSHA256)
	}
	return nil
}
