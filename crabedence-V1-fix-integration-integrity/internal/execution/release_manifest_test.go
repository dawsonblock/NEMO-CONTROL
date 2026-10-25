package execution

// F-04 — the signed release manifest: the only channel through which
// a verified release identity reaches custody envelopes. Every
// negative is a real signature/key operation — a "fake" here is a
// second real signer, never a stub verification.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openclaw/crabbox/internal/evidence"
)

// manifestFixture is a well-formed manifest awaiting a signature.
func manifestFixture() *ReleaseManifest {
	return &ReleaseManifest{
		Schema:          ReleaseManifestSchema,
		Version:         "0.55.0-rc8.2-dev",
		SourceCommit:    strings.Repeat("a", 40),
		ArtifactSHA256:  strings.Repeat("b", 64),
		ArtifactKind:    ArtifactKindBinary,
		PolicyDigest:    strings.Repeat("c", 64),
		RegistryDigest:  strings.Repeat("d", 64),
		CustodyProtocol: "custody-envelope-v1",
	}
}

// signManifest signs the fixture and returns (signed bytes, signers).
func signManifest(t *testing.T, m *ReleaseManifest) ([]byte, ReleaseSigners) {
	t.Helper()
	signer, err := evidence.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := SignReleaseManifest(signer, m)
	if err != nil {
		t.Fatal(err)
	}
	return raw, ReleaseSigners{signer.Fingerprint(): signer.PublicKey()}
}

// TestReleaseManifestRoundTrip: a signed manifest verifies and yields
// the bound release identity.
func TestReleaseManifestRoundTrip(t *testing.T) {
	m := manifestFixture()
	raw, signers := signManifest(t, m)
	got, err := ParseReleaseManifest(raw, signers)
	if err != nil {
		t.Fatalf("valid manifest rejected: %v", err)
	}
	if got.Version != m.Version || got.SourceCommit != m.SourceCommit ||
		got.ArtifactSHA256 != m.ArtifactSHA256 || got.PolicyDigest != m.PolicyDigest ||
		got.RegistryDigest != m.RegistryDigest || got.CustodyProtocol != m.CustodyProtocol {
		t.Fatalf("verified manifest mutated: %+v", got)
	}
	if got.SignerFingerprint == "" {
		t.Fatal("manifest carries no signer identity")
	}
}

// TestReleaseManifestTamperedRejected: every signed-field mutation
// invalidates the signature — no field of the identity is malleable.
func TestReleaseManifestTamperedRejected(t *testing.T) {
	mutations := map[string]func(*ReleaseManifest){
		"version":       func(m *ReleaseManifest) { m.Version = "0.55.0-rc8.3-dev" },
		"source commit": func(m *ReleaseManifest) { m.SourceCommit = strings.Repeat("f", 40) },
		"artifact":      func(m *ReleaseManifest) { m.ArtifactSHA256 = strings.Repeat("e", 64) },
		"policy":        func(m *ReleaseManifest) { m.PolicyDigest = strings.Repeat("9", 64) },
		"registry":      func(m *ReleaseManifest) { m.RegistryDigest = strings.Repeat("8", 64) },
		"protocol":      func(m *ReleaseManifest) { m.CustodyProtocol = "" },
		"signer":        func(m *ReleaseManifest) { m.SignerFingerprint = strings.Repeat("1", 64) },
		"signature":     func(m *ReleaseManifest) { m.Signature = m.Signature[:len(m.Signature)-4] + "AAAA" },
		"artifact kind": func(m *ReleaseManifest) { m.ArtifactKind = ArtifactKindSourceArchive },
		"schema":        func(m *ReleaseManifest) { m.Schema = "release-manifest-v2" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			m := manifestFixture()
			raw, signers := signManifest(t, m)
			var got ReleaseManifest
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Fatal(err)
			}
			mutate(&got)
			mutated, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParseReleaseManifest(mutated, signers); err == nil {
				t.Fatalf("manifest with tampered %s verified", name)
			}
		})
	}
}

// TestReleaseManifestUnauthorizedSignerRejected: a valid signature
// from a key outside the pinned release-authority set is not a
// release identity — signature correctness is necessary, not
// sufficient.
func TestReleaseManifestUnauthorizedSignerRejected(t *testing.T) {
	m := manifestFixture()
	signer, err := evidence.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := SignReleaseManifest(signer, m)
	if err != nil {
		t.Fatal(err)
	}
	// Trust set pins a DIFFERENT real key.
	other, err := evidence.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseReleaseManifest(raw, ReleaseSigners{other.Fingerprint(): other.PublicKey()}); err == nil {
		t.Fatal("manifest signed by an unauthorized release key verified")
	}
}

// TestReleaseManifestShapeRejected: a well-signed but malformed
// manifest is a fault, not an identity — empty mandatory fields,
// wrong digest widths, unknown kinds are all refused.
func TestReleaseManifestShapeRejected(t *testing.T) {
	cases := map[string]func(*ReleaseManifest){
		"empty version":    func(m *ReleaseManifest) { m.Version = "" },
		"bad commit":       func(m *ReleaseManifest) { m.SourceCommit = "not-a-commit" },
		"bad artifact":     func(m *ReleaseManifest) { m.ArtifactSHA256 = "deadbeef" },
		"empty policy":     func(m *ReleaseManifest) { m.PolicyDigest = "" },
		"bad kind":         func(m *ReleaseManifest) { m.ArtifactKind = "container" },
		"foreign protocol": func(m *ReleaseManifest) { m.CustodyProtocol = "custody-envelope-v9" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			m := manifestFixture()
			mutate(m)
			raw, signers := signManifest(t, m)
			if _, err := ParseReleaseManifest(raw, signers); err == nil {
				t.Fatalf("manifest with %s verified", name)
			}
		})
	}
}

// TestReleaseManifestTreeIdentity: a 64-hex source-tree identity is an
// acceptable commit field — archives without git history still bind.
func TestReleaseManifestTreeIdentity(t *testing.T) {
	m := manifestFixture()
	m.SourceCommit = strings.Repeat("7", 64)
	raw, signers := signManifest(t, m)
	if _, err := ParseReleaseManifest(raw, signers); err != nil {
		t.Fatalf("tree-identity manifest rejected: %v", err)
	}
}

// TestReleaseSignersFileVerification: the trust file itself is
// verified — a declared fingerprint that does not match its key
// bytes is a fault, not an identity.
func TestReleaseSignersFileVerification(t *testing.T) {
	dir := t.TempDir()
	signer, err := evidence.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	write := func(body string) string {
		p := filepath.Join(dir, "signers.json")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	good := fmt.Sprintf(`{"version":1,"signers":[{"fingerprint":"%s","public_key":"%s"}]}`,
		signer.Fingerprint(), base64.StdEncoding.EncodeToString(signer.PublicKey()))
	signers, err := LoadReleaseSigners(write(good))
	if err != nil {
		t.Fatalf("valid signer file rejected: %v", err)
	}
	if _, ok := signers[signer.Fingerprint()]; !ok {
		t.Fatal("pinned signer missing")
	}
	// Fingerprint lies about the key bytes.
	lie := fmt.Sprintf(`{"version":1,"signers":[{"fingerprint":"%s","public_key":"%s"}]}`,
		strings.Repeat("0", 64), base64.StdEncoding.EncodeToString(signer.PublicKey()))
	if _, err := LoadReleaseSigners(write(lie)); err == nil {
		t.Fatal("trust file with a false fingerprint accepted")
	}
	// Malformed key bytes.
	bad := fmt.Sprintf(`{"version":1,"signers":[{"fingerprint":"%s","public_key":"AA=="}]}`,
		strings.Repeat("0", 64))
	if _, err := LoadReleaseSigners(write(bad)); err == nil {
		t.Fatal("trust file with malformed key bytes accepted")
	}
}

// TestReleaseManifestDeploymentAttestation: the running artifact
// must prove it IS the declared artifact — same digest passes, any
// other binary fails, and a source-archive kind cannot self-verify.
func TestReleaseManifestDeploymentAttestation(t *testing.T) {
	dir := t.TempDir()
	fixture := filepath.Join(dir, "crabbox-bin")
	payload := []byte("the exact release binary bytes")
	if err := os.WriteFile(fixture, payload, 0o700); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)

	orig := selfArtifactPath
	defer func() { selfArtifactPath = orig }()
	selfArtifactPath = func() (string, error) { return fixture, nil }

	m := manifestFixture()
	m.ArtifactSHA256 = hex.EncodeToString(sum[:])
	if err := m.VerifyDeployment(); err != nil {
		t.Fatalf("matching artifact refused: %v", err)
	}

	m.ArtifactSHA256 = strings.Repeat("9", 64)
	if err := m.VerifyDeployment(); err == nil {
		t.Fatal("different binary accepted as the signed release")
	}

	m.ArtifactSHA256 = hex.EncodeToString(sum[:])
	m.ArtifactKind = ArtifactKindSourceArchive
	if err := m.VerifyDeployment(); err == nil {
		t.Fatal("source-archive artifact claimed self-verification")
	}
}

// TestReleaseManifestLoadsFromFile: the config-time load path —
// manifest file + signer file — verifies end to end.
func TestReleaseManifestLoadsFromFile(t *testing.T) {
	dir := t.TempDir()
	m := manifestFixture()
	raw, signers := signManifest(t, m)
	var pub string
	for _, p := range signers {
		pub = base64.StdEncoding.EncodeToString(p)
	}
	signersFile := filepath.Join(dir, "signers.json")
	if err := os.WriteFile(signersFile,
		[]byte(fmt.Sprintf(`{"version":1,"signers":[{"fingerprint":"%s","public_key":"%s"}]}`, m.SignerFingerprint, pub)),
		0o600); err != nil {
		t.Fatal(err)
	}
	manifestFile := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(manifestFile, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadReleaseSigners(signersFile)
	if err != nil {
		t.Fatal(err)
	}
	got, err := LoadReleaseManifest(manifestFile, loaded)
	if err != nil {
		t.Fatalf("file-loaded manifest rejected: %v", err)
	}
	if got.Version != m.Version {
		t.Fatalf("version = %q, want %q", got.Version, m.Version)
	}
}
