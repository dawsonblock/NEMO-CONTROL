package execution

// F-05 — the deployment assurance profile: a declared, startup-verified
// custody posture. Every invalid configuration fails closed, and no
// combination of flags lets a weaker deployment claim independently
// custodied production.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// profileConfig builds a config carrying exactly the prerequisites
// under test.
func profileConfig(production bool, wc WitnessConfig, release *ReleaseManifest) *ServiceConfig {
	return &ServiceConfig{production: production, Witness: wc, Release: release}
}

var haWitness = WitnessConfig{
	TLSAddr:  "custody.internal:9443",
	TLSKeyFP: strings.Repeat("a", 64),
}

// TestAssuranceProfileResolution: defaults resolve to the weakest
// profile the mode tolerates; explicit values resolve only when their
// prerequisites verify.
func TestAssuranceProfileResolution(t *testing.T) {
	t.Setenv("CRABEDENCE_ASSURANCE_PROFILE", "")
	if p, err := resolveAssuranceProfile(profileConfig(false, WitnessConfig{}, nil)); err != nil || p != AssuranceDevelopment {
		t.Fatalf("dev default = %q/%v, want development", p, err)
	}
	if p, err := resolveAssuranceProfile(profileConfig(true, WitnessConfig{}, nil)); err != nil || p != AssuranceReduced {
		t.Fatalf("prod default = %q/%v, want reduced", p, err)
	}
	t.Setenv("CRABEDENCE_ASSURANCE_PROFILE", "reduced")
	if p, err := resolveAssuranceProfile(profileConfig(true, WitnessConfig{}, nil)); err != nil || p != AssuranceReduced {
		t.Fatalf("explicit reduced = %q/%v", p, err)
	}
}

// TestAssuranceProfileInvalidValuesFail: every unrecognized or
// contradictory declaration is a startup error — a generic
// "production" string is never a profile.
func TestAssuranceProfileInvalidValuesFail(t *testing.T) {
	for _, v := range []string{"production", "high", "ha", "independent", "yes", "1"} {
		t.Setenv("CRABEDENCE_ASSURANCE_PROFILE", v)
		if _, err := resolveAssuranceProfile(profileConfig(true, haWitness, nil)); err == nil {
			t.Fatalf("profile %q resolved", v)
		}
	}
}

// TestAssuranceDevelopmentUnderProductionRefused: production mode may
// not declare the development profile — the weakest posture is below
// the production floor.
func TestAssuranceDevelopmentUnderProductionRefused(t *testing.T) {
	t.Setenv("CRABEDENCE_ASSURANCE_PROFILE", "development")
	if _, err := resolveAssuranceProfile(profileConfig(true, WitnessConfig{}, nil)); err == nil {
		t.Fatal("development profile accepted under production")
	}
}

// TestAssuranceHighAssuranceRequiresProduction: the strongest profile
// requires production mode — a development deployment cannot claim
// independently custodied authority.
func TestAssuranceHighAssuranceRequiresProduction(t *testing.T) {
	t.Setenv("CRABEDENCE_ASSURANCE_PROFILE", "high-assurance")
	if _, err := resolveAssuranceProfile(profileConfig(false, haWitness, validBinaryManifest(t))); err == nil {
		t.Fatal("high-assurance accepted outside production")
	}
}

// TestAssuranceHighAssurancePrerequisites: each missing prerequisite
// fails closed — witness absent, same-host socket only, no verified
// manifest, non-binary artifact, wrong binary.
func TestAssuranceHighAssurancePrerequisites(t *testing.T) {
	t.Setenv("CRABEDENCE_ASSURANCE_PROFILE", "high-assurance")

	if _, err := resolveAssuranceProfile(profileConfig(true, WitnessConfig{}, validBinaryManifest(t))); err == nil {
		t.Fatal("high-assurance accepted with no witness")
	}
	socketOnly := WitnessConfig{Socket: "/run/custody/w.sock"}
	if _, err := resolveAssuranceProfile(profileConfig(true, socketOnly, validBinaryManifest(t))); err == nil {
		t.Fatal("high-assurance accepted a same-host socket witness")
	}
	if _, err := resolveAssuranceProfile(profileConfig(true, haWitness, nil)); err == nil {
		t.Fatal("high-assurance accepted without a verified release manifest")
	}
	archive := manifestFixture()
	archive.ArtifactKind = ArtifactKindSourceArchive
	if _, err := resolveAssuranceProfile(profileConfig(true, haWitness, archive)); err == nil {
		t.Fatal("high-assurance accepted a source-archive artifact it cannot self-verify")
	}
	wrong := validBinaryManifest(t)
	wrong.ArtifactSHA256 = strings.Repeat("9", 64)
	if _, err := resolveAssuranceProfile(profileConfig(true, haWitness, wrong)); err == nil {
		t.Fatal("high-assurance accepted a binary that is not the signed release")
	}
}

// TestAssuranceHighAssuranceResolves: the full prerequisite set —
// production, separate-host witness, verified manifest, matching
// binary — resolves.
func TestAssuranceHighAssuranceResolves(t *testing.T) {
	t.Setenv("CRABEDENCE_ASSURANCE_PROFILE", "high-assurance")
	p, err := resolveAssuranceProfile(profileConfig(true, haWitness, validBinaryManifest(t)))
	if err != nil || p != AssuranceHighAssurance {
		t.Fatalf("high-assurance = %q/%v", p, err)
	}
}

// validBinaryManifest returns a manifest whose artifact digest matches
// a fixture binary the deployment check will hash.
func validBinaryManifest(t *testing.T) *ReleaseManifest {
	t.Helper()
	dir := t.TempDir()
	fixture := filepath.Join(dir, "bin")
	payload := []byte("rc8.2 release binary")
	if err := os.WriteFile(fixture, payload, 0o700); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(payload)
	m := manifestFixture()
	m.ArtifactSHA256 = hex.EncodeToString(h[:])
	orig := selfArtifactPath
	selfArtifactPath = func() (string, error) { return fixture, nil }
	t.Cleanup(func() { selfArtifactPath = orig })
	return m
}

// TestReleaseManifestEnvPairing: a manifest without its signer set —
// or signers without a manifest — fails closed at load; a policy
// digest contradicting the manifest is a startup error.
func TestReleaseManifestEnvPairing(t *testing.T) {
	t.Setenv("CRABBOX_MODE", "development")

	t.Setenv("CRABEDENCE_RELEASE_MANIFEST", "/tmp/m.json")
	t.Setenv("CRABEDENCE_RELEASE_SIGNERS", "")
	if _, err := LoadServiceConfig(ServeOptions{}); err == nil {
		t.Fatal("manifest without signers accepted")
	}

	t.Setenv("CRABEDENCE_RELEASE_MANIFEST", "")
	t.Setenv("CRABEDENCE_RELEASE_SIGNERS", "/tmp/s.json")
	if _, err := LoadServiceConfig(ServeOptions{}); err == nil {
		t.Fatal("signers without manifest accepted")
	}

	// A valid manifest pair whose policy contradicts the env digest.
	dir := t.TempDir()
	m := manifestFixture()
	raw, signers := signManifest(t, m)
	var pub string
	for _, p := range signers {
		pub = base64.StdEncoding.EncodeToString(p)
	}
	signersFile := filepath.Join(dir, "s.json")
	if err := os.WriteFile(signersFile, []byte(`{"version":1,"signers":[{"fingerprint":"`+m.SignerFingerprint+`","public_key":"`+pub+`"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	manifestFile := filepath.Join(dir, "m.json")
	if err := os.WriteFile(manifestFile, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CRABEDENCE_RELEASE_MANIFEST", manifestFile)
	t.Setenv("CRABEDENCE_RELEASE_SIGNERS", signersFile)
	t.Setenv("CRABEDENCE_POLICY_DIGEST", strings.Repeat("f", 64))
	if _, err := LoadServiceConfig(ServeOptions{}); err == nil {
		t.Fatal("policy digest contradicting the manifest accepted")
	}
	// Clean declaration resolves and binds the manifest's policy.
	t.Setenv("CRABEDENCE_POLICY_DIGEST", "")
	cfg, err := LoadServiceConfig(ServeOptions{})
	if err != nil {
		t.Fatalf("clean manifest pair rejected: %v", err)
	}
	if cfg.Release == nil || cfg.Witness.PolicyDigest != m.PolicyDigest {
		t.Fatalf("release identity not bound: %+v / %q", cfg.Release, cfg.Witness.PolicyDigest)
	}
}
