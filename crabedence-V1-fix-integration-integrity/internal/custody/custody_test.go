package custody

// G4 — custody-envelope-v1 contract: canonical signing, the §8
// verification pipeline, and trust-set rotation. Tests sign real
// envelopes with real keys — no verification stubbing.

import (
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/openclaw/crabbox/internal/evidence"
)

const testDep = "dep-alpha"

func testSigners(t *testing.T) (kernel, custodian *evidence.Signer) {
	t.Helper()
	var err error
	if kernel, err = evidence.GenerateSigner(); err != nil {
		t.Fatalf("kernel signer: %v", err)
	}
	if custodian, err = evidence.GenerateSigner(); err != nil {
		t.Fatalf("custodian signer: %v", err)
	}
	return
}

func testTrust(t *testing.T, key *evidence.Signer, role string) *TrustSet {
	t.Helper()
	return NewTrustSet(TrustedKey{
		Role: role, KeyID: key.Fingerprint(), PublicKey: key.PublicKey(), DeploymentID: testDep,
	})
}

func testEnvelope(t *testing.T, family string, signer *evidence.Signer, payload []byte) *Envelope {
	t.Helper()
	env := New(family, testDep,
		ReleaseIdentity{Version: "0.55.0-rc8.1-dev", SourceCommit: strings.Repeat("a", 40)},
		"",
		Subject{EffectID: "exec-1", ExecutionID: "exec-1"},
		Sequence{Domain: family, Epoch: 0, Index: 1},
		EncodingWitnessFrame, payload)
	if err := Sign(env, RoleKernelRelay, signer); err != nil {
		t.Fatalf("sign: %v", err)
	}
	return env
}

// TestSameHashDifferentPayloadRejected: the verifier re-derives the
// content hash from the bytes — a record whose bytes do not produce
// its declared hash is refused before the signature is even checked.
func TestSameHashDifferentPayloadRejected(t *testing.T) {
	kernel, _ := testSigners(t)
	trust := testTrust(t, kernel, RoleKernelRelay)
	env := testEnvelope(t, FamilyReceipt, kernel, []byte(`{"payload":"A"}`))

	// Swap the carried bytes while keeping the declared hash — the
	// "same hash, different payload" attack shape.
	env.Content.BytesB64 = base64.StdEncoding.EncodeToString([]byte(`{"payload":"B"}`))
	err := Verify(env, VerifyOptions{DeploymentID: testDep, Trust: trust})
	if err == nil || !errors.Is(err, ErrContentHash) {
		t.Fatalf("mismatched payload/hash verified: %v", err)
	}
}

// TestEnvelopeVerifyPipeline exercises the §8 obligation order — each
// layer independently rejects.
func TestEnvelopeVerifyPipeline(t *testing.T) {
	kernel, _ := testSigners(t)
	trust := testTrust(t, kernel, RoleKernelRelay)
	good := func() *Envelope {
		return testEnvelope(t, FamilyReceipt, kernel, []byte(`{"r":1}`))
	}
	opts := VerifyOptions{DeploymentID: testDep, Trust: trust}

	if err := Verify(good(), opts); err != nil {
		t.Fatalf("well-formed envelope refused: %v", err)
	}

	bad := good()
	bad.Envelope = "custody-envelope-v0"
	if err := Verify(bad, opts); !errors.Is(err, ErrVersion) {
		t.Fatalf("version check: %v", err)
	}

	bad = good()
	bad.Family = "operator-control"
	if err := Verify(bad, opts); !errors.Is(err, ErrFamily) {
		t.Fatalf("family allowlist: %v", err)
	}

	bad = good()
	bad.DeploymentID = "dep-beta"
	if err := Verify(bad, opts); !errors.Is(err, ErrDeployment) {
		t.Fatalf("deployment check: %v", err)
	}

	bad = good()
	bad.ReleaseIdentity.Version = "0.55.0-other"
	if err := Verify(bad, VerifyOptions{
		DeploymentID: testDep, Trust: trust,
		ReleaseIdentity: &ReleaseIdentity{Version: "0.55.0-rc8.1-dev"},
	}); !errors.Is(err, ErrRelease) {
		t.Fatalf("release binding: %v", err)
	}

	bad = good()
	bad.PolicyDigest = strings.Repeat("f", 64)
	if err := Verify(bad, VerifyOptions{
		DeploymentID: testDep, Trust: trust,
		PolicyDigest: strings.Repeat("0", 64),
	}); !errors.Is(err, ErrPolicyDigest) {
		t.Fatalf("policy digest: %v", err)
	}

	bad = good()
	bad.Sequence.Index = 4
	if err := Verify(bad, VerifyOptions{
		DeploymentID: testDep, Trust: trust,
		Seq: &SeqExpect{Index: 2},
	}); !errors.Is(err, ErrSequence) {
		t.Fatalf("sequence check: %v", err)
	}

	// Prior-epoch replay.
	bad = good()
	bad.Sequence.Epoch = -1
	if err := Verify(bad, VerifyOptions{
		DeploymentID: testDep, Trust: trust,
		Seq: &SeqExpect{Index: 1, MinEpoch: 0},
	}); !errors.Is(err, ErrSequence) {
		t.Fatalf("epoch check: %v", err)
	}

	bad = good()
	bad.Signature = base64.StdEncoding.EncodeToString(make([]byte, 64))
	if err := Verify(bad, opts); !errors.Is(err, ErrSignature) {
		t.Fatalf("signature check: %v", err)
	}

	// Empty trust fails closed even with a perfectly signed record.
	if err := Verify(good(), VerifyOptions{DeploymentID: testDep, Trust: &TrustSet{}}); !errors.Is(err, ErrUntrustedKey) {
		t.Fatalf("empty trust did not fail closed: %v", err)
	}
}

// TestTrustSetRotationWindow: a successor resolves only inside its
// authorized window, the incumbent only inside its own, and a
// successor without incumbent authorization never enters the set.
func TestTrustSetRotationWindow(t *testing.T) {
	k1, _ := testSigners(t)
	k2, _ := testSigners(t)

	set := NewTrustSet(TrustedKey{
		Role: RoleCustodian, KeyID: k1.Fingerprint(), PublicKey: k1.PublicKey(),
		DeploymentID: testDep, ValidFromIndex: 0, ValidUntilIndex: 7,
	})
	next := TrustedKey{
		Role: RoleCustodian, KeyID: k2.Fingerprint(), PublicKey: k2.PublicKey(),
		DeploymentID: testDep, ValidFromIndex: 8,
	}
	// Without authorization: refused.
	if _, err := set.Resolve(RoleCustodian, testDep, k2.Fingerprint(), 9); err == nil {
		t.Fatalf("unauthorized successor resolved")
	}
	auth, err := SignKeyRotation(k1, next)
	if err != nil {
		t.Fatalf("sign rotation: %v", err)
	}
	if err := set.AddAuthorized(k1.Fingerprint(), next, auth); err != nil {
		t.Fatalf("authorized successor refused: %v", err)
	}
	if _, err := set.Resolve(RoleCustodian, testDep, k2.Fingerprint(), 9); err != nil {
		t.Fatalf("successor unresolved inside its window: %v", err)
	}
	// Successor cannot vouch below its window; incumbent cannot vouch
	// past it.
	if _, err := set.Resolve(RoleCustodian, testDep, k2.Fingerprint(), 5); err == nil {
		t.Fatalf("successor resolved before its window opened")
	}
	if _, err := set.Resolve(RoleCustodian, testDep, k1.Fingerprint(), 9); err == nil {
		t.Fatalf("incumbent resolved past its rotation point")
	}
	// Wrong-role and foreign-deployment resolution refuse.
	if _, err := set.Resolve(RoleKernelRelay, testDep, k2.Fingerprint(), 9); err == nil {
		t.Fatalf("custodian key resolved for the kernel-relay role")
	}
	if _, err := set.Resolve(RoleCustodian, "dep-beta", k2.Fingerprint(), 9); err == nil {
		t.Fatalf("deployment-scoped key resolved for a foreign deployment")
	}
}

// TestTrustSetLoadFile exercises the controlled-configuration loader:
// anchors, authorized successors, and refusal shapes.
func TestTrustSetLoadFile(t *testing.T) {
	k1, _ := testSigners(t)
	k2, _ := testSigners(t)
	dir := t.TempDir()
	write := func(name, body string, mode uint32) string {
		p := dir + "/" + name
		if err := writeFile(p, body, mode); err != nil {
			t.Fatalf("write trust file: %v", err)
		}
		return p
	}

	next := TrustedKey{
		Role: RoleCustodian, KeyID: k2.Fingerprint(), PublicKey: k2.PublicKey(),
		DeploymentID: testDep, ValidFromIndex: 3,
	}
	auth, _ := SignKeyRotation(k1, next)
	good := `{"version":1,"keys":[
		{"role":"custodian","key_id":"` + k1.Fingerprint() + `","public_key":"` +
		base64.StdEncoding.EncodeToString(k1.PublicKey()) + `","deployment_id":"` + testDep +
		`","valid_from_index":0,"valid_until_index":2},
		{"role":"custodian","key_id":"` + k2.Fingerprint() + `","public_key":"` +
		base64.StdEncoding.EncodeToString(k2.PublicKey()) + `","deployment_id":"` + testDep +
		`","valid_from_index":3,"valid_until_index":0,"authorized_by":"` + k1.Fingerprint() +
		`","authorization":"` + auth + `"}]}`

	set, err := LoadTrustSet(write("trust.json", good, 0o600))
	if err != nil {
		t.Fatalf("good trust file refused: %v", err)
	}
	if _, err := set.Resolve(RoleCustodian, testDep, k2.Fingerprint(), 5); err != nil {
		t.Fatalf("loaded successor unresolved: %v", err)
	}

	// Successor without authorization refuses the whole file.
	noauth := strings.Replace(good, `,"authorized_by":"`+k1.Fingerprint()+`","authorization":"`+auth+`"`, "", 1)
	if _, err := LoadTrustSet(write("noauth.json", noauth, 0o600)); err == nil {
		t.Fatalf("unauthorized successor file loaded")
	}

	// Group/world-readable trust files refuse — controlled
	// configuration is owner-only.
	if _, err := LoadTrustSet(write("world.json", good, 0o644)); err == nil {
		t.Fatalf("group/world-accessible trust file loaded")
	}
}

func writeFile(path, body string, mode uint32) error {
	return os.WriteFile(path, []byte(body), os.FileMode(mode))
}
