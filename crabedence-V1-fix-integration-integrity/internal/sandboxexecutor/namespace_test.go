package sandboxexecutor

import (
	"path/filepath"
	"strings"
	"testing"
)

// Exclusive-namespace isolation (RC8.2 F-06 / INV-01): msb v0.7.8
// exposes no atomic identity-conditional delete — `rm` resolves a
// name or label, then deletes. The deployment supplies the isolation
// boundary instead: a per-deployment namespace every handle, label,
// and cleanup identity check resolves against. These cases prove the
// boundary holds on creation, on pre-removal verification, and on
// handle admission — and that nothing about it pretends to be
// atomicity.

func TestValidateNamespace(t *testing.T) {
	for _, ns := range []string{"prod", "a", "team-1", "a-b-c-9", strings.Repeat("a", 32)} {
		if err := ValidateNamespace(ns); err != nil {
			t.Fatalf("valid namespace %q rejected: %v", ns, err)
		}
	}
	for _, ns := range []string{
		"", strings.Repeat("a", 33), "Upper", "-lead", "trail_",
		"with.dot", "with/slash", "with space", "WITH", "ns:0",
	} {
		if err := ValidateNamespace(ns); err == nil {
			t.Fatalf("invalid namespace %q accepted", ns)
		}
	}
}

// TestNamespaceMintsPrefixedLabeledSandbox: a namespaced backend puts
// every sandbox under sx-<ns>- and stamps the namespace onto the
// runtime catalog identity — the two facts cleanup later verifies.
func TestNamespaceMintsPrefixedLabeledSandbox(t *testing.T) {
	key, _ := testAuthority(t)
	bin, stateDir := fakeMSB(t, nil)
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	backend.Namespace = "prod-a"
	job := testContract(t, key, func(c *JobContractV2) { c.JobID = "ns-1"; c.Nonce = "n-ns" })

	disp, err := backend.Dispatch(testContext(t), job, nil)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if !strings.HasPrefix(disp.Handle, "sx-prod-a-") {
		t.Fatalf("namespaced handle %q lacks the sx-prod-a- prefix", disp.Handle)
	}
	sb := readFakeSandbox(t, stateDir, disp.Handle)
	if got := sb.Config.Labels["crabedence.namespace"]; got != "prod-a" {
		t.Fatalf("sandbox labels %+v lack crabedence.namespace=prod-a", sb.Config.Labels)
	}
}

// TestNamespaceCleanupHappyPath: the namespaced boundary does not
// obstruct its own sandboxes — dispatch plus cleanup resolves the
// obligation exactly as the shared namespace does.
func TestNamespaceCleanupHappyPath(t *testing.T) {
	key, _ := testAuthority(t)
	bin, _ := fakeMSB(t, nil)
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	backend.Namespace = "prod-b"
	job := testContract(t, key, func(c *JobContractV2) { c.JobID = "ns-ok"; c.Nonce = "n-ok" })

	disp, err := backend.Dispatch(testContext(t), job, nil)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	res, err := backend.Cleanup(testContext(t), cleanupReqFor(job, disp))
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if !res.Outcome.ProvesAbsent() {
		t.Fatalf("cleanup classified %s, want absent-verified: %s", res.Outcome, res.Detail)
	}
	if _, err := backend.Inspect(testContext(t), disp.Handle); err == nil {
		t.Fatalf("sandbox %s still inspectable after verified removal", disp.Handle)
	}
}

// TestNamespaceForeignOccupantRefused: an occupant presenting the
// authorized dispatch/job labels but a foreign namespace — the
// cross-deployment collision the exclusive namespace exists to stop —
// is classified and survives.
func TestNamespaceForeignOccupantRefused(t *testing.T) {
	key, _ := testAuthority(t)
	bin, stateDir := fakeMSB(t, nil)
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	backend.Namespace = "prod-c"
	job := testContract(t, key, func(c *JobContractV2) { c.JobID = "ns-foreign"; c.Nonce = "n-foreign" })

	disp, err := backend.Dispatch(testContext(t), job, nil)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	substitute(t, stateDir, disp.Handle, map[string]string{
		"crabedence.job":       job.JobID,
		"crabedence.dispatch":  disp.Nonce,
		"crabedence.namespace": "other-deploy",
	})

	res, err := backend.Cleanup(testContext(t), cleanupReqFor(job, disp))
	if err != nil {
		t.Fatalf("cleanup must classify, not error: %v", err)
	}
	if res.Outcome != CleanupIdentityMismatch {
		t.Fatalf("foreign-namespace occupant classified %s, want %s: %s", res.Outcome, CleanupIdentityMismatch, res.Detail)
	}
	survive(t, stateDir, disp.Handle)
}

// TestNamespaceLabelAbsentRefused: an occupant under our prefix with
// our dispatch labels but no namespace declaration at all — the
// shared-namespace shape inside an exclusive deployment — is never
// destroyed.
func TestNamespaceLabelAbsentRefused(t *testing.T) {
	key, _ := testAuthority(t)
	bin, stateDir := fakeMSB(t, nil)
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	backend.Namespace = "prod-d"
	job := testContract(t, key, func(c *JobContractV2) { c.JobID = "ns-missing"; c.Nonce = "n-missing" })

	disp, err := backend.Dispatch(testContext(t), job, nil)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	substitute(t, stateDir, disp.Handle, map[string]string{
		"crabedence.job":      job.JobID,
		"crabedence.dispatch": disp.Nonce,
	})

	res, err := backend.Cleanup(testContext(t), cleanupReqFor(job, disp))
	if err != nil {
		t.Fatalf("cleanup must classify, not error: %v", err)
	}
	if res.Outcome != CleanupIdentityMismatch {
		t.Fatalf("unlabeled-namespace occupant classified %s, want %s: %s", res.Outcome, CleanupIdentityMismatch, res.Detail)
	}
	survive(t, stateDir, disp.Handle)
}

// TestNamespaceRejectsHandlesOutsidePrefix: a namespaced backend
// refuses a handle from the shared sx- space or another deployment's
// space before identity verification even begins — the prefix is the
// admission fence.
func TestNamespaceRejectsHandlesOutsidePrefix(t *testing.T) {
	key, _ := testAuthority(t)
	bin, stateDir := fakeMSB(t, nil)
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	backend.Namespace = "prod-e"

	// A real shared-namespace sandbox dispatched by an unnamespaced
	// backend against the same runtime: a foreign tenant's resource.
	shared := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts-shared"))
	job := testContract(t, key, func(c *JobContractV2) { c.JobID = "ns-shared"; c.Nonce = "n-shared" })
	disp, err := shared.Dispatch(testContext(t), job, nil)
	if err != nil {
		t.Fatalf("shared dispatch: %v", err)
	}
	if !strings.HasPrefix(disp.Handle, "sx-") || strings.HasPrefix(disp.Handle, "sx-prod-e-") {
		t.Fatalf("shared handle %q unexpectedly inside prod-e", disp.Handle)
	}

	res, err := backend.Cleanup(testContext(t), cleanupReqFor(job, disp))
	if err != nil {
		t.Fatalf("cleanup must classify, not error: %v", err)
	}
	if res.Outcome != CleanupIdentityUnverifiable {
		t.Fatalf("out-of-namespace handle classified %s, want %s: %s", res.Outcome, CleanupIdentityUnverifiable, res.Detail)
	}
	survive(t, stateDir, disp.Handle)
}

// TestNamespaceCrossDeploymentSymmetric: two namespaced deployments on
// one runtime cannot reach each other's sandboxes in either direction.
func TestNamespaceCrossDeploymentSymmetric(t *testing.T) {
	key, _ := testAuthority(t)
	bin, stateDir := fakeMSB(t, nil)
	mine := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts-mine"))
	mine.Namespace = "deploy-x"
	theirs := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts-theirs"))
	theirs.Namespace = "deploy-y"

	job := testContract(t, key, func(c *JobContractV2) { c.JobID = "ns-cross"; c.Nonce = "n-cross" })
	disp, err := mine.Dispatch(testContext(t), job, nil)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}

	// The foreign deployment's backend cannot even admit my handle —
	// it sits outside their prefix.
	res, err := theirs.Cleanup(testContext(t), cleanupReqFor(job, disp))
	if err != nil {
		t.Fatalf("foreign cleanup must classify, not error: %v", err)
	}
	if res.Outcome != CleanupIdentityUnverifiable {
		t.Fatalf("cross-deployment cleanup classified %s, want %s: %s", res.Outcome, CleanupIdentityUnverifiable, res.Detail)
	}
	survive(t, stateDir, disp.Handle)

	// And my cleanup of my own sandbox still resolves.
	res, err = mine.Cleanup(testContext(t), cleanupReqFor(job, disp))
	if err != nil {
		t.Fatalf("own cleanup: %v", err)
	}
	if !res.Outcome.ProvesAbsent() {
		t.Fatalf("own cleanup classified %s, want absent-verified: %s", res.Outcome, res.Detail)
	}
}
