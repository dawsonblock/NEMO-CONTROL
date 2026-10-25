package sandboxexecutor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// RC8.3 PR-01 — fail-closed sandbox deletion: when pre-deletion
// inspection cannot classify the occupant, no destructive command is
// ever issued. The destructive-command counter is the proof — an
// outcome classification alone cannot show `rm` was never invoked.

// destructiveCount returns how many `rm` invocations the fake
// runtime has executed; absence of the counter file means zero.
func destructiveCount(t *testing.T, dir string) int {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "rm.count"))
	if err != nil {
		if os.IsNotExist(err) {
			return 0
		}
		t.Fatal(err)
	}
	return strings.Count(string(raw), "\n")
}

// TestCleanupUnverifiedInspectNeverRemoves: pre-inspection timeout,
// transport error and malformed responses must refuse with
// IDENTITY_UNVERIFIABLE — and the fake's rm counter stays at zero.
func TestCleanupUnverifiedInspectNeverRemoves(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
	}{
		{"transport_error", map[string]string{"MSB_FAKE_INSPECT_FAIL": "1"}},
		{"malformed_response", map[string]string{"MSB_FAKE_INSPECT_GARBAGE": "1"}},
		{"inspect_wedge", map[string]string{"MSB_FAKE_INSPECT_SLEEP": "10"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key, _ := testAuthority(t)
			bin, stateDir := fakeMSB(t, nil)
			backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
			backend.stepTimeoutOverride = 300 * time.Millisecond
			job := testContract(t, key, func(c *JobContractV2) { c.JobID = "failclosed-" + tc.name; c.Nonce = "n-fc-" + tc.name })

			disp, err := backend.Dispatch(testContext(t), job, nil)
			if err != nil {
				t.Fatalf("dispatch: %v", err)
			}
			// Arm the inspect fault only after dispatch — the knob is
			// inherited by the fake process, so an armed-at-start
			// fault would also break dispatch's own verification.
			for k, v := range tc.env {
				os.Setenv(k, v)
				defer os.Unsetenv(k)
			}
			res, err := backend.Cleanup(testContext(t), cleanupReqFor(job, disp))
			if err != nil {
				t.Fatalf("cleanup must classify, not error: %v", err)
			}
			if res.Outcome != CleanupIdentityUnverifiable {
				t.Fatalf("unverifiable inspect classified %s, want %s: %s", res.Outcome, CleanupIdentityUnverifiable, res.Detail)
			}
			if destructiveCount(t, stateDir) != 0 {
				t.Fatal("a destructive command was issued against an unverified occupant")
			}
			if res.Outcome.ProvesAbsent() || res.Outcome.ResolvesObligation() {
				t.Fatalf("an unverifiable outcome resolved the obligation: %s", res.Outcome)
			}
			survive(t, stateDir, disp.Handle)
		})
	}
}

// TestCleanupPostCheckDelayUncertain: the pre-check verified the
// authorized identity and the removal issued — but post-removal
// verification wedges. Removal happened; proof did not. The outcome
// is REMOVAL_UNCERTAIN and the obligation stays pending.
func TestCleanupPostCheckDelayUncertain(t *testing.T) {
	key, _ := testAuthority(t)
	bin, stateDir := fakeMSB(t, map[string]string{"MSB_FAKE_INSPECT_SLOW_ON": "2"})
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	backend.postVerifyOverride = 300 * time.Millisecond
	job := testContract(t, key, func(c *JobContractV2) { c.JobID = "delay-1"; c.Nonce = "n-delay" })

	disp, err := backend.Dispatch(testContext(t), job, nil)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	// Dispatch's own lifecycle inspects consumed counter slots —
	// reset so the cleanup's pre-check is inspect #1 and the
	// post-removal verification deterministically wedges on #2.
	_ = os.WriteFile(filepath.Join(stateDir, disp.Handle+".inspect-count"), []byte("0"), 0o600)
	res, err := backend.Cleanup(testContext(t), cleanupReqFor(job, disp))
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if res.Outcome != CleanupRemovalUncertain {
		t.Fatalf("wedged post-check classified %s, want %s: %s", res.Outcome, CleanupRemovalUncertain, res.Detail)
	}
	if res.Outcome.ProvesAbsent() || res.Outcome.ResolvesObligation() {
		t.Fatalf("an unproven removal resolved the obligation: %s", res.Outcome)
	}
	if destructiveCount(t, stateDir) != 1 {
		t.Fatalf("expected exactly one removal after a verified inspect, got %d", destructiveCount(t, stateDir))
	}
}

// TestCleanupInvalidNamespaceRefused: a backend carrying a malformed
// namespace cannot authorize creation or destruction — the boundary
// itself is unverifiable, so both admissions fail closed.
func TestCleanupInvalidNamespaceRefused(t *testing.T) {
	key, _ := testAuthority(t)
	bin, stateDir := fakeMSB(t, nil)
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	backend.Namespace = "BAD NAMESPACE!"
	job := testContract(t, key, func(c *JobContractV2) { c.JobID = "badns-1"; c.Nonce = "n-badns" })

	if _, err := backend.Dispatch(testContext(t), job, nil); err == nil {
		t.Fatal("a malformed namespace admitted a dispatch")
	}
	res, err := backend.Cleanup(testContext(t), CleanupRequest{
		JobID: job.JobID, BackendID: "microsandbox",
		Handle: "sx-badns-1-n-badns", DispatchNonce: "n-badns",
	})
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if res.Outcome != CleanupIdentityUnverifiable {
		t.Fatalf("invalid-namespace backend classified %s, want %s", res.Outcome, CleanupIdentityUnverifiable)
	}
	if destructiveCount(t, stateDir) != 0 {
		t.Fatal("destruction issued under a malformed namespace")
	}
}

// TestHighAssuranceSharedNamespaceDenied: a high-assurance backend
// with no exclusive namespace and no dedicated catalog refuses every
// admission — no dispatch, no destruction, never a silent fallback to
// shared posture.
func TestHighAssuranceSharedNamespaceDenied(t *testing.T) {
	key, _ := testAuthority(t)
	bin, stateDir := fakeMSB(t, nil)
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	backend.HighAssurance = true
	job := testContract(t, key, func(c *JobContractV2) { c.JobID = "ha-1"; c.Nonce = "n-ha" })

	if _, err := backend.DeploymentPosture(); err == nil {
		t.Fatal("shared/empty posture proved exclusive")
	}
	if _, err := backend.Dispatch(testContext(t), job, nil); err == nil {
		t.Fatal("high-assurance dispatch admitted under a shared namespace")
	}
	res, err := backend.Cleanup(testContext(t), CleanupRequest{
		JobID: job.JobID, BackendID: "microsandbox",
		Handle: "sx-ha-1-n-ha", DispatchNonce: "n-ha",
	})
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if res.Outcome != CleanupIdentityUnverifiable {
		t.Fatalf("high-assurance shared cleanup classified %s, want %s", res.Outcome, CleanupIdentityUnverifiable)
	}
	if destructiveCount(t, stateDir) != 0 {
		t.Fatal("destruction issued under an unproven shared posture")
	}
}

// TestHighAssuranceSharedCatalogDenied: namespace alone is not
// exclusivity — a namespaced backend sharing the default catalog has
// no runtime-ownership boundary and refuses high-assurance admission.
func TestHighAssuranceSharedCatalogDenied(t *testing.T) {
	key, _ := testAuthority(t)
	bin, _ := fakeMSB(t, nil)
	backend := testBackend(t, bin, t.TempDir())
	backend.HighAssurance = true
	backend.Namespace = "prod-a"
	if _, err := backend.DeploymentPosture(); err == nil {
		t.Fatal("a namespaced backend on the shared catalog proved exclusive")
	}
	if _, err := backend.Dispatch(testContext(t), testContract(t, key, func(c *JobContractV2) {
		c.JobID = "ha-cat"
		c.Nonce = "n-hacat"
	}), nil); err == nil {
		t.Fatal("dispatch admitted against the shared catalog under high assurance")
	}
}

// TestHighAssuranceExclusivePostureAdmits: a dedicated, owner-only
// MSB_HOME catalog plus a validated namespace is the exclusive
// runtime-ownership posture — admission proceeds and the posture
// proof is auditable.
func TestHighAssuranceExclusivePostureAdmits(t *testing.T) {
	key, _ := testAuthority(t)
	bin, stateDir := fakeMSB(t, nil)
	catalog := filepath.Join(t.TempDir(), "msb-home")
	if err := os.MkdirAll(catalog, 0o700); err != nil {
		t.Fatal(err)
	}
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	backend.HighAssurance = true
	backend.Namespace = "prod-a"
	backend.MSBHome = catalog

	proof, err := backend.DeploymentPosture()
	if err != nil {
		t.Fatalf("exclusive posture refused: %v", err)
	}
	if !strings.Contains(proof, "prod-a") || !strings.Contains(proof, catalog) {
		t.Fatalf("posture proof does not bind the scope: %q", proof)
	}
	job := testContract(t, key, func(c *JobContractV2) { c.JobID = "ha-ok"; c.Nonce = "n-haok" })
	disp, err := backend.Dispatch(testContext(t), job, nil)
	if err != nil {
		t.Fatalf("high-assurance dispatch refused under a proven posture: %v", err)
	}
	res, err := backend.Cleanup(testContext(t), cleanupReqFor(job, disp))
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if !res.Outcome.ProvesAbsent() {
		t.Fatalf("exclusive-posture cleanup could not prove absence: %s — %s", res.Outcome, res.Detail)
	}
	if destructiveCount(t, stateDir) != 1 {
		t.Fatalf("expected exactly one verified removal, got %d", destructiveCount(t, stateDir))
	}
}

// TestHighAssuranceLooseCatalogDenied: a dedicated catalog directory
// that grants group/other access admits co-tenants — the posture is
// not exclusive and every admission fails closed.
func TestHighAssuranceLooseCatalogDenied(t *testing.T) {
	key, _ := testAuthority(t)
	bin, _ := fakeMSB(t, nil)
	catalog := filepath.Join(t.TempDir(), "loose")
	if err := os.MkdirAll(catalog, 0o755); err != nil {
		t.Fatal(err)
	}
	backend := testBackend(t, bin, t.TempDir())
	backend.HighAssurance = true
	backend.Namespace = "prod-a"
	backend.MSBHome = catalog
	if _, err := backend.DeploymentPosture(); err == nil {
		t.Fatal("a world-readable catalog proved exclusive")
	}
	if _, err := backend.Dispatch(testContext(t), testContract(t, key, func(c *JobContractV2) {
		c.JobID = "ha-loose"
		c.Nonce = "n-haloose"
	}), nil); err == nil {
		t.Fatal("dispatch admitted against a co-tenant-accessible catalog")
	}
}
