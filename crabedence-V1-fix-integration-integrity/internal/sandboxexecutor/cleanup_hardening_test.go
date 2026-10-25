package sandboxexecutor

// RC8.3 PR-05 — adversarial cleanup hardening: symlink/ancestor-path
// substitution, same-UID catalog replacement, inspect-then-delete
// races, and crash-recovery intents. These tests assert refusals, not
// best-effort behavior.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func highAssuranceBackend(t *testing.T, catalog string) (*MSBBackend, string) {
	t.Helper()
	key, _ := testAuthority(t)
	bin, stateDir := fakeMSB(t, nil)
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	backend.HighAssurance = true
	backend.Namespace = "prod-a"
	backend.MSBHome = catalog
	_ = key
	return backend, stateDir
}

func TestHighAssuranceRejectsSymlinkCatalog(t *testing.T) {
	realDir := filepath.Join(t.TempDir(), "real")
	if err := os.MkdirAll(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(realDir, link); err != nil {
		t.Fatal(err)
	}
	backend, _ := highAssuranceBackend(t, link)
	_, err := backend.DeploymentPosture()
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink catalog posture = %v, want a symlink refusal", err)
	}
}

func TestHighAssuranceRejectsNonRootAncestorSymlink(t *testing.T) {
	base := t.TempDir()
	realParent := filepath.Join(base, "real-parent")
	if err := os.MkdirAll(realParent, 0o700); err != nil {
		t.Fatal(err)
	}
	catalog := filepath.Join(realParent, "catalog")
	if err := os.MkdirAll(catalog, 0o700); err != nil {
		t.Fatal(err)
	}
	linkParent := filepath.Join(base, "link-parent")
	if err := os.Symlink(realParent, linkParent); err != nil {
		t.Fatal(err)
	}
	backend, _ := highAssuranceBackend(t, filepath.Join(linkParent, "catalog"))
	_, err := backend.DeploymentPosture()
	if err == nil || !strings.Contains(err.Error(), "non-root symlink") {
		t.Fatalf("ancestor symlink posture = %v, want a non-root symlink refusal", err)
	}
}

func TestHighAssuranceRejectsGroupWritableAncestor(t *testing.T) {
	base := t.TempDir()
	loose := filepath.Join(base, "loose")
	if err := os.MkdirAll(loose, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loose, 0o777); err != nil {
		t.Fatal(err)
	}
	catalog := filepath.Join(loose, "catalog")
	if err := os.MkdirAll(catalog, 0o700); err != nil {
		t.Fatal(err)
	}
	backend, _ := highAssuranceBackend(t, catalog)
	_, err := backend.DeploymentPosture()
	if err == nil || !strings.Contains(err.Error(), "group/other writable") {
		t.Fatalf("group-writable ancestor posture = %v, want a refusal", err)
	}
}

func TestCleanupRejectsCatalogReplacementBeforePosture(t *testing.T) {
	catalog := filepath.Join(t.TempDir(), "msb-home")
	if err := os.MkdirAll(catalog, 0o700); err != nil {
		t.Fatal(err)
	}
	backend, stateDir := highAssuranceBackend(t, catalog)
	key, _ := testAuthority(t)
	job := testContract(t, key, func(c *JobContractV2) { c.JobID = "catalog-replace"; c.Nonce = "n-cat-rep" })
	disp, err := backend.Dispatch(testContext(t), job, nil)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if err := os.Rename(catalog, catalog+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(catalog, 0o700); err != nil {
		t.Fatal(err)
	}
	res, err := backend.Cleanup(testContext(t), cleanupReqFor(job, disp))
	if err != nil {
		t.Fatalf("cleanup must classify, not error: %v", err)
	}
	if res.Outcome != CleanupIdentityUnverifiable {
		t.Fatalf("replaced catalog classified %s, want %s: %s", res.Outcome, CleanupIdentityUnverifiable, res.Detail)
	}
	if destructiveCount(t, stateDir) != 0 {
		t.Fatal("destruction issued against a replaced runtime catalog")
	}
	survive(t, stateDir, disp.Handle)
}

func TestCleanupRejectsCatalogReplacementInsideWindow(t *testing.T) {
	catalog := filepath.Join(t.TempDir(), "msb-home")
	if err := os.MkdirAll(catalog, 0o700); err != nil {
		t.Fatal(err)
	}
	backend, stateDir := highAssuranceBackend(t, catalog)
	key, _ := testAuthority(t)
	job := testContract(t, key, func(c *JobContractV2) { c.JobID = "catalog-window"; c.Nonce = "n-cat-win" })
	disp, err := backend.Dispatch(testContext(t), job, nil)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	backend.cleanupHook = func(stage string) error {
		if stage == "after_preinspect" {
			if err := os.Rename(catalog, catalog+".swapped"); err != nil {
				return err
			}
			return os.MkdirAll(catalog, 0o700)
		}
		return nil
	}
	res, err := backend.Cleanup(testContext(t), cleanupReqFor(job, disp))
	if err != nil {
		t.Fatalf("cleanup must classify, not error: %v", err)
	}
	if res.Outcome != CleanupIdentityUnverifiable {
		t.Fatalf("mid-window catalog replacement classified %s, want %s: %s", res.Outcome, CleanupIdentityUnverifiable, res.Detail)
	}
	if destructiveCount(t, stateDir) != 0 {
		t.Fatal("destruction issued after a mid-window catalog replacement")
	}
	survive(t, stateDir, disp.Handle)
}

func TestCleanupReinspectCatchesSubstitution(t *testing.T) {
	key, _ := testAuthority(t)
	bin, stateDir := fakeMSB(t, nil)
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	job := testContract(t, key, func(c *JobContractV2) { c.JobID = "reinspect"; c.Nonce = "n-reinspect" })
	disp, err := backend.Dispatch(testContext(t), job, nil)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	backend.cleanupHook = func(stage string) error {
		if stage == "after_preinspect" {
			substitute(t, stateDir, disp.Handle, map[string]string{"foreign": "yes"})
		}
		return nil
	}
	res, err := backend.Cleanup(testContext(t), cleanupReqFor(job, disp))
	if err != nil {
		t.Fatalf("cleanup must classify, not error: %v", err)
	}
	if res.Outcome != CleanupIdentityMismatch {
		t.Fatalf("mid-window substitution classified %s, want %s: %s", res.Outcome, CleanupIdentityMismatch, res.Detail)
	}
	if destructiveCount(t, stateDir) != 0 {
		t.Fatal("destruction issued against a substituted occupant")
	}
}

func TestCleanupIntentSurvivesUncertainOutcome(t *testing.T) {
	key, _ := testAuthority(t)
	bin, _ := fakeMSB(t, nil)
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	job := testContract(t, key, func(c *JobContractV2) { c.JobID = "intent"; c.Nonce = "n-intent" })
	disp, err := backend.Dispatch(testContext(t), job, nil)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	t.Setenv("MSB_FAKE_RM_FAIL", "1")
	res, err := backend.Cleanup(testContext(t), cleanupReqFor(job, disp))
	if err != nil {
		t.Fatalf("cleanup must classify, not error: %v", err)
	}
	if res.Outcome != CleanupRemovalUncertain {
		t.Fatalf("failed removal classified %s, want %s: %s", res.Outcome, CleanupRemovalUncertain, res.Detail)
	}
	pending, err := backend.PendingCleanupObligations(testContext(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].Handle != disp.Handle {
		t.Fatalf("unresolved cleanup intent = %+v, want one for %s", pending, disp.Handle)
	}
	os.Unsetenv("MSB_FAKE_RM_FAIL")
	res, err = backend.Cleanup(testContext(t), cleanupReqFor(job, disp))
	if err != nil || !res.Outcome.ProvesAbsent() {
		t.Fatalf("recovery cleanup = %s, %v", res.Outcome, err)
	}
	pending, err = backend.PendingCleanupObligations(testContext(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("resolved cleanup left intents: %+v", pending)
	}
}

func TestCleanupVerifiedRemovalLeavesNoIntent(t *testing.T) {
	key, _ := testAuthority(t)
	bin, _ := fakeMSB(t, nil)
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	job := testContract(t, key, func(c *JobContractV2) { c.JobID = "intent-clean"; c.Nonce = "n-intent-clean" })
	disp, err := backend.Dispatch(testContext(t), job, nil)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	res, err := backend.Cleanup(testContext(t), cleanupReqFor(job, disp))
	if err != nil || !res.Outcome.ProvesAbsent() {
		t.Fatalf("cleanup = %s, %v", res.Outcome, err)
	}
	pending, err := backend.PendingCleanupObligations(testContext(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("verified removal left an intent: %+v", pending)
	}
}

func TestCleanupIntentRequiresDurableStateDirectory(t *testing.T) {
	key, _ := testAuthority(t)
	bin, stateDir := fakeMSB(t, nil)
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	job := testContract(t, key, func(c *JobContractV2) { c.JobID = "intent-nodir"; c.Nonce = "n-intent-nodir" })
	disp, err := backend.Dispatch(testContext(t), job, nil)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	backend.StateDir = ""
	res, err := backend.Cleanup(testContext(t), cleanupReqFor(job, disp))
	if err != nil {
		t.Fatalf("cleanup must classify, not error: %v", err)
	}
	if res.Outcome != CleanupIdentityUnverifiable {
		t.Fatalf("missing state directory classified %s, want %s: %s", res.Outcome, CleanupIdentityUnverifiable, res.Detail)
	}
	if destructiveCount(t, stateDir) != 0 {
		t.Fatal("destruction issued without a durable cleanup intent")
	}
	survive(t, stateDir, disp.Handle)
}

func TestCleanupIntentSyncFailureFailsClosed(t *testing.T) {
	for _, stage := range []string{"after_file_sync", "after_dir_sync"} {
		t.Run(stage, func(t *testing.T) {
			key, _ := testAuthority(t)
			bin, stateDir := fakeMSB(t, nil)
			backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
			job := testContract(t, key, func(c *JobContractV2) { c.JobID = "intent-sync-" + stage; c.Nonce = "n-intent-sync-" + stage })
			disp, err := backend.Dispatch(testContext(t), job, nil)
			if err != nil {
				t.Fatalf("dispatch: %v", err)
			}
			backend.cleanupIntentSyncHook = func(got string) error {
				if got == stage {
					return errors.New("injected intent sync failure")
				}
				return nil
			}
			res, err := backend.Cleanup(testContext(t), cleanupReqFor(job, disp))
			if err != nil {
				t.Fatalf("cleanup must classify, not error: %v", err)
			}
			if res.Outcome != CleanupIdentityUnverifiable {
				t.Fatalf("sync failure classified %s, want %s: %s", res.Outcome, CleanupIdentityUnverifiable, res.Detail)
			}
			if destructiveCount(t, stateDir) != 0 {
				t.Fatal("destruction issued without a durable cleanup intent")
			}
			survive(t, stateDir, disp.Handle)
		})
	}
}

func TestCleanupIntentClearFailureSurfaced(t *testing.T) {
	key, _ := testAuthority(t)
	bin, _ := fakeMSB(t, nil)
	backend := testBackend(t, bin, filepath.Join(t.TempDir(), "artifacts"))
	job := testContract(t, key, func(c *JobContractV2) { c.JobID = "intent-clear"; c.Nonce = "n-intent-clear" })
	disp, err := backend.Dispatch(testContext(t), job, nil)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	intentDir := filepath.Join(backend.StateDir, "cleanup-intents")
	t.Cleanup(func() { _ = os.Chmod(intentDir, 0o700) })
	backend.cleanupIntentSyncHook = func(stage string) error {
		if stage == "before_intent_clear" {
			return os.Chmod(intentDir, 0o500)
		}
		return nil
	}
	res, err := backend.Cleanup(testContext(t), cleanupReqFor(job, disp))
	if err != nil {
		t.Fatalf("cleanup must classify, not error: %v", err)
	}
	if !res.Outcome.ProvesAbsent() {
		t.Fatalf("removal outcome = %s: %s", res.Outcome, res.Detail)
	}
	if !strings.Contains(res.Detail, "clear failed") {
		t.Fatalf("clear failure was not surfaced: %q", res.Detail)
	}
	if err := os.Chmod(intentDir, 0o700); err != nil {
		t.Fatal(err)
	}
	pending, err := backend.PendingCleanupObligations(testContext(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 {
		t.Fatalf("unresolved intent = %+v, want one", pending)
	}
	if err := backend.clearCleanupIntent(disp.Handle); err != nil {
		t.Fatal(err)
	}
	pending, err = backend.PendingCleanupObligations(testContext(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("cleared intent still listed: %+v", pending)
	}
}
