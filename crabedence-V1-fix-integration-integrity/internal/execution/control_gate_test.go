package execution

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openclaw/crabbox/internal/capability"
	"github.com/openclaw/crabbox/internal/evidence"
	"github.com/openclaw/crabbox/internal/releasectl"
)

// TestControlGateDeniesMutations: a denying gate refuses MUTATION work
// before the provider is invoked; PURE/READ never consult it —
// evidence and recovery paths continue during a halt.
func TestControlGateDeniesMutations(t *testing.T) {
	p := &simProvider{effect: true}
	exec, _ := simExec(t, p)
	exec.SetControlGate(func() error { return errors.New("deployment halted") })

	resp := exec.ExecuteWithIdempotency(context.Background(),
		crashRequest("alice@example.com", "gate-deny-1"), crashDesc)
	if resp.Status != StatusDenied {
		t.Fatalf("halted dispatch = %s, want DENIED", resp.Status)
	}
	if p.calls.Load() != 0 || p.effects.Load() != 0 {
		t.Fatalf("denied dispatch invoked provider: calls=%d effects=%d", p.calls.Load(), p.effects.Load())
	}

	// PURE skips the gate entirely.
	pure := capability.ResolvedDescriptor{ExecutionClass: capability.ClassPure, AdapterID: "test-adapter"}
	resp = exec.ExecuteWithIdempotency(context.Background(),
		crashRequest("alice@example.com", "gate-pure-1"), pure)
	if resp.Status == StatusDenied {
		t.Fatal("PURE must not be denied by the control gate")
	}
	if p.calls.Load() != 1 {
		t.Fatalf("pure dispatch calls=%d, want 1", p.calls.Load())
	}
}

// TestControlGateUnavailableFailsClosed: a gate that errors because
// the store is unreachable denies — outage is never "no restrictions".
func TestControlGateUnavailableFailsClosed(t *testing.T) {
	p := &simProvider{effect: true}
	exec, _ := simExec(t, p)
	exec.SetControlGate(func() error {
		return fmt.Errorf("%w: store gone", releasectl.ErrUnavailable)
	})
	resp := exec.ExecuteWithIdempotency(context.Background(),
		crashRequest("alice@example.com", "gate-outage-1"), crashDesc)
	if resp.Status != StatusDenied {
		t.Fatalf("outage dispatch = %s, want DENIED", resp.Status)
	}
	if p.effects.Load() != 0 {
		t.Fatal("no effect may be applied while control state is unreadable")
	}
}

// TestControlGateLedgerFlow: the wired gate enforces the real ledger —
// unsigned halt denies the next dispatch; a signed resume from a
// trusted operator admits again. The gate re-reads the chain on every
// admission, so operator action lands without a service restart.
func TestControlGateLedgerFlow(t *testing.T) {
	dir := t.TempDir()
	ledgerPath := filepath.Join(dir, "control.jsonl")
	ckptPath := filepath.Join(dir, "ext", "control.checkpoint")
	rootsPath := filepath.Join(dir, "trust-roots.txt")

	op, err := evidence.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	if err := writeTextFile(rootsPath, op.Fingerprint()+"\n"); err != nil {
		t.Fatal(err)
	}

	cfg := ControlLedgerConfig{
		LedgerPath:     ledgerPath,
		CheckpointPath: ckptPath,
		TrustRootsPath: rootsPath,
		Deployment:     "dep-a",
	}
	gate, err := newControlGate(cfg)
	if err != nil {
		t.Fatal(err)
	}
	p := &simProvider{effect: true}
	exec, _ := simExec(t, p)
	exec.SetControlGate(gate)

	mut := crashDesc
	key := "gate-flow-1"
	resp := exec.ExecuteWithIdempotency(context.Background(), crashRequest("alice@example.com", key), mut)
	if resp.Status == StatusDenied {
		t.Fatalf("admission denied before any control event: %s", resp.Error)
	}
	if p.calls.Load() != 1 {
		t.Fatalf("baseline dispatch calls=%d, want 1", p.calls.Load())
	}

	// Operator halts — unsigned emergency event through the ledger API.
	v := releasectl.NewVerifier(releasectl.TrustRoots{op.Fingerprint(): true}, false)
	l, err := releasectl.Create(ledgerPath, ckptPath, v)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Append(l.NewEvent(releasectl.KindHalt, "dep-a", "incident")); err != nil {
		t.Fatal(err)
	}
	resp = exec.ExecuteWithIdempotency(context.Background(), crashRequest("alice@example.com", "gate-flow-2"), mut)
	if resp.Status != StatusDenied {
		t.Fatalf("halted dispatch = %s, want DENIED", resp.Status)
	}
	if p.calls.Load() != 1 {
		t.Fatalf("halted dispatch invoked provider: calls=%d", p.calls.Load())
	}

	// Other deployments are unaffected.
	if err := l.AdmitError("dep-b"); err != nil {
		t.Fatalf("dep-b must be unaffected: %v", err)
	}

	// Signed resume restores admission.
	e := l.NewEvent(releasectl.KindResume, "dep-a", "incident closed")
	if err := releasectl.SignEvent(op, &e); err != nil {
		t.Fatal(err)
	}
	if err := l.Append(e); err != nil {
		t.Fatal(err)
	}
	resp = exec.ExecuteWithIdempotency(context.Background(), crashRequest("alice@example.com", "gate-flow-3"), mut)
	if resp.Status == StatusDenied {
		t.Fatalf("post-resume dispatch denied: %s", resp.Error)
	}
	if p.calls.Load() != 2 {
		t.Fatalf("post-resume calls=%d, want 2", p.calls.Load())
	}
}

// TestControlGateTamperedLedgerFailsClosed: a kernel-writable process
// that rewrites the ledger cannot admit itself — the chain fails
// verification and the gate denies.
func TestControlGateTamperedLedgerFailsClosed(t *testing.T) {
	dir := t.TempDir()
	ledgerPath := filepath.Join(dir, "control.jsonl")
	ckptPath := filepath.Join(dir, "ext", "control.checkpoint")
	rootsPath := filepath.Join(dir, "trust-roots.txt")

	op, _ := evidence.GenerateSigner()
	writeTextFile(rootsPath, op.Fingerprint()+"\n")

	v := releasectl.NewVerifier(releasectl.TrustRoots{op.Fingerprint(): true}, false)
	l, err := releasectl.Create(ledgerPath, ckptPath, v)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Append(l.NewEvent(releasectl.KindHalt, "dep-a", "incident")); err != nil {
		t.Fatal(err)
	}

	cfg := ControlLedgerConfig{LedgerPath: ledgerPath, CheckpointPath: ckptPath, TrustRootsPath: rootsPath, Deployment: "dep-a"}
	gate, err := newControlGate(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := gate(); err == nil {
		t.Fatal("gate must deny under halt")
	}

	// Rogue rewrite: change halt→resume in place.
	data, _ := os.ReadFile(ledgerPath)
	forged := strings.Replace(string(data), `"kind":"halt"`, `"kind":"resume"`, 1)
	if err := writeTextFile(ledgerPath, forged); err != nil {
		t.Fatal(err)
	}
	if err := gate(); err == nil {
		t.Fatal("tampered ledger must fail closed, not admit")
	}
}

// ─── Config resolution ──────────────────────────────────────────────

func TestControlLedgerConfigFromEnv(t *testing.T) {
	set := func(k, v string) { t.Setenv(k, v) }

	t.Run("production requires full tuple", func(t *testing.T) {
		set("CRABEDENCE_CONTROL_LEDGER", "")
		set("CRABEDENCE_CONTROL_TRUST_ROOTS", "")
		set("CRABEDENCE_DEPLOYMENT", "")
		set("CRABEDENCE_CONTROL_ALLOW_UNSIGNED", "")
		if _, err := controlLedgerConfigFromEnv(true); err == nil {
			t.Fatal("production without control config must fail closed")
		}
	})
	t.Run("production full tuple resolves", func(t *testing.T) {
		set("CRABEDENCE_CONTROL_LEDGER", "/var/lib/ctl/ledger.jsonl")
		set("CRABEDENCE_CONTROL_TRUST_ROOTS", "/etc/ctl/roots.txt")
		set("CRABEDENCE_DEPLOYMENT", "prod-a")
		set("CRABEDENCE_CONTROL_CHECKPOINT", "")
		set("CRABEDENCE_CONTROL_ALLOW_UNSIGNED", "")
		cfg, err := controlLedgerConfigFromEnv(true)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.CheckpointPath != "/var/lib/ctl/ledger.jsonl.checkpoint" {
			t.Fatalf("default checkpoint = %q", cfg.CheckpointPath)
		}
	})
	t.Run("production refuses unsigned mode", func(t *testing.T) {
		set("CRABEDENCE_CONTROL_LEDGER", "/x")
		set("CRABEDENCE_CONTROL_TRUST_ROOTS", "/y")
		set("CRABEDENCE_DEPLOYMENT", "d")
		set("CRABEDENCE_CONTROL_CHECKPOINT", "")
		set("CRABEDENCE_CONTROL_ALLOW_UNSIGNED", "1")
		if _, err := controlLedgerConfigFromEnv(true); err == nil {
			t.Fatal("ALLOW_UNSIGNED must be refused in production")
		}
	})
	t.Run("development tolerates absence", func(t *testing.T) {
		set("CRABEDENCE_CONTROL_LEDGER", "")
		set("CRABEDENCE_CONTROL_TRUST_ROOTS", "")
		set("CRABEDENCE_DEPLOYMENT", "")
		set("CRABEDENCE_CONTROL_ALLOW_UNSIGNED", "")
		cfg, err := controlLedgerConfigFromEnv(false)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Enabled() {
			t.Fatal("unconfigured dev must not enable the gate")
		}
	})
	t.Run("development ledger requires deployment", func(t *testing.T) {
		set("CRABEDENCE_CONTROL_LEDGER", "/x")
		set("CRABEDENCE_DEPLOYMENT", "")
		set("CRABEDENCE_CONTROL_TRUST_ROOTS", "")
		set("CRABEDENCE_CONTROL_ALLOW_UNSIGNED", "")
		if _, err := controlLedgerConfigFromEnv(false); err == nil {
			t.Fatal("dev ledger without deployment must fail")
		}
	})
}

func writeTextFile(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0o600)
}
