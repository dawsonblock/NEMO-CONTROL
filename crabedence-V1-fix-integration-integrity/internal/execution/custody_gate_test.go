package execution

// G4 — custody boundary at the dispatch executor: CRITICAL work fails
// closed while custody is degraded, terminal receipts flow to the
// durable outbox, and provider-terminal state stays distinct from
// verified custody.

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openclaw/crabbox/internal/capability"
	"github.com/openclaw/crabbox/internal/custody"
	"github.com/openclaw/crabbox/internal/evidence"
	"github.com/openclaw/crabbox/internal/idempotency"
	"github.com/openclaw/crabbox/internal/witness"
)

// fullProofsProvider wraps simProvider declaring the evidence proofs
// CRITICAL admission requires, and artifactProvider returns a provider
// whose terminal responses carry the evidence artifact the CRITICAL
// receipt is computed from.
func fullProofsProvider(p *simProvider) Handler {
	return declaringProvider{simProvider: p, caps: ProviderCapabilities{
		SupportsProviderIdempotency: true,
		SupportsStatusLookup:        true,
		SupportsCompletionProof:     true,
		SupportsNonexecutionProof:   true,
		RecoveryLocatorType:         "provider_run_id",
	}}
}

func artifactProvider() *simProvider {
	return &simProvider{effect: true, respond: func(n int32) Response {
		return Response{Status: StatusSucceeded, EvidenceArtifact: []byte(`{"proof":"terminal"}`)}
	}}
}

func custodySigner(t *testing.T) *evidence.Signer {
	t.Helper()
	s, err := evidence.GenerateSigner()
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return s
}

// TestCustodyGateRefusesCriticalWhenDegraded: the custody gate admits
// only when the custody path is clean — a degraded witness path
// refuses CRITICAL work before the provider runs; MUTATION never
// consults it.
func TestCustodyGateRefusesCriticalWhenDegraded(t *testing.T) {
	p := &simProvider{effect: true}
	store := openExecutorSQLiteStore(t, idempotency.DefaultLeaseConfig)
	exec := NewDispatchExecutor(fullProofsProvider(p), store)
	exec.SetEvidenceSigner(custodySigner(t))

	var degraded atomic.Bool
	degraded.Store(true)
	exec.SetCustodyGate(func() error {
		if degraded.Load() {
			return errors.New("custody backlog pending")
		}
		return nil
	})

	resp := exec.ExecuteWithIdempotency(context.Background(),
		crashRequest("alice@example.com", "custody-deny-1"), criticalDesc())
	if resp.Status != StatusDenied || resp.FailureCode != string(capability.FailureAdmissionDenied) {
		t.Fatalf("degraded custody dispatch = %s/%s, want DENIED", resp.Status, resp.FailureCode)
	}
	if p.calls.Load() != 0 {
		t.Fatal("refused dispatch invoked the provider")
	}

	// MUTATION never consults the custody gate.
	resp = exec.ExecuteWithIdempotency(context.Background(),
		crashRequest("alice@example.com", "custody-mut-1"), crashDesc)
	if resp.Status == StatusDenied {
		t.Fatalf("MUTATION refused by the custody gate: %s", resp.Error)
	}

	degraded.Store(false)
	resp = exec.ExecuteWithIdempotency(context.Background(),
		crashRequest("alice@example.com", "custody-admit-1"), criticalDesc())
	if resp.Status == StatusDenied {
		t.Fatalf("healthy custody refused CRITICAL: %s", resp.Error)
	}
	if p.calls.Load() != 2 {
		t.Fatalf("calls=%d, want 2 (mutation + admitted critical)", p.calls.Load())
	}
}

// TestCustodySinkReceivesTerminalReceipts: every committed terminal
// outcome reaches the custody sink with its receipt identity and
// signed bytes — the envelope the witness will custody wraps these
// exact bytes.
func TestCustodySinkReceivesTerminalReceipts(t *testing.T) {
	p := artifactProvider()
	store := openExecutorSQLiteStore(t, idempotency.DefaultLeaseConfig)
	kernel := custodySigner(t)
	store.SetTrustedEvidenceSigners(kernel.Fingerprint())
	exec := NewDispatchExecutor(fullProofsProvider(p), store)
	exec.SetEvidenceSigner(kernel)

	type captured struct {
		execID, digest string
		payload        []byte
	}
	var got atomic.Value
	exec.SetCustodySink(func(executionID, receiptDigest string, payload []byte) {
		got.Store(captured{executionID, receiptDigest, payload})
	})

	resp := exec.ExecuteWithIdempotency(context.Background(),
		crashRequest("alice@example.com", "custody-sink-1"), criticalDesc())
	if resp.Status != StatusSucceeded {
		t.Fatalf("critical dispatch = %s: %s", resp.Status, resp.Error)
	}
	c, ok := got.Load().(captured)
	if !ok || c.execID == "" || c.digest == "" || len(c.payload) == 0 {
		t.Fatalf("custody sink did not capture a terminal receipt: %+v", c)
	}
	if _, err := evidence.ParseReceipt(c.payload); err != nil {
		t.Fatalf("sink payload is not a signed receipt: %v", err)
	}
}

// TestCustodyEndToEndProviderTerminalVsVerified: a committed provider
// terminal result is custody-pending until the witness's verified
// acknowledgement lands — the outage refuses follow-on CRITICAL work,
// the reconnect reconciles, and the recorded ack verifies under the
// pinned custodian key. Wire-to-wire, no stubs.
func TestCustodyEndToEndProviderTerminalVsVerified(t *testing.T) {
	dep := "dep-alpha"
	kernel := custodySigner(t)
	wsigner := custodySigner(t)

	// Witness side: real ledger + service on a unix socket (short
	// path — platform limit).
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	ktrust := custody.NewTrustSet(custody.TrustedKey{
		Role: custody.RoleKernelRelay, KeyID: kernel.Fingerprint(),
		PublicKey: kernel.PublicKey(), DeploymentID: dep,
	})
	ledger, err := witness.OpenLedger(filepath.Join(dir, "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	svc := witness.NewService(ledger, wsigner, dep, ktrust, nil)
	sockDir, err := os.MkdirTemp("/tmp", "cw")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(sockDir)
	sock := filepath.Join(sockDir, "w.sock")

	// Kernel side: the real boundary wiring against a trust file.
	ctrust := custody.NewTrustSet(custody.TrustedKey{
		Role: custody.RoleCustodian, KeyID: wsigner.Fingerprint(),
		PublicKey: wsigner.PublicKey(), DeploymentID: dep,
	})
	trustPath := filepath.Join(dir, "custodian-trust.json")
	trustJSON := fmt.Sprintf(`{"version":1,"keys":[{"role":"custodian","key_id":"%s","public_key":"%s","deployment_id":"%s","valid_from_index":0,"valid_until_index":0}]}`,
		wsigner.Fingerprint(), b64pub(wsigner), dep)
	if err := os.WriteFile(trustPath, []byte(trustJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	outboxPath := filepath.Join(dir, "outbox.db")
	// Outbox dir must be 0700 for the custody-storage rule.
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	wc := WitnessConfig{
		Socket:         sock,
		OutboxPath:     outboxPath,
		TrustRootsPath: trustPath,
		Deployment:     dep,
		// Long interval: drains happen only when the sink wakes the
		// sender — the test controls custody timing deterministically.
		DrainInterval: time.Hour,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Witness UP first: a terminal dispatch commits AND is custodied.
	svcCtx, svcCancel := context.WithCancel(context.Background())
	go func() { _ = svc.Serve(svcCtx, sock) }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("witness socket never appeared")
		}
		time.Sleep(10 * time.Millisecond)
	}

	hooks, err := wireCustodyBoundary(ctx, wc, kernel, "0.55.0-rc8.1-dev")
	if err != nil {
		t.Fatal(err)
	}
	p := artifactProvider()
	store := openExecutorSQLiteStore(t, idempotency.DefaultLeaseConfig)
	store.SetTrustedEvidenceSigners(kernel.Fingerprint())
	exec := NewDispatchExecutor(fullProofsProvider(p), store)
	exec.SetEvidenceSigner(kernel)
	exec.SetCustodyGate(hooks.gate)
	exec.SetCustodySink(hooks.sink)

	outbox, err := witness.OpenOutbox(outboxPath)
	if err != nil {
		t.Fatal(err)
	}
	defer outbox.Close()

	resp := exec.ExecuteWithIdempotency(context.Background(),
		crashRequest("alice@example.com", "custody-e2e-1"), criticalDesc())
	if resp.Status != StatusSucceeded {
		t.Fatalf("terminal dispatch = %s: %s", resp.Status, resp.Error)
	}
	for {
		if n, _ := outbox.Undelivered(context.Background()); n == 0 && hooks.gate() == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("first receipt never reached verified custody")
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Witness dies: the next dispatch still commits provider-terminal
	// — a committed outcome is never rewound — but custody stays
	// pending, and the gate then refuses FOLLOW-ON critical work. The
	// gate is still healthy at admission: the sender only learns of
	// the outage when the sink's enqueue wakes the drain.
	svcCancel()
	resp = exec.ExecuteWithIdempotency(context.Background(),
		crashRequest("alice@example.com", "custody-e2e-2"), criticalDesc())
	if resp.Status != StatusSucceeded {
		t.Fatalf("in-flight terminal dispatch = %s: %s", resp.Status, resp.Error)
	}
	if p.calls.Load() != 2 {
		t.Fatalf("calls=%d, want 2 — the committed dispatch ran its provider", p.calls.Load())
	}
	for {
		if err := hooks.gate(); err != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("custody gate stayed healthy through a witness outage")
		}
		time.Sleep(20 * time.Millisecond)
	}
	resp = exec.ExecuteWithIdempotency(context.Background(),
		crashRequest("alice@example.com", "custody-e2e-3"), criticalDesc())
	if resp.Status != StatusDenied {
		t.Fatalf("CRITICAL admitted while custody degraded: %s", resp.Status)
	}
	if p.calls.Load() != 2 {
		t.Fatal("degraded-custody dispatch invoked the provider")
	}

	// Witness up again: the backlog drains, custody reconciles, and
	// admissions resume — the outage never produced verified custody,
	// it delayed it.
	svc2Ctx, svc2Cancel := context.WithCancel(context.Background())
	defer svc2Cancel()
	svc2 := witness.NewService(ledger, wsigner, dep, ktrust, nil)
	go func() { _ = svc2.Serve(svc2Ctx, sock) }()
	for {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("witness socket never reappeared")
		}
		time.Sleep(10 * time.Millisecond)
	}
	hooks.wake()
	for {
		if n, _ := outbox.Undelivered(context.Background()); n == 0 && hooks.gate() == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("custody never reconciled after reconnect")
		}
		time.Sleep(20 * time.Millisecond)
	}
	resp = exec.ExecuteWithIdempotency(context.Background(),
		crashRequest("alice@example.com", "custody-e2e-4"), criticalDesc())
	if resp.Status != StatusSucceeded {
		t.Fatalf("post-reconcile CRITICAL = %s: %s", resp.Status, resp.Error)
	}
	for {
		if n, _ := ledger.Records(context.Background(), dep); n == 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("witness holds %d custody records, want 3", func() int64 { n, _ := ledger.Records(context.Background(), dep); return n }())
		}
		hooks.wake()
		time.Sleep(20 * time.Millisecond)
	}
	_ = ctrust // kernel-side verification exercised inside the sender
}

func b64pub(s *evidence.Signer) string {
	return base64.StdEncoding.EncodeToString(s.PublicKey())
}

// TestWitnessConfigFromEnv: a configured custody boundary is complete
// or startup fails — a half-configured boundary is refused, and the
// local and separate-host transports are mutually exclusive.
func TestWitnessConfigFromEnv(t *testing.T) {
	keys := []string{
		"CRABEDENCE_WITNESS_SOCKET", "CRABEDENCE_WITNESS_TLS",
		"CRABEDENCE_WITNESS_TLS_KEY", "CRABEDENCE_WITNESS_OUTBOX",
		"CRABEDENCE_WITNESS_TRUST_ROOTS", "CRABEDENCE_POLICY_DIGEST",
		"CRABEDENCE_WITNESS_DRAIN_INTERVAL",
	}
	clear := func() {
		for _, k := range keys {
			t.Setenv(k, "")
		}
	}
	full := func() {
		t.Setenv("CRABEDENCE_WITNESS_SOCKET", "/run/custody/w.sock")
		t.Setenv("CRABEDENCE_WITNESS_OUTBOX", "/var/lib/custody/outbox.db")
		t.Setenv("CRABEDENCE_WITNESS_TRUST_ROOTS", "/etc/custody/roots.json")
	}

	t.Run("absent is disabled", func(t *testing.T) {
		clear()
		cfg, err := witnessConfigFromEnv(false, "dep-a")
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Enabled() {
			t.Fatal("unconfigured custody must not enable")
		}
	})
	t.Run("complete local tuple resolves", func(t *testing.T) {
		clear()
		full()
		cfg, err := witnessConfigFromEnv(false, "dep-a")
		if err != nil {
			t.Fatal(err)
		}
		if !cfg.Enabled() || cfg.Deployment != "dep-a" {
			t.Fatalf("resolved %+v", cfg)
		}
	})
	t.Run("missing pieces fail", func(t *testing.T) {
		clear()
		t.Setenv("CRABEDENCE_WITNESS_SOCKET", "/run/custody/w.sock")
		if _, err := witnessConfigFromEnv(false, "dep-a"); err == nil {
			t.Fatal("socket without outbox/trust must fail")
		}
	})
	t.Run("deployment required", func(t *testing.T) {
		clear()
		full()
		if _, err := witnessConfigFromEnv(false, ""); err == nil {
			t.Fatal("custody without a deployment identity must fail")
		}
	})
	t.Run("transports are exclusive", func(t *testing.T) {
		clear()
		full()
		t.Setenv("CRABEDENCE_WITNESS_TLS", "custody.internal:9443")
		t.Setenv("CRABEDENCE_WITNESS_TLS_KEY", "aa")
		if _, err := witnessConfigFromEnv(false, "dep-a"); err == nil {
			t.Fatal("socket+tls together must fail")
		}
	})
	t.Run("tls requires pinned key", func(t *testing.T) {
		clear()
		full()
		t.Setenv("CRABEDENCE_WITNESS_SOCKET", "")
		t.Setenv("CRABEDENCE_WITNESS_TLS", "custody.internal:9443")
		if _, err := witnessConfigFromEnv(false, "dep-a"); err == nil {
			t.Fatal("tls without a pinned witness key must fail")
		}
	})
}
