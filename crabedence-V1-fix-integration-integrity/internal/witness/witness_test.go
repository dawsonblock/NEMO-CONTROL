package witness

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openclaw/crabbox/internal/evidence"
)

func newDeploymentSigner(t *testing.T) *evidence.Signer {
	t.Helper()
	s, err := evidence.GenerateSigner()
	if err != nil {
		t.Fatalf("deployment signer: %v", err)
	}
	return s
}

func newLedger(t *testing.T) *Ledger {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "witness")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	l, err := OpenLedger(filepath.Join(dir, "custody.db"))
	if err != nil {
		t.Fatalf("open ledger: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

func signedPayload(t *testing.T, signer *evidence.Signer, executionID string) []byte {
	t.Helper()
	payload, err := signer.Sign(evidence.Binding{
		ExecutionID:    executionID,
		Capability:     "test.critical.deploy",
		Principal:      "alice@example.com",
		RequestDigest:  "digest-1",
		ProviderID:     "deploy-adapter",
		ProviderRunID:  "run-1",
		Outcome:        evidence.OutcomeCompleted,
		EvidenceSHA256: strings.Repeat("ab", 32),
	})
	if err != nil {
		t.Fatalf("sign payload: %v", err)
	}
	return payload
}

func submitReq(deploymentFP string, seq int64, executionID, digest string, payload []byte) Request {
	return Request{
		Op:            OpSubmit,
		DeploymentFP:  deploymentFP,
		Seq:           seq,
		ExecutionID:   executionID,
		ReceiptDigest: digest,
		Payload:       payload,
	}
}

func TestSubmitSignedReceiptReturnsVerifiableAck(t *testing.T) {
	ctx := context.Background()
	dep := newDeploymentSigner(t)
	ws := newDeploymentSigner(t)
	ledger := newLedger(t)

	ack, err := ledger.Submit(ctx, ws,
		submitReq(dep.Fingerprint(), 1, "exec-1", "digest-1", signedPayload(t, dep, "exec-1")), "")
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if ack.WitnessFP != ws.Fingerprint() || ack.Seq != 1 || ack.ExecutionID != "exec-1" {
		t.Fatalf("ack fields wrong: %+v", ack)
	}
	if err := VerifyAck(ack, ws.PublicKey()); err != nil {
		t.Fatalf("ack does not verify under witness key: %v", err)
	}
	// A foreign witness key must NOT verify the ack — custody proof is
	// bound to the witness identity that countersigned it.
	other := newDeploymentSigner(t)
	if err := VerifyAck(ack, other.PublicKey()); err == nil {
		t.Fatal("ack verified under a foreign witness key")
	}
	head, execID, digest, err := ledger.Head(ctx, dep.Fingerprint())
	if err != nil || head != 1 || execID != "exec-1" || digest != "digest-1" {
		t.Fatalf("head after submit = (%d,%q,%q), err %v", head, execID, digest, err)
	}
}

func TestSubmitRejectsForgedReceipt(t *testing.T) {
	ctx := context.Background()
	dep := newDeploymentSigner(t)
	forged := newDeploymentSigner(t)
	ws := newDeploymentSigner(t)
	ledger := newLedger(t)

	// A receipt signed by a foreign key presented under the bound
	// deployment's identity — the kernel cannot mint its own proof.
	req := submitReq(dep.Fingerprint(), 1, "exec-1", "digest-1", signedPayload(t, forged, "exec-1"))
	if _, err := ledger.Submit(ctx, ws, req, ""); !errors.Is(err, ErrReceiptVerify) {
		t.Fatalf("forged receipt: want ErrReceiptVerify, got %v", err)
	}
}

func TestSubmitRejectsTamperedReceipt(t *testing.T) {
	ctx := context.Background()
	dep := newDeploymentSigner(t)
	ws := newDeploymentSigner(t)
	ledger := newLedger(t)

	payload := signedPayload(t, dep, "exec-1")
	var receipt map[string]any
	if err := json.Unmarshal(payload, &receipt); err != nil {
		t.Fatal(err)
	}
	receipt["outcome"] = "NO_EFFECT" // rewrite history after signing
	tampered, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.Submit(ctx, ws, submitReq(dep.Fingerprint(), 1, "exec-1", "digest-1", tampered), ""); !errors.Is(err, ErrReceiptVerify) {
		t.Fatalf("tampered receipt: want ErrReceiptVerify, got %v", err)
	}
}

func TestSubmitRejectsReceiptExecutionMismatch(t *testing.T) {
	ctx := context.Background()
	dep := newDeploymentSigner(t)
	ws := newDeploymentSigner(t)
	ledger := newLedger(t)

	// A validly signed receipt naming a different execution — a
	// compromised kernel replaying a real receipt under a wrong
	// execution identity.
	payload := signedPayload(t, dep, "exec-A")
	if _, err := ledger.Submit(ctx, ws, submitReq(dep.Fingerprint(), 1, "exec-B", "digest-1", payload), ""); !errors.Is(err, ErrReceiptVerify) {
		t.Fatalf("execution mismatch: want ErrReceiptVerify, got %v", err)
	}
}

func TestSubmitRejectsForeignDeployment(t *testing.T) {
	ctx := context.Background()
	depA := newDeploymentSigner(t)
	depB := newDeploymentSigner(t)
	ws := newDeploymentSigner(t)
	ledger := newLedger(t)

	if _, err := ledger.Submit(ctx, ws, submitReq(depA.Fingerprint(), 1, "exec-1", "d", nil), ""); err != nil {
		t.Fatalf("first submit: %v", err)
	}
	// Deployment B arrives at a witness bound to A — replaying acks
	// into a different deployment boundary must not hold.
	if _, err := ledger.Submit(ctx, ws, submitReq(depB.Fingerprint(), 1, "exec-1", "d", nil), ""); !errors.Is(err, ErrDeploymentMismatch) {
		t.Fatalf("foreign deployment: want ErrDeploymentMismatch, got %v", err)
	}
}

func TestSubmitSequenceRules(t *testing.T) {
	ctx := context.Background()
	dep := newDeploymentSigner(t)
	ws := newDeploymentSigner(t)
	ledger := newLedger(t)

	// Gap: the first submission cannot jump past head+1.
	if _, err := ledger.Submit(ctx, ws, submitReq(dep.Fingerprint(), 2, "exec-2", "d", nil), ""); !errors.Is(err, ErrSequence) {
		t.Fatalf("sequence gap: want ErrSequence, got %v", err)
	}
	ack1, err := ledger.Submit(ctx, ws, submitReq(dep.Fingerprint(), 1, "exec-1", "digest-1", nil), "")
	if err != nil {
		t.Fatalf("submit seq 1: %v", err)
	}
	// Idempotent resend — an identical row returns the stored ack.
	ack2, err := ledger.Submit(ctx, ws, submitReq(dep.Fingerprint(), 1, "exec-1", "digest-1", nil), "")
	if err != nil {
		t.Fatalf("idempotent resend: %v", err)
	}
	if ack1.Signature != ack2.Signature {
		t.Fatal("idempotent resend returned a different ack")
	}
	// Divergent reuse of a consumed sequence — a rollback disguise —
	// is a hard refusal, never a silent rewrite.
	if _, err := ledger.Submit(ctx, ws, submitReq(dep.Fingerprint(), 1, "exec-OTHER", "digest-OTHER", nil), ""); !errors.Is(err, ErrSequence) {
		t.Fatalf("divergent seq reuse: want ErrSequence, got %v", err)
	}
	// Next must be head+1 — a skipped seq is refused.
	if _, err := ledger.Submit(ctx, ws, submitReq(dep.Fingerprint(), 3, "exec-3", "d", nil), ""); !errors.Is(err, ErrSequence) {
		t.Fatalf("skip to seq 3: want ErrSequence, got %v", err)
	}
	if _, err := ledger.Submit(ctx, ws, submitReq(dep.Fingerprint(), 2, "exec-2", "d", nil), ""); err != nil {
		t.Fatalf("seq 2 after head+1: %v", err)
	}
}

func TestPinnedDeploymentBinding(t *testing.T) {
	ctx := context.Background()
	dep := newDeploymentSigner(t)
	other := newDeploymentSigner(t)
	ws := newDeploymentSigner(t)
	ledger := newLedger(t)

	// Pinned witness refuses any other deployment even as first-seen.
	if _, err := ledger.Submit(ctx, ws, submitReq(other.Fingerprint(), 1, "exec-1", "d", nil), dep.Fingerprint()); !errors.Is(err, ErrDeploymentMismatch) {
		t.Fatalf("pinned mismatch: want ErrDeploymentMismatch, got %v", err)
	}
	if _, err := ledger.Submit(ctx, ws, submitReq(dep.Fingerprint(), 1, "exec-1", "d", nil), dep.Fingerprint()); err != nil {
		t.Fatalf("pinned submit: %v", err)
	}
}

func TestHandleValidationAndStatus(t *testing.T) {
	ctx := context.Background()
	dep := newDeploymentSigner(t)
	ws := newDeploymentSigner(t)
	svc := NewService(newLedger(t), ws, dep.Fingerprint(), nil)

	if resp := svc.Handle(ctx, Request{Op: OpSubmit, DeploymentFP: dep.Fingerprint(), Seq: 0, ExecutionID: "e", ReceiptDigest: "d"}); resp.OK {
		t.Fatal("seq 0 accepted")
	}
	if resp := svc.Handle(ctx, Request{Op: OpSubmit, DeploymentFP: dep.Fingerprint(), Seq: 1, ExecutionID: "", ReceiptDigest: "d"}); resp.OK {
		t.Fatal("missing execution_id accepted")
	}
	if resp := svc.Handle(ctx, Request{Op: "bogus"}); resp.OK {
		t.Fatal("unknown op accepted")
	}
	resp := svc.Handle(ctx, Request{Op: OpStatus, DeploymentFP: dep.Fingerprint()})
	if !resp.OK || resp.WitnessFP != ws.Fingerprint() || resp.Records != 0 {
		t.Fatalf("status: %+v", resp)
	}
}

// ─── Kernel-side outbox + sender ─────────────────────────────────────

func newOutbox(t *testing.T, dir string) *Outbox {
	t.Helper()
	o, err := OpenOutbox(filepath.Join(dir, "outbox.db"))
	if err != nil {
		t.Fatalf("open outbox: %v", err)
	}
	t.Cleanup(func() { o.Close() })
	return o
}

// startWitness runs a witness service on a fresh socket under dir and
// returns its ledger (for assertions) — the separate process is an
// in-process goroutine here, but the boundary (socket + own signer +
// own ledger) is the production boundary.
func startWitness(t *testing.T, dir, pinnedFP string) (*Ledger, string, context.CancelFunc) {
	t.Helper()
	wDir := filepath.Join(dir, "witness")
	// Darwin bounds unix socket paths at ~104 bytes — the deep TempDir
	// path overflows it, so the socket lives under a short temp root.
	sockRoot, err := os.MkdirTemp("", "ws")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(sockRoot) })
	if err := os.MkdirAll(wDir, 0o700); err != nil {
		t.Fatal(err)
	}
	ledger, err := OpenLedger(filepath.Join(wDir, "custody.db"))
	if err != nil {
		t.Fatalf("witness ledger: %v", err)
	}
	ws, err := evidence.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(sockRoot, "w.sock")
	ctx, cancel := context.WithCancel(context.Background())
	svc := NewService(ledger, ws, pinnedFP, nil)
	serveErr := make(chan error, 1)
	go func() { serveErr <- svc.Serve(ctx, sock) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		select {
		case err := <-serveErr:
			t.Fatalf("witness serve exited: %v", err)
		default:
		}
		if _, err := os.Stat(sock); err == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, err := os.Stat(sock); err != nil {
		t.Fatalf("witness socket never appeared: %v", err)
	}
	t.Cleanup(func() { cancel(); ledger.Close() })
	return ledger, sock, cancel
}

func TestSenderDeliversAndWitnessVerifies(t *testing.T) {
	ctx := context.Background()
	dep := newDeploymentSigner(t)
	root := t.TempDir()
	ledger, sock, _ := startWitness(t, root, dep.Fingerprint())

	outbox := newOutbox(t, filepath.Join(root, "kernel"))
	client := NewClient(sock)
	sender := NewSender(client, outbox, dep.Fingerprint(), nil)

	seq1, err := outbox.Enqueue(ctx, "exec-1", "digest-1", signedPayload(t, dep, "exec-1"))
	if err != nil || seq1 != 1 {
		t.Fatalf("enqueue: %v seq=%d", err, seq1)
	}
	if _, err := outbox.Enqueue(ctx, "exec-2", "digest-2", nil); err != nil {
		t.Fatalf("enqueue 2: %v", err)
	}

	sender.drain(ctx)
	if !sender.CustodyHealthy(ctx) {
		t.Fatalf("custody not healthy after drain: %v", sender.LastError())
	}
	if n, _ := outbox.Undelivered(ctx); n != 0 {
		t.Fatalf("%d undelivered after drain", n)
	}
	head, execID, _, err := ledger.Head(ctx, dep.Fingerprint())
	if err != nil || head != 2 || execID != "exec-2" {
		t.Fatalf("witness head = %d/%q, err %v", head, execID, err)
	}
}

func TestSenderDegradedWhileWitnessDown(t *testing.T) {
	ctx := context.Background()
	dep := newDeploymentSigner(t)
	root := t.TempDir()
	outbox := newOutbox(t, filepath.Join(root, "kernel"))

	// No witness listening — the sender degrades, the outbox retains,
	// and the custody gate (CustodyHealthy) refuses CRITICAL work.
	sender := NewSender(NewClient(filepath.Join(root, "nowhere.sock")), outbox, dep.Fingerprint(), nil)
	if _, err := outbox.Enqueue(ctx, "exec-1", "d", nil); err != nil {
		t.Fatal(err)
	}
	sender.drain(ctx)
	if sender.CustodyHealthy(ctx) {
		t.Fatal("custody healthy while witness unreachable")
	}
	if sender.LastError() == "" {
		t.Fatal("no degradation recorded")
	}
	if n, _ := outbox.Undelivered(ctx); n != 1 {
		t.Fatalf("outbox lost its pending row: %d undelivered", n)
	}

	// Witness arrives — backlog drains, health restores.
	_, sock, _ := startWitness(t, root, dep.Fingerprint())
	sender = NewSender(NewClient(sock), outbox, dep.Fingerprint(), nil)
	sender.drain(ctx)
	if !sender.CustodyHealthy(ctx) {
		t.Fatalf("custody still degraded after witness recovery: %v", sender.LastError())
	}
}

func TestWitnessRestoreRealignsFromCheckpoint(t *testing.T) {
	ctx := context.Background()
	dep := newDeploymentSigner(t)
	root := t.TempDir()

	// Phase 1: deliver three receipts to witness A.
	_, sockA, cancelA := startWitness(t, filepath.Join(root, "a"), dep.Fingerprint())
	outbox := newOutbox(t, filepath.Join(root, "kernel"))
	for i := 1; i <= 3; i++ {
		if _, err := outbox.Enqueue(ctx, "exec-"+string(rune('0'+i)), "d", nil); err != nil {
			t.Fatal(err)
		}
	}
	sender := NewSender(NewClient(sockA), outbox, dep.Fingerprint(), nil)
	sender.drain(ctx)
	if !sender.CustodyHealthy(ctx) {
		t.Fatalf("phase 1 drain failed: %v", sender.LastError())
	}
	cancelA()

	// Phase 2: witness restored from an older checkpoint — a fresh
	// ledger at head 0. The kernel resends from head+1; identical rows
	// re-custody cleanly, so history is re-established rather than
	// silently lost.
	ledgerB, sockB, _ := startWitness(t, filepath.Join(root, "b"), dep.Fingerprint())
	sender = NewSender(NewClient(sockB), outbox, dep.Fingerprint(), nil)
	sender.drain(ctx)
	if !sender.CustodyHealthy(ctx) {
		t.Fatalf("phase 2 resend failed: %v", sender.LastError())
	}
	if head, _, _, err := ledgerB.Head(ctx, dep.Fingerprint()); err != nil || head != 3 {
		t.Fatalf("restored witness head = %d, want 3 (err %v)", head, err)
	}
}

func TestWitnessRejectsDivergentResend(t *testing.T) {
	ctx := context.Background()
	dep := newDeploymentSigner(t)
	root := t.TempDir()
	ledger, sock, _ := startWitness(t, root, dep.Fingerprint())
	outbox := newOutbox(t, filepath.Join(root, "kernel"))

	if _, err := outbox.Enqueue(ctx, "exec-1", "digest-1", nil); err != nil {
		t.Fatal(err)
	}
	sender := NewSender(NewClient(sock), outbox, dep.Fingerprint(), nil)
	sender.drain(ctx)
	if !sender.CustodyHealthy(ctx) {
		t.Fatal("initial drain failed")
	}

	// A compromised kernel tampers with its own outbox: seq 1 is
	// already custodied for exec-1/digest-1 — resubmission with
	// divergent content must be refused by the witness, and the sender
	// surfaces the refusal rather than overwriting history.
	if _, err := outbox.Enqueue(ctx, "exec-1-REWRITTEN", "digest-REWRITTEN", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.Submit(ctx, newDeploymentSigner(t),
		submitReq(dep.Fingerprint(), 1, "exec-1-REWRITTEN", "digest-REWRITTEN", nil), ""); !errors.Is(err, ErrSequence) {
		t.Fatalf("divergent custody rewrite accepted: %v", err)
	}
}
