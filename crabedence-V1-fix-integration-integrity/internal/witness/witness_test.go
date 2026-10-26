package witness

// G4 — independent custody + witness. These tests drive the real
// service, ledger, outbox, and sender; nothing is simulated. A "fake"
// here is a second real signer or a second real ledger — never a stub
// verification.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openclaw/crabbox/internal/custody"
	"github.com/openclaw/crabbox/internal/evidence"
)

const testDeployment = "dep-alpha"

type harness struct {
	t          *testing.T
	dir        string
	dep        string
	kernel     *evidence.Signer
	wsigner    *evidence.Signer
	ktrust     *custody.TrustSet // pinned kernel-relay keys (witness side)
	ctrust     *custody.TrustSet // pinned custodian keys (kernel side)
	ledger     *Ledger
	ledgerPath string
	service    *Service
	socket     string
	client     *Client
	outbox     *Outbox
	prod       Producer
	sender     *Sender
	cancel     context.CancelFunc
}

func newHarness(t *testing.T, serve bool) *harness {
	t.Helper()
	h := &harness{t: t, dep: testDeployment}
	h.dir = t.TempDir()
	if err := os.Chmod(h.dir, 0o700); err != nil {
		t.Fatalf("chmod temp dir: %v", err)
	}
	var err error
	if h.kernel, err = evidence.GenerateSigner(); err != nil {
		t.Fatalf("kernel signer: %v", err)
	}
	if h.wsigner, err = evidence.GenerateSigner(); err != nil {
		t.Fatalf("witness signer: %v", err)
	}
	h.ktrust = custody.NewTrustSet(custody.TrustedKey{
		Role: custody.RoleKernelRelay, KeyID: h.kernel.Fingerprint(),
		PublicKey: h.kernel.PublicKey(), DeploymentID: h.dep,
	})
	h.ctrust = custody.NewTrustSet(custody.TrustedKey{
		Role: custody.RoleCustodian, KeyID: h.wsigner.Fingerprint(),
		PublicKey: h.wsigner.PublicKey(), DeploymentID: h.dep,
	})
	h.ledgerPath = filepath.Join(h.dir, "witness-ledger.db")
	if h.ledger, err = OpenLedger(h.ledgerPath); err != nil {
		t.Fatalf("ledger: %v", err)
	}
	h.service = NewService(h.ledger, h.wsigner, h.dep, h.ktrust, nil)
	// Unix sockets are capped at ~104 chars on this platform — the
	// t.TempDir path is already near the limit, so the socket lives in
	// a short /tmp dir while durable state stays in h.dir.
	sockDir, err := os.MkdirTemp("/tmp", "ws")
	if err != nil {
		t.Fatalf("socket dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(sockDir) })
	h.socket = filepath.Join(sockDir, "w.sock")
	if h.outbox, err = OpenOutbox(filepath.Join(h.dir, "outbox.db")); err != nil {
		t.Fatalf("outbox: %v", err)
	}
	h.prod = Producer{
		DeploymentID: h.dep,
		Release:      custody.ReleaseIdentity{Version: "0.55.0-rc8.3-dev", SourceCommit: strings.Repeat("a", 40)},
		Signer:       h.kernel,
	}
	h.client = NewClient(h.socket)
	h.sender = NewSender(h.client, h.outbox, h.dep, h.ctrust, nil)
	if serve {
		h.serve()
	}
	return h
}

func (h *harness) serve() {
	h.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	go func() { _ = h.service.Serve(ctx, h.socket) }()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(h.socket); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	h.t.Fatalf("witness socket did not appear")
}

func (h *harness) enqueue(exec, payload string) int64 {
	h.t.Helper()
	seq, err := h.outbox.Enqueue(context.Background(), h.prod, exec, "digest-"+exec, []byte(payload))
	if err != nil {
		h.t.Fatalf("enqueue %s: %v", exec, err)
	}
	return seq
}

// drain drives exactly one sender pass — deterministic, no ticker.
func (h *harness) drain() bool {
	h.t.Helper()
	return h.sender.drain(context.Background())
}

// craft builds and signs a free-standing envelope for direct
// submission — used for adversarial cases the outbox would never
// produce.
func (h *harness) craft(exec string, index, epoch int64, prev, family string, signer *evidence.Signer, deployment string, payload []byte) *custody.Envelope {
	h.t.Helper()
	env := custody.New(family, deployment,
		custody.ReleaseIdentity{Version: "0.55.0-rc8.3-dev"}, "",
		custody.Subject{EffectID: exec, ExecutionID: exec},
		custody.Sequence{Domain: family, Epoch: epoch, Index: index, PreviousCheckpointHash: prev},
		custody.EncodingWitnessFrame, payload)
	if err := custody.Sign(env, custody.RoleKernelRelay, signer); err != nil {
		h.t.Fatalf("sign envelope: %v", err)
	}
	return env
}

// headPrev returns the previous-checkpoint hash a new submission must
// chain to.
func (h *harness) headPrev() string {
	h.t.Helper()
	_, hash, _, err := h.ledger.Head(context.Background(), h.dep)
	if err != nil {
		h.t.Fatalf("ledger head: %v", err)
	}
	return hash
}

func (h *harness) submitErr(env *custody.Envelope) error {
	h.t.Helper()
	_, err := h.client.Submit(context.Background(), h.dep, env)
	return err
}

func (h *harness) records() int64 {
	h.t.Helper()
	n, err := h.ledger.Records(context.Background(), h.dep)
	if err != nil {
		h.t.Fatalf("records: %v", err)
	}
	return n
}

func (h *harness) row(t *testing.T, seq int64) PendingRow {
	t.Helper()
	rows, err := h.outbox.rowsFrom(context.Background(), seq)
	if err != nil {
		t.Fatalf("outbox rows: %v", err)
	}
	for _, r := range rows {
		if r.Seq == seq {
			return r
		}
	}
	t.Fatalf("outbox row %d missing", seq)
	return PendingRow{}
}

// TestWitnessForgedAckRejected: an acknowledgement not minted by the
// pinned witness key is refused at the recording boundary — forged
// custody is not custody.
func TestWitnessForgedAckRejected(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	h.enqueue("exec-1", `{"receipt":1}`)
	if !h.drain() {
		t.Fatalf("drain failed: %v", h.sender.LastError())
	}
	row := h.row(t, 1)
	if row.Ack == nil {
		t.Fatalf("no ack recorded")
	}
	envHash, _ := row.Envelope.Hash()

	attacker, _ := evidence.GenerateSigner()
	forged, err := SignAck(attacker, row.Ack.SignerEpoch, row.Envelope, envHash)
	if err != nil {
		t.Fatalf("forge: %v", err)
	}
	if err := VerifyAck(forged, row.Envelope, h.ctrust); err == nil {
		t.Fatalf("forged acknowledgement under an unpinned key verified")
	}

	// A real ack rebound to different custody content fails the binding
	// check before signature verification.
	rebound := *row.Ack
	rebound.ExecutionID = "exec-other"
	if err := VerifyAck(&rebound, row.Envelope, h.ctrust); err == nil {
		t.Fatalf("rebound acknowledgement verified")
	}
}

// TestWitnessWrongKeyRejected: an envelope signed by a kernel key the
// witness does not pin is refused — trust resolves only from
// configuration, never from the record.
func TestWitnessWrongKeyRejected(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	stray, _ := evidence.GenerateSigner()
	env := h.craft("exec-1", 1, 0, "", custody.FamilyReceipt, stray, h.dep, []byte(`{"receipt":1}`))
	if err := h.submitErr(env); err == nil || !strings.Contains(err.Error(), "untrusted") && !strings.Contains(err.Error(), "pinned") {
		t.Fatalf("envelope under an unpinned kernel key was accepted: %v", err)
	}
	if n := h.records(); n != 0 {
		t.Fatalf("untrusted submission was custodied: %d records", n)
	}
}

// TestWitnessReplayRejected: re-presenting an already-custodied
// execution under a new index, or a prior-epoch record after the
// stream advanced, is refused.
func TestWitnessReplayRejected(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()

	if err := h.submitErr(h.craft("exec-1", 1, 0, "", custody.FamilyReceipt, h.kernel, h.dep, []byte(`{"r":1}`))); err != nil {
		t.Fatalf("first submit: %v", err)
	}
	// Execution replayed under a new index — dedupe refuses it.
	if err := h.submitErr(h.craft("exec-1", 2, 0, h.headPrev(), custody.FamilyReceipt, h.kernel, h.dep, []byte(`{"r":1}`))); err == nil || !strings.Contains(err.Error(), "already custodied") {
		t.Fatalf("execution replay under new index was accepted: %v", err)
	}
	// Epoch advance, then a prior-epoch record — refused.
	if err := h.submitErr(h.craft("exec-2", 2, 1, h.headPrev(), custody.FamilyReceipt, h.kernel, h.dep, []byte(`{"r":2}`))); err != nil {
		t.Fatalf("epoch-advance submit: %v", err)
	}
	if err := h.submitErr(h.craft("exec-3", 3, 0, h.headPrev(), custody.FamilyReceipt, h.kernel, h.dep, []byte(`{"r":3}`))); err == nil || !strings.Contains(err.Error(), "epoch") {
		t.Fatalf("prior-epoch replay was accepted: %v", err)
	}
}

// TestWitnessDuplicateIdempotent: re-offering the identical record
// returns the stored acknowledgement — recovery redelivery is the same
// custody, never a second one.
func TestWitnessDuplicateIdempotent(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	env := h.craft("exec-1", 1, 0, "", custody.FamilyReceipt, h.kernel, h.dep, []byte(`{"r":1}`))
	ack1, err := h.client.Submit(context.Background(), h.dep, env)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	ack2, err := h.client.Submit(context.Background(), h.dep, env)
	if err != nil {
		t.Fatalf("redelivery refused: %v", err)
	}
	if ack1.Signature != ack2.Signature || ack1.Seq != ack2.Seq {
		t.Fatalf("idempotent resend returned a different acknowledgement")
	}
	if n := h.records(); n != 1 {
		t.Fatalf("duplicate recorded twice: %d records", n)
	}
}

// TestWitnessSequenceGapDetected: a submission that does not extend
// the custody head by exactly one is refused — gaps make the chain
// unauditable.
func TestWitnessSequenceGapDetected(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	if err := h.submitErr(h.craft("exec-1", 1, 0, "", custody.FamilyReceipt, h.kernel, h.dep, []byte(`{"r":1}`))); err != nil {
		t.Fatalf("first submit: %v", err)
	}
	err := h.submitErr(h.craft("exec-2", 3, 0, "whatever", custody.FamilyReceipt, h.kernel, h.dep, []byte(`{"r":2}`)))
	if err == nil || !strings.Contains(err.Error(), "extend") && !strings.Contains(err.Error(), "sequence") {
		t.Fatalf("sequence gap accepted: %v", err)
	}
	if n := h.records(); n != 1 {
		t.Fatalf("gap submission was custodied: %d records", n)
	}
}

// TestWitnessForeignDeploymentRejected: an envelope naming another
// deployment is refused — the witness custodies exactly the
// deployment it is pinned to.
func TestWitnessForeignDeploymentRejected(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	env := h.craft("exec-1", 1, 0, "", custody.FamilyReceipt, h.kernel, "dep-beta", []byte(`{"r":1}`))
	if err := h.submitErr(env); err == nil || !strings.Contains(err.Error(), "deployment") {
		t.Fatalf("foreign deployment accepted: %v", err)
	}
	if n := h.records(); n != 0 {
		t.Fatalf("foreign submission was custodied: %d records", n)
	}
}

// TestContradictoryCheckpointRejected: a divergent record at a
// custodied index is equivocation — refused at the ledger, and a
// checkpoint head that disagrees with the outbox's own record
// escalates the sender rather than reconciling silently.
func TestContradictoryCheckpointRejected(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()

	if err := h.submitErr(h.craft("exec-1", 1, 0, "", custody.FamilyReceipt, h.kernel, h.dep, []byte(`{"r":1}`))); err != nil {
		t.Fatalf("first submit: %v", err)
	}
	err := h.submitErr(h.craft("exec-different", 1, 0, "", custody.FamilyReceipt, h.kernel, h.dep, []byte(`{"r":other}`)))
	if err == nil || !strings.Contains(err.Error(), "ontradict") {
		t.Fatalf("contradictory record at custodied index accepted: %v", err)
	}

	// Sender-side fork: the outbox holds record H1 at seq 1 while the
	// witness (here a second deployment's ledger replayed at the same
	// index) reports a head custoding H1' — escalated, never merged.
	h2 := newHarness(t, true)
	defer h2.cancel()
	h2.enqueue("exec-x", `{"fork":true}`) // outbox seq 1, never submitted
	if err := h2.submitErr(h2.craft("exec-y", 1, 0, "", custody.FamilyReceipt, h2.kernel, h2.dep, []byte(`{"fork":false}`))); err != nil {
		t.Fatalf("fork submit: %v", err)
	}
	if h2.drain() {
		t.Fatalf("drain reconciled a forked custody head")
	}
	if !strings.Contains(h2.sender.LastError(), "ontradictor") {
		t.Fatalf("fork not escalated as contradiction: %v", h2.sender.LastError())
	}
	if n, _ := h2.outbox.Undelivered(context.Background()); n != 1 {
		t.Fatalf("fork silently recorded custody: %d undelivered", n)
	}
}

// TestCustodyOutageNoTerminalSuccess: witness downtime cannot produce
// verified custody — obligations queue durably, carry no acks, and the
// custody health gate reports degraded.
func TestCustodyOutageNoTerminalSuccess(t *testing.T) {
	h := newHarness(t, false) // witness never starts
	h.enqueue("exec-1", `{"receipt":1}`)
	h.enqueue("exec-2", `{"receipt":2}`)

	if h.drain() {
		t.Fatalf("drain succeeded with the witness down")
	}
	if n, _ := h.outbox.Undelivered(context.Background()); n != 2 {
		t.Fatalf("outage lost custody obligations: %d undelivered", n)
	}
	for _, seq := range []int64{1, 2} {
		if h.row(t, seq).Ack != nil {
			t.Fatalf("seq %d shows custody without a witness — outage minted a success", seq)
		}
	}
	if h.sender.CustodyHealthy(context.Background()) {
		t.Fatalf("custody reported healthy during a witness outage")
	}
}

// TestCustodyReconnectReconciles: on reconnect the durable backlog
// drains with independently verified acknowledgements — nothing is
// re-enqueued or re-executed.
func TestCustodyReconnectReconciles(t *testing.T) {
	h := newHarness(t, false)
	h.enqueue("exec-1", `{"receipt":1}`)
	h.enqueue("exec-2", `{"receipt":2}`)
	if h.drain() {
		t.Fatalf("drain succeeded with the witness down")
	}
	h.serve()
	defer h.cancel()
	if !h.drain() {
		t.Fatalf("reconnect drain failed: %v", h.sender.LastError())
	}
	if n, _ := h.outbox.Undelivered(context.Background()); n != 0 {
		t.Fatalf("reconnect left backlog: %d", n)
	}
	for _, seq := range []int64{1, 2} {
		row := h.row(t, seq)
		if row.Ack == nil {
			t.Fatalf("seq %d delivered without recorded custody", seq)
		}
		if err := VerifyAck(row.Ack, row.Envelope, h.ctrust); err != nil {
			t.Fatalf("seq %d ack does not verify at the boundary: %v", seq, err)
		}
	}
	if !h.sender.CustodyHealthy(context.Background()) {
		t.Fatalf("custody unhealthy after successful reconciliation")
	}
}

// TestColdRestoreReconciles: a kernel restart keeps every queued
// obligation — a reopened outbox continues draining — and a witness
// restored from an older checkpoint is re-custodied idempotently.
func TestColdRestoreReconciles(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	h.enqueue("exec-1", `{"receipt":1}`)
	h.enqueue("exec-2", `{"receipt":2}`)
	if !h.drain() {
		t.Fatalf("initial drain: %v", h.sender.LastError())
	}
	ack1 := h.row(t, 1).Ack.Signature
	ack2 := h.row(t, 2).Ack.Signature

	// Kernel-side cold restore: close the outbox, reopen on the same
	// path, build a fresh sender — queued+delivered rows persist.
	h.outbox.Close()
	outbox, err := OpenOutbox(filepath.Join(h.dir, "outbox.db"))
	if err != nil {
		t.Fatalf("reopen outbox: %v", err)
	}
	h.outbox = outbox
	h.sender = NewSender(h.client, h.outbox, h.dep, h.ctrust, nil)
	h.enqueue("exec-3", `{"receipt":3}`)
	if !h.drain() {
		t.Fatalf("post-restore drain: %v", h.sender.LastError())
	}
	if n := h.records(); n != 3 {
		t.Fatalf("witness lost records across kernel restore: %d", n)
	}
	if got := h.row(t, 1).Ack.Signature; got != ack1 {
		t.Fatalf("acknowledged row was re-executed on restore")
	}
	if got := h.row(t, 2).Ack.Signature; got != ack2 {
		t.Fatalf("acknowledged row was re-executed on restore")
	}
	if h.row(t, 3).Ack == nil {
		t.Fatalf("post-restore enqueue never custodied")
	}

	// Witness-side cold restore: a fresh ledger for the same
	// deployment and key sees head 0 — the outbox re-delivers every
	// row; the records re-custody with identical acks (deterministic
	// signatures over identical custody positions).
	ledger2, err := OpenLedger(filepath.Join(h.dir, "restored", "witness.db"))
	if err != nil {
		t.Fatalf("restored ledger: %v", err)
	}
	svc2 := NewService(ledger2, h.wsigner, h.dep, h.ktrust, nil)
	sockDir2, err := os.MkdirTemp("/tmp", "ws")
	if err != nil {
		t.Fatalf("socket dir: %v", err)
	}
	defer os.RemoveAll(sockDir2)
	sock2 := filepath.Join(sockDir2, "w.sock")
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	go func() { _ = svc2.Serve(ctx2, sock2) }()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(sock2); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	h.client = NewClient(sock2)
	h.sender = NewSender(h.client, h.outbox, h.dep, h.ctrust, nil)
	if !h.drain() {
		t.Fatalf("witness-restore drain: %v", h.sender.LastError())
	}
	if n, _ := ledger2.Records(context.Background(), h.dep); n != 3 {
		t.Fatalf("witness restore lost custody: %d records", n)
	}
	if got := h.row(t, 1).Ack.Signature; got != ack1 {
		t.Fatalf("witness restore rewrote recorded custody")
	}
}

// TestWitnessKeyRotation: a rotated custodian key verifies new
// acknowledgements while records under the retired key remain valid
// only below the rotation point — rotation is authorized by the
// incumbent, never claimed by the successor.
func TestWitnessKeyRotation(t *testing.T) {
	h := newHarness(t, false)
	wsigner2, _ := evidence.GenerateSigner()
	// The kernel-side trust set carries the incumbent (valid through
	// index 2) and the successor (from index 3), authorized by the
	// incumbent's rotation signature — mirroring what the operator's
	// trust file declares.
	h.ctrust = custody.NewTrustSet(custody.TrustedKey{
		Role: custody.RoleCustodian, KeyID: h.wsigner.Fingerprint(),
		PublicKey: h.wsigner.PublicKey(), DeploymentID: h.dep,
		ValidFromIndex: 0, ValidUntilIndex: 2,
	})
	next := custody.TrustedKey{
		Role: custody.RoleCustodian, KeyID: wsigner2.Fingerprint(),
		PublicKey: wsigner2.PublicKey(), DeploymentID: h.dep,
		ValidFromIndex: 3,
	}
	auth, err := custody.SignKeyRotation(h.wsigner, next)
	if err != nil {
		t.Fatalf("rotation auth: %v", err)
	}
	if err := h.ctrust.AddAuthorized(h.wsigner.Fingerprint(), next, auth); err != nil {
		t.Fatalf("authorized rotation refused: %v", err)
	}
	// The sender captured the original trust pointer at construction —
	// rebuild it against the rotation-carrying set (a restart-time
	// trust reload in production terms).
	h.sender = NewSender(h.client, h.outbox, h.dep, h.ctrust, nil)
	// An unauthorized successor must not enter the set.
	unauthorized := custody.TrustedKey{
		Role: custody.RoleCustodian, KeyID: "deadbeef",
		PublicKey: wsigner2.PublicKey(), DeploymentID: h.dep, ValidFromIndex: 5,
	}
	if err := h.ctrust.AddAuthorized("deadbeef", unauthorized, auth); err == nil {
		t.Fatalf("unauthorized rotation joined the trust set")
	}

	h.serve()
	defer h.cancel()
	h.enqueue("exec-1", `{"receipt":1}`)
	h.enqueue("exec-2", `{"receipt":2}`)
	if !h.drain() {
		t.Fatalf("pre-rotation drain: %v", h.sender.LastError())
	}
	if got := h.row(t, 1).Ack.WitnessFP; got != h.wsigner.Fingerprint() {
		t.Fatalf("pre-rotation ack under unexpected key %s", got)
	}

	if _, err := h.service.RotateSigner(context.Background(), wsigner2); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	h.enqueue("exec-3", `{"receipt":3}`)
	if !h.drain() {
		t.Fatalf("post-rotation drain: %v", h.sender.LastError())
	}
	row3 := h.row(t, 3)
	if row3.Ack.WitnessFP != wsigner2.Fingerprint() {
		t.Fatalf("post-rotation ack under retired key %s", row3.Ack.WitnessFP)
	}
	if row3.Ack.SignerEpoch != 1 {
		t.Fatalf("post-rotation ack carries epoch %d, want 1", row3.Ack.SignerEpoch)
	}
	if err := VerifyAck(row3.Ack, row3.Envelope, h.ctrust); err != nil {
		t.Fatalf("post-rotation ack does not verify: %v", err)
	}
	// Historical records still verify under the retired key — inside
	// its window.
	for _, seq := range []int64{1, 2} {
		row := h.row(t, seq)
		if err := VerifyAck(row.Ack, row.Envelope, h.ctrust); err != nil {
			t.Fatalf("pre-rotation ack %d lost validity: %v", seq, err)
		}
	}
	// The retired key cannot mint acks for post-rotation indexes.
	envHash, _ := row3.Envelope.Hash()
	forged, _ := SignAck(h.wsigner, 0, row3.Envelope, envHash)
	if err := VerifyAck(forged, row3.Envelope, h.ctrust); err == nil {
		t.Fatalf("retired key verified a post-rotation acknowledgement")
	}
}

// TestWitnessCrossFamilyConfusion: family is literal in the signature
// domain — a receipt-family signature never verifies as
// sandbox_archive, and a correctly signed non-receipt envelope is
// refused by the receipt witness's family allowlist before the
// signature is even checked.
func TestWitnessCrossFamilyConfusion(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()

	// Contract layer: re-label the family post-signing.
	env := h.craft("exec-1", 1, 0, "", custody.FamilyReceipt, h.kernel, h.dep, []byte(`{"r":1}`))
	relabeled := *env
	relabeled.Family = custody.FamilySandboxArchive
	relabeled.Sequence.Domain = custody.FamilySandboxArchive
	if err := custody.Verify(&relabeled, custody.VerifyOptions{
		DeploymentID: h.dep, Trust: h.ktrust,
	}); err == nil {
		t.Fatalf("receipt signature verified as sandbox_archive")
	}

	// Reverse direction: archive-domain signature relabeled receipt.
	arc := h.craft("job-1", 1, 0, "", custody.FamilySandboxArchive, h.kernel, h.dep, []byte(`{"archive":1}`))
	relabeled2 := *arc
	relabeled2.Family = custody.FamilyReceipt
	relabeled2.Sequence.Domain = custody.FamilyReceipt
	if err := custody.Verify(&relabeled2, custody.VerifyOptions{
		DeploymentID: h.dep, Trust: h.ktrust,
	}); err == nil {
		t.Fatalf("sandbox_archive signature verified as receipt")
	}

	// Protocol layer: a legitimately signed archive-family envelope is
	// refused by the receipt witness — the families do not share a
	// sequence domain even when the signature is valid.
	err := h.submitErr(h.craft("job-1", 1, 0, "", custody.FamilySandboxArchive, h.kernel, h.dep, []byte(`{"archive":1}`)))
	if err == nil || !strings.Contains(err.Error(), "family") {
		t.Fatalf("archive-family envelope was custodied by the receipt witness: %v", err)
	}
	if n := h.records(); n != 0 {
		t.Fatalf("cross-family submission was custodied: %d records", n)
	}
}

// TestWitnessTLSRoundTrip exercises the separate-host transport:
// mutually authenticated TLS where both peers present their custody
// keys as certificates and each pins the other's fingerprint. A client
// presenting any other key is refused before protocol bytes flow.
func TestWitnessTLSRoundTrip(t *testing.T) {
	h := newHarness(t, false)
	srvTLS, err := ServerTLSConfig(h.wsigner, h.kernel.Fingerprint())
	if err != nil {
		t.Fatalf("server tls: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = h.service.ServeTLS(ctx, addr, srvTLS) }()

	cliTLS, err := ClientTLSConfig(h.kernel, h.wsigner.Fingerprint())
	if err != nil {
		t.Fatalf("client tls: %v", err)
	}
	client := NewTLSClient(addr, cliTLS)
	env := h.craft("exec-1", 1, 0, "", custody.FamilyReceipt, h.kernel, h.dep, []byte(`{"r":1}`))
	deadline := time.Now().Add(5 * time.Second)
	var ack *Ack
	for {
		ack, err = client.Submit(context.Background(), h.dep, env)
		if err == nil || !strings.Contains(err.Error(), "dial") && !strings.Contains(err.Error(), "connection refused") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("tls submit never succeeded: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("tls submit: %v", err)
	}
	if err := VerifyAck(ack, env, h.ctrust); err != nil {
		t.Fatalf("tls ack unverifiable: %v", err)
	}

	// A client pinning a different witness key, or presenting an
	// unpinned client key, is refused at the handshake — not the
	// protocol layer.
	stray, _ := evidence.GenerateSigner()
	badClient, _ := ClientTLSConfig(stray, h.wsigner.Fingerprint())
	bad := NewTLSClient(addr, badClient)
	bad.Timeout = 2 * time.Second
	if _, err := bad.Submit(context.Background(), h.dep, env); err == nil {
		t.Fatalf("mTLS accepted an unpinned client key")
	}
}

// TestWitnessCheckpointForgedRejected ensures a checkpoint response
// signed by a non-witness key cannot realign the sender.
func TestWitnessCheckpointForgedRejected(t *testing.T) {
	h := newHarness(t, false)
	attacker, _ := evidence.GenerateSigner()
	head := &CheckpointHead{Seq: 99, Hash: "deadbeef", SignerEpoch: 0}
	if _, err := SignCheckpoint(attacker, h.dep, head); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := VerifyCheckpoint(head, h.dep, h.ctrust); err == nil {
		t.Fatalf("forged checkpoint accepted")
	}
	// A real-key checkpoint for a different deployment is equally
	// refused — deployment is inside the signed fields.
	head2, _ := SignCheckpoint(h.wsigner, "dep-beta", &CheckpointHead{Seq: 1, Hash: "x"})
	if err := VerifyCheckpoint(head2, h.dep, h.ctrust); err == nil {
		t.Fatalf("foreign-deployment checkpoint accepted")
	}
}

// sanity: the framed wire format is exercised end-to-end by every test
// through h.client/h.service — this documents the encoding contract.
func TestFrameRoundTrip(t *testing.T) {
	c1, c2 := net.Pipe()
	go func() {
		defer c1.Close()
		_ = writeFrame(c1, []byte(`{"op":"status"}`))
	}()
	got, err := readFrame(c2)
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	var req map[string]string
	if err := json.Unmarshal(got, &req); err != nil || req["op"] != "status" {
		t.Fatalf("frame payload corrupted: %v %q", err, got)
	}
	// Oversized frames refuse before allocation.
	var hdr [4]byte
	c3, c4 := net.Pipe()
	go func() {
		defer c3.Close()
		hdr[3] = 0x7f
		_, _ = c3.Write(append(hdr[:], make([]byte, 8)...))
	}()
	if _, err := readFrame(c4); err == nil {
		t.Fatalf("out-of-bounds frame accepted")
	}
	_ = base64.StdEncoding
	_ = fmt.Sprint
}
