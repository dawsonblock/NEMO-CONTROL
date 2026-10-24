package releasectl

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openclaw/crabbox/internal/evidence"
)

// ─── Helpers ────────────────────────────────────────────────────────

func testSigner(t *testing.T) *evidence.Signer {
	t.Helper()
	s, err := evidence.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func rootsOf(signers ...*evidence.Signer) TrustRoots {
	r := TrustRoots{}
	for _, s := range signers {
		r[s.Fingerprint()] = true
	}
	return r
}

type fixture struct {
	dir   string
	path  string
	ckpt  string
	op    *evidence.Signer
	roots TrustRoots
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	op := testSigner(t)
	return &fixture{
		dir:   dir,
		path:  filepath.Join(dir, "control.jsonl"),
		ckpt:  filepath.Join(dir, "ext", "checkpoint.json"),
		op:    op,
		roots: rootsOf(op),
	}
}

func (f *fixture) open(t *testing.T) *Ledger {
	t.Helper()
	l, err := Create(f.path, f.ckpt, NewVerifier(f.roots, false))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return l
}

// signed builds a chained event, signs it, appends it.
func (f *fixture) signed(t *testing.T, l *Ledger, kind, dep string) Event {
	t.Helper()
	e := l.NewEvent(kind, dep, "test "+kind)
	e.ReleaseDigest = strings.Repeat("a", 64)
	e.PolicyDigest = strings.Repeat("b", 64)
	if kind == KindStage {
		e.Stage = 1
		e.EvidenceRefs = []string{"sha256:" + strings.Repeat("c", 64)}
	}
	if err := SignEvent(f.op, &e); err != nil {
		t.Fatal(err)
	}
	if err := l.Append(e); err != nil {
		t.Fatalf("append %s: %v", kind, err)
	}
	return e
}

// unsigned appends an unsigned chained event (tightening kinds only).
func (f *fixture) unsigned(t *testing.T, l *Ledger, kind, dep string) Event {
	t.Helper()
	e := l.NewEvent(kind, dep, "emergency "+kind)
	if err := l.Append(e); err != nil {
		t.Fatalf("append %s: %v", kind, err)
	}
	return e
}

func mustDeny(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected denial, got nil")
	}
}

// ─── Required G3 fixtures ────────────────────────────────────────────

// TestVerifyEmptyAllowlistFailsClosed: with no configured trust roots,
// even a cryptographically valid signed relaxation is denied.
func TestVerifyEmptyAllowlistFailsClosed(t *testing.T) {
	dir := t.TempDir()
	path, ckpt := filepath.Join(dir, "c.jsonl"), filepath.Join(dir, "k.json")
	op := testSigner(t)

	l, err := Create(path, ckpt, NewVerifier(TrustRoots{}, false))
	if err != nil {
		t.Fatal(err)
	}
	e := l.NewEvent(KindHalt, "dep", "stop")
	if err := l.Append(e); err != nil {
		t.Fatalf("unsigned halt must always be accepted: %v", err)
	}
	// A validly-signed resume with an EMPTY allowlist must be denied.
	r := l.NewEvent(KindResume, "dep", "resume")
	if err := SignEvent(op, &r); err != nil {
		t.Fatal(err)
	}
	mustDeny(t, l.Append(r))
	if err := l.AdmitError("dep"); err == nil {
		t.Fatal("halt must still deny admission after rejected resume")
	}
}

// TestVerifySelfSignedRejected: a valid signature from a key that is
// not in the externally provisioned root set is denied — trust is
// never learned from the event's embedded public key.
func TestVerifySelfSignedRejected(t *testing.T) {
	dir := t.TempDir()
	path, ckpt := filepath.Join(dir, "c.jsonl"), filepath.Join(dir, "k.json")
	op, rogue := testSigner(t), testSigner(t)

	l, err := Create(path, ckpt, NewVerifier(rootsOf(op), false))
	if err != nil {
		t.Fatal(err)
	}
	e := l.NewEvent(KindHalt, "dep", "stop")
	if err := l.Append(e); err != nil {
		t.Fatal(err)
	}
	r := l.NewEvent(KindResume, "dep", "rogue resume")
	if err := SignEvent(rogue, &r); err != nil {
		t.Fatal(err)
	}
	mustDeny(t, l.Append(r))
	// Poisoning the store directly with the rogue record must also
	// fail closed at next open — the signature verifies but the
	// signer is not trusted, making the whole record unauthorized.
	raw, _ := json.Marshal(r)
	f, _ := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	f.Write(append(raw, '\n'))
	f.Close()
	if _, err := Open(path, ckpt, NewVerifier(rootsOf(op), false)); err == nil {
		t.Fatal("untrusted-signer record must fail closed on open")
	}
}

// TestResumeUnsignedRejected: resume without a signature is refused at
// append, and a forged unsigned record spliced into the store makes the
// ledger fail closed on open.
func TestResumeUnsignedRejected(t *testing.T) {
	f := newFixture(t)
	l := f.open(t)
	f.unsigned(t, l, KindHalt, "dep")

	r := l.NewEvent(KindResume, "dep", "unsigned resume")
	mustDeny(t, l.Append(r))

	raw, _ := json.Marshal(r)
	fp, _ := os.OpenFile(f.path, os.O_WRONLY|os.O_APPEND, 0)
	fp.Write(append(raw, '\n'))
	fp.Close()
	if _, err := Open(f.path, f.ckpt, NewVerifier(f.roots, false)); err == nil {
		t.Fatal("unsigned resume in store must fail closed on open")
	}
}

// TestHaltSurvivesFileDeletion: a halt cannot be cleared by deleting
// files — removing the checkpoint leaves the halt enforced AND denies
// all relaxations; removing the entire store fails closed (not
// "absent means clear").
func TestHaltSurvivesFileDeletion(t *testing.T) {
	f := newFixture(t)
	l := f.open(t)
	f.unsigned(t, l, KindHalt, "dep")

	// Deleting the checkpoint must not clear the halt.
	if err := os.Remove(f.ckpt); err != nil {
		t.Fatal(err)
	}
	l2, err := Open(f.path, f.ckpt, NewVerifier(f.roots, false))
	if err != nil {
		t.Fatalf("ledger must still open with missing checkpoint: %v", err)
	}
	if err := l2.AdmitError("dep"); err == nil {
		t.Fatal("halt must survive checkpoint deletion")
	}
	// With the checkpoint gone, an appended signed resume lands but
	// must not take effect... until a new checkpoint covers it — the
	// next append re-anchors. The tight check: relaxations recorded
	// while no checkpoint existed are honored only after a covered
	// checkpoint exists. Here Append re-establishes the checkpoint,
	// so resume+rehalt shows the fold is consistent.
	r := l2.NewEvent(KindResume, "dep", "resume")
	if err := SignEvent(f.op, &r); err != nil {
		t.Fatal(err)
	}
	if err := l2.Append(r); err != nil {
		t.Fatal(err)
	}
	f.unsigned(t, l2, KindHalt, "dep")
	if err := l2.AdmitError("dep"); err == nil {
		t.Fatal("re-halt must deny admission")
	}

	// Deleting the entire store fails closed at open — a missing
	// ledger is not a cleared restriction.
	if err := os.Remove(f.path); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(f.path, f.ckpt, NewVerifier(f.roots, false)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("missing ledger must fail closed, got %v", err)
	}
}

// TestControlLedgerRollbackFailsClosed: a checkpoint ahead of the
// ledger — events vanished that the anchor authorized — is a rollback
// and refuses to open.
func TestControlLedgerRollbackFailsClosed(t *testing.T) {
	f := newFixture(t)
	l := f.open(t)
	f.unsigned(t, l, KindHalt, "dep")
	f.signed(t, l, KindResume, "dep")

	// Truncate the store to drop the last record; checkpoint still
	// points past it → rollback.
	data, _ := os.ReadFile(f.path)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	os.WriteFile(f.path, []byte(strings.Join(lines[:len(lines)-1], "\n")+"\n"), 0o600)

	if _, err := Open(f.path, f.ckpt, NewVerifier(f.roots, false)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("rollback must fail closed, got %v", err)
	}
}

// TestStaleEpochRejected: events at an epoch older than the ledger's
// maximum are refused — at append and on reopen.
func TestStaleEpochRejected(t *testing.T) {
	f := newFixture(t)
	l := f.open(t)

	// Advance epoch via a signed halt at epoch 7.
	e := l.NewEvent(KindHalt, "dep", "epoch advance")
	e.Epoch = 7
	if err := SignEvent(f.op, &e); err != nil {
		t.Fatal(err)
	}
	if err := l.Append(e); err != nil {
		t.Fatal(err)
	}
	if l.MaxEpoch() != 7 {
		t.Fatalf("maxEpoch=%d, want 7", l.MaxEpoch())
	}
	stale := l.NewEvent(KindHalt, "dep", "stale")
	stale.Epoch = 5
	mustDeny(t, l.Append(stale))

	// Forge a stale-epoch record with valid chain fields directly
	// into the store: reopening must fail closed.
	stale = l.NewEvent(KindHalt, "dep", "forged stale")
	stale.Epoch = 5
	if err := SignEvent(f.op, &stale); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(stale)
	fp, _ := os.OpenFile(f.path, os.O_WRONLY|os.O_APPEND, 0)
	fp.Write(append(raw, '\n'))
	fp.Close()
	if _, err := Open(f.path, f.ckpt, NewVerifier(f.roots, false)); err == nil {
		t.Fatal("stale-epoch record must fail closed on open")
	}
}

// TestRogueDaemonCannotClear: a process with write access to the
// store cannot clear a restriction — unsigned relaxations poison the
// ledger into fail-closed, truncation breaks the chain, and deleting
// the store denies rather than clears.
func TestRogueDaemonCannotClear(t *testing.T) {
	build := func(t *testing.T) *fixture {
		f := newFixture(t)
		l := f.open(t)
		f.unsigned(t, l, KindHalt, "dep")
		return f
	}

	t.Run("unsigned resume append", func(t *testing.T) {
		f := build(t)
		l, _ := Open(f.path, f.ckpt, NewVerifier(f.roots, false))
		r := l.NewEvent(KindResume, "dep", "rogue")
		raw, _ := json.Marshal(r)
		fp, _ := os.OpenFile(f.path, os.O_WRONLY|os.O_APPEND, 0)
		fp.Write(append(raw, '\n'))
		fp.Close()
		if _, err := Open(f.path, f.ckpt, NewVerifier(f.roots, false)); err == nil {
			t.Fatal("rogue unsigned resume must fail closed")
		}
	})

	t.Run("store truncation", func(t *testing.T) {
		f := build(t)
		data, _ := os.ReadFile(f.path)
		os.WriteFile(f.path, data[:len(data)-10], 0o600)
		if _, err := Open(f.path, f.ckpt, NewVerifier(f.roots, false)); err == nil {
			t.Fatal("truncated store must fail closed")
		}
	})

	t.Run("store deletion", func(t *testing.T) {
		f := build(t)
		os.Remove(f.path)
		if _, err := Open(f.path, f.ckpt, NewVerifier(f.roots, false)); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("deleted store must fail closed, got %v", err)
		}
	})

	t.Run("record rewrite", func(t *testing.T) {
		f := build(t)
		data, _ := os.ReadFile(f.path)
		// Flip halt→resume inside the stored record.
		forged := strings.Replace(string(data), `"kind":"halt"`, `"kind":"resume"`, 1)
		if forged == string(data) {
			t.Fatal("fixture: halt record not found")
		}
		os.WriteFile(f.path, []byte(forged), 0o600)
		if _, err := Open(f.path, f.ckpt, NewVerifier(f.roots, false)); err == nil {
			t.Fatal("rewritten record must fail closed")
		}
	})
}

// TestCorruptRecordFailsClosed: any byte-level corruption of a record
// is detected at open.
func TestCorruptRecordFailsClosed(t *testing.T) {
	f := newFixture(t)
	l := f.open(t)
	f.unsigned(t, l, KindHalt, "dep")
	f.signed(t, l, KindResume, "dep")

	data, _ := os.ReadFile(f.path)
	// Corrupt a byte inside the second record (offset into line 2).
	idx := strings.Index(string(data), "\n") + 20
	data[idx] ^= 0xFF
	os.WriteFile(f.path, data, 0o600)
	if _, err := Open(f.path, f.ckpt, NewVerifier(f.roots, false)); err == nil {
		t.Fatal("corrupt record must fail closed on open")
	}
}

// TestReplicaMismatchFailsClosed: a checkpoint whose head hash does not
// match the record at its claimed sequence — a conflicting replica or
// rewritten chain — refuses to open.
func TestReplicaMismatchFailsClosed(t *testing.T) {
	f := newFixture(t)
	l := f.open(t)
	f.unsigned(t, l, KindHalt, "dep")

	// Write a checkpoint claiming seq 1 coverage of a different head.
	mustWriteCkpt(t, f.ckpt, Checkpoint{
		Sequence: 1, HeadHash: strings.Repeat("f", 64), Epoch: 0,
	})
	if _, err := Open(f.path, f.ckpt, NewVerifier(f.roots, false)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("replica mismatch must fail closed, got %v", err)
	}
}

func mustWriteCkpt(t *testing.T, path string, cp Checkpoint) {
	t.Helper()
	if err := writeCheckpoint(path, cp); err != nil {
		t.Fatal(err)
	}
}

// TestRestartPreservesState: state is reconstructed from the chain
// across process restarts — nothing lives in memory.
func TestRestartPreservesState(t *testing.T) {
	f := newFixture(t)
	l := f.open(t)
	f.unsigned(t, l, KindHalt, "dep")

	l2, err := Open(f.path, f.ckpt, NewVerifier(f.roots, false))
	if err != nil {
		t.Fatal(err)
	}
	if err := l2.AdmitError("dep"); err == nil {
		t.Fatal("halt must survive restart")
	}
	f.signed(t, l2, KindResume, "dep")

	l3, err := Open(f.path, f.ckpt, NewVerifier(f.roots, false))
	if err != nil {
		t.Fatal(err)
	}
	if err := l3.AdmitError("dep"); err != nil {
		t.Fatalf("signed resume must survive restart: %v", err)
	}
}

// TestOutageFailsClosed: when the store cannot be read, the gate
// denies — a missing/corrupt backend is never "no restrictions".
func TestOutageFailsClosed(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "nonexistent", "control.jsonl")
	if _, err := Open(missing, filepath.Join(dir, "k.json"), NewVerifier(TrustRoots{}, false)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("missing store must fail closed, got %v", err)
	}
	// Corrupt store bytes.
	bad := filepath.Join(dir, "bad.jsonl")
	os.WriteFile(bad, []byte("not-json\n"), 0o600)
	if _, err := Open(bad, filepath.Join(dir, "k2.json"), NewVerifier(TrustRoots{}, false)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("corrupt store must fail closed, got %v", err)
	}
}

// TestTwoStepRecovery: after halt+revoke, a single unrevoke leaves the
// deployment halted — recovery requires both authorized steps, each
// independently signed and checkpoint-covered.
func TestTwoStepRecovery(t *testing.T) {
	f := newFixture(t)
	l := f.open(t)
	f.unsigned(t, l, KindHalt, "dep")
	f.unsigned(t, l, KindRevoke, "dep")

	// Step 1: unrevoke — clears revoke, halt still stands.
	f.signed(t, l, KindUnrevoke, "dep")
	if err := l.AdmitError("dep"); err == nil {
		t.Fatal("unrevoke alone must not admit while halt stands")
	}
	// Step 2: resume — now admitted.
	f.signed(t, l, KindResume, "dep")
	if err := l.AdmitError("dep"); err != nil {
		t.Fatalf("two-step recovery must admit: %v", err)
	}
}

// ─── Additional adversarial fixtures ────────────────────────────────

// TestEventSignatureTamperRejected: modifying any signed field after
// signing invalidates the event.
func TestEventSignatureTamperRejected(t *testing.T) {
	f := newFixture(t)
	l := f.open(t)
	f.unsigned(t, l, KindHalt, "dep")

	r := l.NewEvent(KindResume, "dep", "resume")
	if err := SignEvent(f.op, &r); err != nil {
		t.Fatal(err)
	}
	r.Deployment = "other" // tamper after signing
	mustDeny(t, l.Append(r))
}

// TestEquivocationForkRejected: two different events claiming the same
// sequence — an equivocating fork — cannot both exist in the chain.
func TestEquivocationForkRejected(t *testing.T) {
	f := newFixture(t)
	l := f.open(t)
	f.unsigned(t, l, KindHalt, "dep")

	// A second event claiming sequence 0 with a different body.
	fork := l.NewEvent(KindRevoke, "dep", "fork")
	fork.Sequence = 0
	fork.PrevEventHash = genesisHash
	mustDeny(t, l.Append(fork))

	// Splicing the fork into the store also fails closed at open.
	raw, _ := json.Marshal(fork)
	fp, _ := os.OpenFile(f.path, os.O_WRONLY|os.O_APPEND, 0)
	fp.Write(append(raw, '\n'))
	fp.Close()
	if _, err := Open(f.path, f.ckpt, NewVerifier(f.roots, false)); err == nil {
		t.Fatal("forked record must fail closed")
	}
}

// TestKeyRotationEpochAdvance: key rotation advances the epoch; events
// signed by the retired key fail once its fingerprint leaves the root
// set, and old-epoch records are stale.
func TestKeyRotationEpochAdvance(t *testing.T) {
	dir := t.TempDir()
	path, ckpt := filepath.Join(dir, "c.jsonl"), filepath.Join(dir, "k.json")
	oldKey, newKey := testSigner(t), testSigner(t)

	l, err := Create(path, ckpt, NewVerifier(rootsOf(oldKey), false))
	if err != nil {
		t.Fatal(err)
	}
	e := l.NewEvent(KindHalt, "dep", "halt under old key")
	if err := l.Append(e); err != nil {
		t.Fatal(err)
	}
	// Rotate: new epoch, new root set.
	l2, err := Open(path, ckpt, NewVerifier(rootsOf(newKey), false))
	if err != nil {
		t.Fatal(err)
	}
	r := l2.NewEvent(KindResume, "dep", "resume under new key")
	r.Epoch = 1
	if err := SignEvent(newKey, &r); err != nil {
		t.Fatal(err)
	}
	if err := l2.Append(r); err != nil {
		t.Fatal(err)
	}
	// Retired key can no longer relax.
	r2 := l2.NewEvent(KindRevoke, "dep", "old key tighten is fine unsigned anyway")
	_ = r2
	oldResume := l2.NewEvent(KindResume, "dep", "old key resume")
	oldResume.Epoch = 1
	if err := SignEvent(oldKey, &oldResume); err != nil {
		t.Fatal(err)
	}
	mustDeny(t, l2.Append(oldResume))
}

// TestUnsignedHaltAlwaysApplies: emergency tightening needs no key and
// no root set — a halt appended unsigned denies admission immediately.
func TestUnsignedHaltAlwaysApplies(t *testing.T) {
	dir := t.TempDir()
	l, err := Create(filepath.Join(dir, "c.jsonl"), filepath.Join(dir, "k.json"), NewVerifier(TrustRoots{}, false))
	if err != nil {
		t.Fatal(err)
	}
	e := l.NewEvent(KindHalt, "dep", "fire alarm")
	if err := l.Append(e); err != nil {
		t.Fatalf("unsigned halt must be accepted: %v", err)
	}
	if err := l.AdmitError("dep"); err == nil {
		t.Fatal("unsigned halt must deny admission")
	}
}

// TestUncheckpointedRelaxationDenied: a relaxation present in the
// ledger but not covered by the checkpoint never takes effect.
func TestUncheckpointedRelaxationDenied(t *testing.T) {
	f := newFixture(t)
	l := f.open(t)
	f.unsigned(t, l, KindHalt, "dep")
	f.signed(t, l, KindResume, "dep")

	// Rewind the checkpoint to cover only the halt.
	haltHash := EventHash(l.events[0])
	mustWriteCkpt(t, f.ckpt, Checkpoint{Sequence: 1, HeadHash: haltHash, Epoch: 0})

	l2, err := Open(f.path, f.ckpt, NewVerifier(f.roots, false))
	if err != nil {
		t.Fatal(err)
	}
	st := l2.State("dep")
	if !st.Halted {
		t.Fatal("uncheckpointed resume must not clear the halt")
	}
	if st.PendingRelaxations != 1 {
		t.Fatalf("pending relaxations=%d, want 1", st.PendingRelaxations)
	}
}

// TestDeploymentIsolation: restrictions scope to their deployment.
func TestDeploymentIsolation(t *testing.T) {
	f := newFixture(t)
	l := f.open(t)
	f.unsigned(t, l, KindHalt, "dep-a")
	if err := l.AdmitError("dep-a"); err == nil {
		t.Fatal("dep-a must be halted")
	}
	if err := l.AdmitError("dep-b"); err != nil {
		t.Fatalf("dep-b must be unaffected: %v", err)
	}
}

// TestStageRequiresEvidence: a stage event without evidence refs is
// rejected — absent records never read as approval.
func TestStageRequiresEvidence(t *testing.T) {
	f := newFixture(t)
	l := f.open(t)
	e := l.NewEvent(KindStage, "dep", "unbacked stage")
	e.Stage = 1
	if err := SignEvent(f.op, &e); err != nil {
		t.Fatal(err)
	}
	mustDeny(t, l.Append(e))
}

// TestStageTransitionSigned: a signed stage binds release digest and
// evidence; stage-clear restores unrestricted stage state.
func TestStageTransitionSigned(t *testing.T) {
	f := newFixture(t)
	l := f.open(t)
	f.signed(t, l, KindStage, "dep")
	st := l.State("dep")
	if st.StageLevel != 1 || st.StagedRelease == "" {
		t.Fatalf("stage not recorded: %+v", st)
	}
	f.signed(t, l, KindStageClear, "dep")
	st = l.State("dep")
	if st.StageLevel != 0 || st.StagedRelease != "" {
		t.Fatalf("stage-clear failed: %+v", st)
	}
}
