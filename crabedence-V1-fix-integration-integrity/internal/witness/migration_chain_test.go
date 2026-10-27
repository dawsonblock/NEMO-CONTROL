package witness

// RC8.3 PR-02 — migration and hash-chain integrity. A rewrite of a
// legacy suffix must update every successor link and signature, never
// touch witnessed or checkpointed history, and survive crash/replay and
// concurrent writers without forking the chain. Every rewrite runs
// inside a witness migration epoch.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func rowHash(t *testing.T, h *harness, seq int64) string {
	t.Helper()
	hash, err := h.row(t, seq).Envelope.Hash()
	if err != nil {
		t.Fatal(err)
	}
	return hash
}

func TestLegacyTwoRowSuffixRehash(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	insertLegacyRow(t, h, 1, "legacy-a", "")
	hash1 := rowHash(t, h, 1)
	insertLegacyRow(t, h, 2, "legacy-b", hash1)

	authority, trust := testRepairAuthority(t, h.dep)
	auth := testAuth(t, h.outbox, authority, trust, h.dep, OperationMigrate)
	payload := []byte(`{"canonical":"a"}`)
	res, err := h.migrate(t, auth, 1, "digest-a", payload)
	if err != nil {
		t.Fatalf("suffix migration: %v", err)
	}
	if res.Rehashed != 2 {
		t.Fatalf("rehashed %d rows, want 2", res.Rehashed)
	}
	chain, err := h.outbox.VerifyChain(context.Background())
	if err != nil {
		t.Fatalf("chain after migration: %v", err)
	}
	if chain.Rows != 2 {
		t.Fatalf("chain rows = %d, want 2", chain.Rows)
	}
	row1, row2 := h.row(t, 1), h.row(t, 2)
	content, err := row1.Envelope.ContentBytes()
	if err != nil || string(content) != string(payload) {
		t.Fatalf("target payload = %q, want %q", content, payload)
	}
	if row2.Envelope.Sequence.PreviousCheckpointHash != row1.EnvelopeHash {
		t.Fatalf("successor links to %q, want rebuilt %q", row2.Envelope.Sequence.PreviousCheckpointHash, row1.EnvelopeHash)
	}
	succ, _ := row2.Envelope.ContentBytes()
	if len(succ) != 0 {
		t.Fatalf("successor payload was rewritten: %q", succ)
	}
	journal, err := h.outbox.MigrationJournal(context.Background())
	if err != nil || len(journal) != 1 {
		t.Fatalf("journal = %+v, %v", journal, err)
	}
	if journal[0].Action != JournalCompensated || journal[0].BeforeDigest == "" || journal[0].AfterDigest == "" {
		t.Fatalf("journal lacks before/after evidence: %+v", journal[0])
	}
	if err := VerifyMigrationProof(journal[0], MigrationProofTrust{
		DeploymentID: h.dep, ProofTrust: h.ktrust, CustodianTrust: h.ctrust,
	}); err != nil {
		t.Fatalf("signed migration proof: %v", err)
	}
}

func TestLegacyThreeRowMixedPayloads(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	insertLegacyRow(t, h, 1, "mixed-a", "")
	h.enqueue("mixed-b", `{"payload":"two"}`)
	hash2 := rowHash(t, h, 2)
	insertLegacyRow(t, h, 3, "mixed-c", hash2)

	authority, trust := testRepairAuthority(t, h.dep)
	auth := testAuth(t, h.outbox, authority, trust, h.dep, OperationMigrate)
	if _, err := h.migrate(t, auth, 1, "digest-mixed-a", []byte(`{"payload":"one"}`)); err != nil {
		t.Fatalf("mixed suffix migration: %v", err)
	}
	if _, err := h.outbox.VerifyChain(context.Background()); err != nil {
		t.Fatalf("chain after mixed migration: %v", err)
	}
	row2, row3 := h.row(t, 2), h.row(t, 3)
	content, _ := row2.Envelope.ContentBytes()
	if string(content) != `{"payload":"two"}` {
		t.Fatalf("middle row content changed: %q", content)
	}
	if row3.Envelope.Sequence.PreviousCheckpointHash != row2.EnvelopeHash {
		t.Fatalf("third row links to %q, want rebuilt %q", row3.Envelope.Sequence.PreviousCheckpointHash, row2.EnvelopeHash)
	}
}

func TestLegacyMixedWitnessedSuffixRefusal(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	insertLegacyRow(t, h, 1, "witnessed-a", "")
	h.enqueue("witnessed-b", `{"payload":"two"}`)
	if _, err := h.outbox.db.ExecContext(context.Background(),
		`UPDATE custody_outbox SET ack = $1, delivered_at = $2 WHERE seq = 2`,
		`{"seq":2,"signature":"witnessed"}`, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	before1, before2 := rowHash(t, h, 1), rowHash(t, h, 2)
	authority, trust := testRepairAuthority(t, h.dep)
	auth := testAuth(t, h.outbox, authority, trust, h.dep, OperationMigrate)
	_, err := h.migrate(t, auth, 1, "digest", []byte(`{"new":true}`))
	if err == nil {
		t.Fatal("migration rewrote a suffix containing a witnessed row")
	}
	if !errors.Is(err, ErrEvidenceContradiction) {
		t.Fatalf("refusal is not a typed contradiction: %v", err)
	}
	if rowHash(t, h, 1) != before1 || rowHash(t, h, 2) != before2 {
		t.Fatal("refused migration still mutated the chain")
	}
	if _, err := h.outbox.VerifyChain(context.Background()); err != nil {
		t.Fatalf("chain after refusal: %v", err)
	}
}

func TestMigrationCrashBeforeCommit(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	insertLegacyRow(t, h, 1, "crash-before", "")
	authority, trust := testRepairAuthority(t, h.dep)
	auth := testAuth(t, h.outbox, authority, trust, h.dep, OperationMigrate)
	fence := h.openFence(t, auth)

	h.outbox.migrationHook = func(stage string) error {
		if stage == "before_commit" {
			return errors.New("injected crash before commit")
		}
		return nil
	}
	if _, err := h.outbox.MigrateLegacySuffix(context.Background(), h.prod,
		h.migrateRequest(auth, fence, 1, "digest", []byte(`{"x":1}`))); err == nil {
		t.Fatal("injected pre-commit crash did not fail the migration")
	}
	h.outbox.migrationHook = nil
	row := h.row(t, 1)
	content, _ := row.Envelope.ContentBytes()
	if len(content) != 0 {
		t.Fatalf("pre-commit crash left partial content: %q", content)
	}
	journal, _ := h.outbox.MigrationJournal(context.Background())
	if len(journal) != 0 {
		t.Fatalf("pre-commit crash left journal rows: %+v", journal)
	}
	if _, err := h.outbox.VerifyChain(context.Background()); err != nil {
		t.Fatalf("chain after pre-commit crash: %v", err)
	}
	// The epoch is still open, so the retry runs inside the same frozen
	// window rather than under a fresh, possibly stale, head.
	if _, err := h.outbox.MigrateLegacySuffix(context.Background(), h.prod,
		h.migrateRequest(auth, fence, 1, "digest", []byte(`{"x":1}`))); err != nil {
		t.Fatalf("retry after pre-commit crash: %v", err)
	}
}

func TestMigrationCrashAfterCommitBeforeAck(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	insertLegacyRow(t, h, 1, "crash-after-a", "")
	h.enqueue("crash-after-b", `{"payload":"two"}`)
	authority, trust := testRepairAuthority(t, h.dep)
	auth := testAuth(t, h.outbox, authority, trust, h.dep, OperationMigrate)
	fence := h.openFence(t, auth)

	h.outbox.migrationHook = func(stage string) error {
		if stage == "after_commit" {
			return errors.New("injected crash after commit")
		}
		return nil
	}
	res, err := h.outbox.MigrateLegacySuffix(context.Background(), h.prod,
		h.migrateRequest(auth, fence, 1, "digest", []byte(`{"x":1}`)))
	if err == nil {
		t.Fatal("injected post-commit crash was not reported")
	}
	if res.Rehashed != 2 {
		t.Fatalf("post-commit crash reported %d rehashed rows, want 2", res.Rehashed)
	}
	h.outbox.migrationHook = nil
	if _, err := h.outbox.VerifyChain(context.Background()); err != nil {
		t.Fatalf("chain after post-commit crash: %v", err)
	}
	replay, err := h.outbox.MigrateLegacySuffix(context.Background(), h.prod,
		h.migrateRequest(auth, fence, 1, "digest", []byte(`{"x":1}`)))
	if err != nil {
		t.Fatalf("replay after post-commit crash: %v", err)
	}
	if !replay.AlreadyMigrated {
		t.Fatal("replay after post-commit crash was not idempotent")
	}
	fc, err := h.fenceClient(auth)
	if err != nil {
		t.Fatal(err)
	}
	h.closeEpoch(t, fc, fence, "result")
	if !h.drain() {
		t.Fatalf("drain after recovered migration: %s", h.sender.LastError())
	}
}

func TestConcurrentEnqueueFenced(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	insertLegacyRow(t, h, 1, "fenced-a", "")
	authority, trust := testRepairAuthority(t, h.dep)
	auth := testAuth(t, h.outbox, authority, trust, h.dep, OperationMigrate)
	fence := h.openFence(t, auth)

	migrating := make(chan struct{})
	release := make(chan struct{})
	h.outbox.migrationHook = func(stage string) error {
		if stage == "before_commit" {
			close(migrating)
			<-release
		}
		return nil
	}
	migErr := make(chan error, 1)
	go func() {
		_, err := h.outbox.MigrateLegacySuffix(context.Background(), h.prod,
			h.migrateRequest(auth, fence, 1, "digest", []byte(`{"x":1}`)))
		migErr <- err
	}()
	<-migrating

	type enqResult struct {
		seq int64
		err error
	}
	enq := make(chan enqResult, 1)
	go func() {
		seq, err := h.outbox.Enqueue(context.Background(), h.prod, "fenced-b", "digest-b", []byte(`{"payload":"two"}`))
		enq <- enqResult{seq, err}
	}()
	time.Sleep(150 * time.Millisecond)
	close(release)
	if err := <-migErr; err != nil {
		t.Fatalf("concurrent migration: %v", err)
	}
	got := <-enq
	if got.err != nil {
		t.Fatalf("concurrent enqueue: %v", got.err)
	}
	h.outbox.migrationHook = nil
	if got.seq != 2 {
		t.Fatalf("concurrent enqueue seq = %d, want 2", got.seq)
	}
	if _, err := h.outbox.VerifyChain(context.Background()); err != nil {
		t.Fatalf("chain after concurrent enqueue: %v", err)
	}
	row1, row2 := h.row(t, 1), h.row(t, 2)
	if row2.Envelope.Sequence.PreviousCheckpointHash != row1.EnvelopeHash {
		t.Fatalf("concurrent enqueue forked the chain: prev %q != %q", row2.Envelope.Sequence.PreviousCheckpointHash, row1.EnvelopeHash)
	}
}

func TestMigrationReplayIdempotent(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	insertLegacyRow(t, h, 1, "replay-a", "")
	authority, trust := testRepairAuthority(t, h.dep)
	auth := testAuth(t, h.outbox, authority, trust, h.dep, OperationMigrate)
	fence := h.openFence(t, auth)
	if _, err := h.outbox.MigrateLegacySuffix(context.Background(), h.prod,
		h.migrateRequest(auth, fence, 1, "digest", []byte(`{"x":1}`))); err != nil {
		t.Fatal(err)
	}
	chain1, _ := h.outbox.VerifyChain(context.Background())
	res, err := h.outbox.MigrateLegacySuffix(context.Background(), h.prod,
		h.migrateRequest(auth, fence, 1, "digest", []byte(`{"x":1}`)))
	if err != nil {
		t.Fatalf("idempotent replay: %v", err)
	}
	if !res.AlreadyMigrated {
		t.Fatal("second migration was not recognized as a replay")
	}
	chain2, _ := h.outbox.VerifyChain(context.Background())
	if chain1.Digest != chain2.Digest {
		t.Fatalf("replay changed the chain: %s → %s", chain1.Digest, chain2.Digest)
	}
	journal, _ := h.outbox.MigrationJournal(context.Background())
	if len(journal) != 1 {
		t.Fatalf("replay duplicated the journal: %d entries", len(journal))
	}
}

// TestMigrationRefusesCheckpointedSuffix: the custodian already holds
// the target sequence (an RC8.1-era witness, or an acknowledgement lost
// in transit). The epoch freezes at that head, and the rewrite is
// refused: rewriting it would fork history the witness already holds.
func TestMigrationRefusesCheckpointedSuffix(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	insertLegacyRow(t, h, 1, "checkpoint-a", "")
	hash1 := rowHash(t, h, 1)
	h.injectWitnessRecord(t, 1, "checkpoint-a", h.row(t, 1).Envelope)

	authority, trust := testRepairAuthority(t, h.dep)
	auth := testAuth(t, h.outbox, authority, trust, h.dep, OperationMigrate)
	fence := h.openFence(t, auth)
	if fence.BaseSeq != 1 {
		t.Fatalf("epoch froze seq %d, want the custodian head 1", fence.BaseSeq)
	}
	_, err := h.outbox.MigrateLegacySuffix(context.Background(), h.prod,
		h.migrateRequest(auth, fence, 1, "digest", []byte(`{"x":1}`)))
	if err == nil {
		t.Fatal("migration rewrote a checkpointed suffix")
	}
	if rowHash(t, h, 1) != hash1 {
		t.Fatal("refused checkpointed migration mutated the target")
	}
}

// TestLostLocalAckWithRemoteCheckpointRefusesRewrite: the local outbox
// has no acknowledgement, but the custodian holds the sequence. The
// suffix must be refused at both preflight and the library boundary.
func TestLostLocalAckWithRemoteCheckpointRefusesRewrite(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	insertLegacyRow(t, h, 1, "lost-ack-a", "")
	hash := rowHash(t, h, 1)
	h.injectWitnessRecord(t, 1, "lost-ack-a", h.row(t, 1).Envelope)

	checkpoint := CheckpointRef{Seq: 1, Hash: hash, WitnessFP: h.wsigner.Fingerprint()}
	pf, err := h.outbox.MigrationPreflight(context.Background(), 1, checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	if !pf.Blocked || !strings.Contains(pf.Reason, "checkpoint") {
		t.Fatalf("remote checkpoint did not block the rewrite: blocked=%v reason=%q", pf.Blocked, pf.Reason)
	}
	authority, trust := testRepairAuthority(t, h.dep)
	auth := testAuth(t, h.outbox, authority, trust, h.dep, OperationMigrate)
	fence := h.openFence(t, auth)
	if _, err := h.outbox.MigrateLegacySuffix(context.Background(), h.prod,
		h.migrateRequest(auth, fence, 1, "digest", []byte(`{"x":1}`))); err == nil {
		t.Fatal("migration rewrote a suffix covered by a remote checkpoint")
	}
}

// TestMigrationRefusesZeroFence: a zero-value epoch is an offline
// attempt and must be refused before any mutation.
func TestMigrationRefusesZeroFence(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	insertLegacyRow(t, h, 1, "offline-a", "")
	authority, trust := testRepairAuthority(t, h.dep)
	auth := testAuth(t, h.outbox, authority, trust, h.dep, OperationMigrate)
	if _, err := h.outbox.MigrateLegacySuffix(context.Background(), h.prod,
		h.migrateRequest(auth, FenceReceipt{}, 1, "digest", []byte(`{"x":1}`))); err == nil {
		t.Fatal("offline migration without a verified epoch was admitted")
	}
	if _, err := h.outbox.VerifyChain(context.Background()); err != nil {
		t.Fatalf("refused offline migration mutated the chain: %v", err)
	}
}
