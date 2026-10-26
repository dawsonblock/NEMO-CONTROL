package witness

// RC8.3 PR-03 — legacy empty-payload migration against the real
// outbox schema: an RC8.1-era row is inserted exactly as the old
// enqueue produced it (empty envelope content), then classified,
// compensated, and drained through the real witness.

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/openclaw/crabbox/internal/custody"
)

// insertLegacyRow writes the RC8.1 durable shape directly: seq,
// chain linkage, signature — everything real except content, which
// the old path left empty.
func insertLegacyRow(t *testing.T, h *harness, seq int64, exec, prev string) {
	t.Helper()
	env := custody.New(custody.FamilyReceipt, h.dep, h.prod.Release, h.prod.PolicyDigest,
		custody.Subject{EffectID: exec, ExecutionID: exec},
		custody.Sequence{Domain: custody.FamilyReceipt, Epoch: 0, Index: seq, PreviousCheckpointHash: prev},
		custody.EncodingWitnessFrame, nil)
	if err := custody.Sign(env, custody.RoleKernelRelay, h.kernel); err != nil {
		t.Fatal(err)
	}
	sum, err := env.Hash()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.outbox.db.ExecContext(context.Background(),
		`INSERT INTO custody_outbox (seq, execution_id, receipt_digest, envelope_hash, envelope_json, created_at)
		 VALUES ($1,$2,$3,$4,$5,$6)`,
		seq, exec, "legacy-"+exec, sum, string(raw),
		time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
}

func TestLegacyMigrationCompensateAndDrain(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	insertLegacyRow(t, h, 1, "legacy-exec", "")

	legacy, err := h.outbox.LegacyRows(context.Background())
	if err != nil || len(legacy) != 1 || legacy[0].Acked {
		t.Fatalf("preflight classification = %+v, want one unacked legacy row", legacy)
	}
	if action, _ := h.outbox.LegacyJournalAction(context.Background(), "legacy-exec"); action != "" {
		t.Fatalf("unmigrated row already journaled: %s", action)
	}

	// Compensate in place — same seq, same linkage, canonical payload.
	payload := []byte(`{"receipt":"v1","exec":"legacy-exec"}`)
	authority, trust := testRepairAuthority(t, h.dep)
	auth := testAuth(t, h.outbox, authority, trust, h.dep, OperationMigrate)
	if _, err := h.migrate(t, auth, 1, "digest-legacy-exec", payload); err != nil {
		t.Fatalf("compensate: %v", err)
	}
	row := h.row(t, 1)
	content, err := row.Envelope.ContentBytes()
	if err != nil || string(content) != string(payload) {
		t.Fatalf("compensated payload = %q, want %q", content, payload)
	}
	if row.Envelope.Sequence.Index != 1 || row.Envelope.Sequence.PreviousCheckpointHash != "" {
		t.Fatalf("compensation disturbed chain linkage: %+v", row.Envelope.Sequence)
	}
	if action, _ := h.outbox.LegacyJournalAction(context.Background(), "legacy-exec"); action != JournalCompensated {
		t.Fatalf("journal action = %q, want %s", action, JournalCompensated)
	}
	if legacy, _ := h.outbox.LegacyRows(context.Background()); len(legacy) != 0 {
		t.Fatalf("compensated row still classifies legacy: %+v", legacy)
	}

	// The compensated row drains through the real witness.
	if !h.drain() {
		t.Fatalf("drain after compensate failed: %s", h.sender.LastError())
	}
	row = h.row(t, 1)
	if row.Ack == nil {
		t.Fatal("compensated row never earned a witnessed ack")
	}
}

func TestLegacyMigrationWitnessedAndUnverifiable(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	insertLegacyRow(t, h, 1, "legacy-acked", "")
	// An RC8.1-era witnessed row: the RC8.3 witness refuses empty
	// content at submission, so the historical ack is simulated by
	// writing the recorded acknowledgement directly — exactly what
	// the old deployment's store holds.
	if _, err := h.outbox.db.ExecContext(context.Background(),
		`UPDATE custody_outbox SET ack=$1, delivered_at=$2 WHERE seq=1`,
		`{"seq":1,"signature":"legacy-ack"}`, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	legacy, err := h.outbox.LegacyRows(context.Background())
	if err != nil || len(legacy) != 1 || !legacy[0].Acked {
		t.Fatalf("classification = %+v, want one acked legacy row", legacy)
	}
	// Evidence bytes are never rewritten.
	authority, trust := testRepairAuthority(t, h.dep)
	refuseAuth := testAuth(t, h.outbox, authority, trust, h.dep, OperationMigrate)
	if _, err := h.migrate(t, refuseAuth, 1, "d", []byte("x")); err == nil {
		t.Fatal("compensation rewrote a witnessed row")
	}
	journalAuth := testAuth(t, h.outbox, authority, trust, h.dep, OperationMigrate)
	if err := h.outbox.JournalLegacyWitnessed(context.Background(), 1, "digest-legacy-acked", "operator alice: known RC8.1 empty divergence", journalAuth); err != nil {
		t.Fatalf("journal witnessed: %v", err)
	}
	if action, _ := h.outbox.LegacyJournalAction(context.Background(), "legacy-acked"); action != JournalLegacyWitnessed {
		t.Fatalf("journal action = %q, want %s", action, JournalLegacyWitnessed)
	}
	// Unverifiable quarantine records without touching the row.
	insertLegacyRow(t, h, 2, "legacy-ghost", "prev-hash")
	quarantineAuth := testAuth(t, h.outbox, authority, trust, h.dep, OperationMigrate)
	if err := h.outbox.JournalUnverifiable(context.Background(), 2, "legacy-ghost",
		"operator alice: no authoritative terminal record — quarantined", quarantineAuth); err != nil {
		t.Fatalf("journal unverifiable: %v", err)
	}
	journal, err := h.outbox.MigrationJournal(context.Background())
	if err != nil || len(journal) != 2 {
		t.Fatalf("journal = %+v, want 2 entries", journal)
	}
	if journal[0].Action != JournalLegacyWitnessed || journal[1].Action != JournalUnverifiable {
		t.Fatalf("journal order wrong: %+v", journal)
	}
}
