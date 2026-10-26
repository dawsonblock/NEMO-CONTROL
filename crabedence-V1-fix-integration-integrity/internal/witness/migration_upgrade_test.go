package witness

// RC8.3 integrity-closure follow-up — upgrade-path and coverage-binding
// regressions. The additive journal upgrade only runs from writable
// OpenOutbox, so read-only inspection must still read a pre-upgrade
// journal; and compensated coverage must be the rewrite the kernel-relay
// key signed, not merely a row whose nonce appears in the ledger.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/openclaw/crabbox/internal/custody"
	"github.com/openclaw/crabbox/internal/evidence"
)

// preUpgradeJournalDDL is the six-column RC8.3-dev journal shape.
const preUpgradeJournalDDL = `CREATE TABLE custody_migration_journal (
	seq INTEGER PRIMARY KEY AUTOINCREMENT,
	row_seq INTEGER NOT NULL,
	execution_id TEXT NOT NULL,
	action TEXT NOT NULL,
	detail TEXT NOT NULL,
	created_at TEXT NOT NULL
)`

func TestJournalReadsPreUpgradeSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pre-upgrade.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(preUpgradeJournalDDL); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO custody_migration_journal
		(row_seq, execution_id, action, detail, created_at)
		VALUES (1, 'legacy-a', 'unverifiable-legacy', 'pre-upgrade row', '2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}

	o := &Outbox{db: db}
	entries, err := o.MigrationJournalPage(context.Background(), 0, 0)
	if err != nil {
		t.Fatalf("pre-upgrade journal read: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	if entries[0].ExecutionID != "legacy-a" || entries[0].Action != JournalUnverifiable {
		t.Fatalf("pre-upgrade entry = %+v", entries[0])
	}
	if entries[0].ProofJSON != "" || entries[0].ProofSignature != "" || entries[0].TerminalSeq != 0 {
		t.Fatalf("absent columns must read as zero values: %+v", entries[0])
	}

	latest, found, err := latestJournalEntry(context.Background(), db, "legacy-a")
	if err != nil || !found {
		t.Fatalf("latestJournalEntry = %+v, %v, %v", latest, found, err)
	}
	if latest.Action != JournalUnverifiable {
		t.Fatalf("latest action = %q", latest.Action)
	}
}

// migratedLegacyRow inserts one legacy row, migrates it, and returns the
// pinned authority the coverage decision needs.
func migratedLegacyRow(t *testing.T, h *harness, seq int64, exec, digest string) (LegacyCoverageRequest, *custody.TrustSet) {
	t.Helper()
	insertLegacyRow(t, h, seq, exec, "")
	authority, repairTrust := testRepairAuthority(t, h.dep)
	auth := testAuth(t, h.outbox, authority, repairTrust, h.dep, OperationMigrate)
	if _, err := h.outbox.MigrateLegacySuffix(context.Background(), h.prod, seq, digest,
		[]byte(`{"canonical":"`+exec+`"}`), CheckpointRef{WitnessFP: "test-witness"}, auth); err != nil {
		t.Fatalf("migrate %s: %v", exec, err)
	}
	return LegacyCoverageRequest{
		ExecutionID:           exec,
		TerminalReceiptDigest: digest,
		DeploymentID:          h.dep,
		RepairTrust:           repairTrust,
		CustodianTrust:        h.ctrust,
		ProofTrust:            h.ktrust,
		Now:                   time.Now(),
	}, repairTrust
}

func TestCompensatedCoverageRequiresSignedProof(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	req, _ := migratedLegacyRow(t, h, 1, "legacy-a", "digest-a")

	cov, err := h.outbox.ResolveLegacyCoverage(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if cov.Disposition != LegacyCoverageVerified {
		t.Fatalf("compensated coverage = %s (%s), want COVERED_VERIFIED", cov.Disposition, cov.Reason)
	}

	// No pinned kernel-relay set: the proof cannot be attributed, so
	// compensated coverage fails closed.
	unpinned := req
	unpinned.ProofTrust = custody.NewTrustSet()
	cov, err = h.outbox.ResolveLegacyCoverage(context.Background(), unpinned)
	if err != nil {
		t.Fatal(err)
	}
	if cov.Disposition != LegacyCoverageUnresolved {
		t.Fatalf("unpinned proof coverage = %s, want UNRESOLVED", cov.Disposition)
	}

	// A proof that no longer matches its signed bytes is not coverage.
	if _, err := h.outbox.db.ExecContext(context.Background(),
		`UPDATE custody_migration_journal SET proof_signature = '' WHERE row_seq = 1`); err != nil {
		t.Fatal(err)
	}
	cov, err = h.outbox.ResolveLegacyCoverage(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if cov.Disposition != LegacyCoverageUnresolved {
		t.Fatalf("proof-less coverage = %s, want UNRESOLVED", cov.Disposition)
	}
}

// TestCopiedMigrationProofDoesNotTransferCoverage is the local-database
// writer case: a forged compensated entry carrying another row's genuine
// signed proof must not become verified coverage.
func TestCopiedMigrationProofDoesNotTransferCoverage(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	insertLegacyRow(t, h, 1, "legacy-a", "")
	hash1 := rowHash(t, h, 1)
	insertLegacyRow(t, h, 2, "legacy-b", hash1)

	authority, repairTrust := testRepairAuthority(t, h.dep)
	auth := testAuth(t, h.outbox, authority, repairTrust, h.dep, OperationMigrate)
	// Migrate the second row only; row 1 stays an unclassified legacy row.
	if _, err := h.outbox.MigrateLegacySuffix(context.Background(), h.prod, 2, "digest-b",
		[]byte(`{"canonical":"b"}`), CheckpointRef{WitnessFP: "test-witness"}, auth); err != nil {
		t.Fatalf("migrate row 2: %v", err)
	}
	journal, err := h.outbox.MigrationJournal(context.Background())
	if err != nil || len(journal) != 1 {
		t.Fatalf("journal = %+v, %v", journal, err)
	}
	real := journal[0]

	// Forge a compensated entry for row 1 that reuses row 2's signed
	// proof and its digests, bound to row 1's actual envelope hash and
	// terminal digest.
	if _, err := h.outbox.db.ExecContext(context.Background(),
		`INSERT INTO custody_migration_journal (
			row_seq, execution_id, action, detail, created_at,
			original_envelope_hash, result_envelope_hash, terminal_receipt_digest,
			authorization_json, authorization_digest, authorized_by, nonce,
			before_digest, after_digest, proof_json, proof_signature)
		 VALUES (1,'legacy-a','payload-compensated','forged copy','`+time.Now().UTC().Format(time.RFC3339Nano)+`',
			$1,$2,'digest-a',$3,$4,$5,$6,$7,$8,$9,$10)`,
		hash1, hash1, real.AuthorizationJSON, real.AuthorizationDigest, real.AuthorizedBy, real.Nonce,
		real.BeforeDigest, real.AfterDigest, real.ProofJSON, real.ProofSignature); err != nil {
		t.Fatal(err)
	}

	cov, err := h.outbox.ResolveLegacyCoverage(context.Background(), LegacyCoverageRequest{
		ExecutionID: "legacy-a", TerminalReceiptDigest: "digest-a", DeploymentID: h.dep,
		RepairTrust: repairTrust, CustodianTrust: h.ctrust, ProofTrust: h.ktrust, Now: time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if cov.Disposition == LegacyCoverageVerified {
		t.Fatal("a copied signed proof from another row transferred coverage")
	}
	// The binding, not some earlier check, is what refused it: the
	// forged entry binds row 1's own hashes and digest.
	if !strings.Contains(cov.Reason, "rewrite proof") {
		t.Fatalf("refusal did not come from the proof binding: %s", cov.Reason)
	}
}

func TestMigrationRefusesSuffixAcrossKeyRotation(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	insertLegacyRow(t, h, 1, "rot-a", "")
	other, err := evidence.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	insertLegacyRowSigned(t, h, 2, "rot-b", rowHash(t, h, 1), other)

	authority, trust := testRepairAuthority(t, h.dep)
	auth := testAuth(t, h.outbox, authority, trust, h.dep, OperationMigrate)
	_, err = h.outbox.MigrateLegacySuffix(context.Background(), h.prod, 1, "digest-rot",
		[]byte(`{"canonical":"rot"}`), CheckpointRef{WitnessFP: "test-witness"}, auth)
	if !errors.Is(err, ErrEvidenceContradiction) {
		t.Fatalf("suffix spanning a rotation = %v, want ErrEvidenceContradiction", err)
	}
	if !strings.Contains(err.Error(), "spans a key rotation") {
		t.Fatalf("refusal does not name the rotation: %v", err)
	}
	content, cerr := h.row(t, 1).Envelope.ContentBytes()
	if cerr != nil || len(content) != 0 {
		t.Fatalf("refused migration still rewrote the target: %q", content)
	}
}

// insertLegacyRowSigned mirrors insertLegacyRow with an explicit signer,
// so a test can build a suffix written under a different kernel key.
func insertLegacyRowSigned(t *testing.T, h *harness, seq int64, exec, prev string, signer *evidence.Signer) {
	t.Helper()
	env := custody.New(custody.FamilyReceipt, h.dep, h.prod.Release, h.prod.PolicyDigest,
		custody.Subject{EffectID: exec, ExecutionID: exec},
		custody.Sequence{Domain: custody.FamilyReceipt, Epoch: 0, Index: seq, PreviousCheckpointHash: prev},
		custody.EncodingWitnessFrame, nil)
	if err := custody.Sign(env, custody.RoleKernelRelay, signer); err != nil {
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
