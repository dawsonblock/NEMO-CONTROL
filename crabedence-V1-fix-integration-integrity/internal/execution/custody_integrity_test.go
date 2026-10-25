package execution

// RC8.3 PR-01 — custody coverage integrity regressions. A legacy
// empty-payload row is covered only when its migration journal entry
// independently binds the row, the authoritative terminal receipt, the
// envelope hash, the row sequence, and a signed operator authorization.
// "Some journal entry exists" is never coverage.

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/openclaw/crabbox/internal/custody"
	"github.com/openclaw/crabbox/internal/evidence"
	"github.com/openclaw/crabbox/internal/idempotency"
	"github.com/openclaw/crabbox/internal/witness"
)

func openIntegrityOutbox(t *testing.T) (*witness.Outbox, *sql.DB) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "outbox.db")
	o, err := witness.OpenOutbox(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { o.Close() })
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return o, db
}

func insertIntegrityLegacyRow(t *testing.T, db *sql.DB, prod witness.Producer, seq int64, execID, prev string) {
	t.Helper()
	env := custody.New(custody.FamilyReceipt, prod.DeploymentID, prod.Release, prod.PolicyDigest,
		custody.Subject{EffectID: execID, ExecutionID: execID},
		custody.Sequence{Domain: custody.FamilyReceipt, Epoch: 0, Index: seq, PreviousCheckpointHash: prev},
		custody.EncodingWitnessFrame, nil)
	if err := custody.Sign(env, custody.RoleKernelRelay, prod.Signer); err != nil {
		t.Fatal(err)
	}
	hash, err := env.Hash()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(
		`INSERT INTO custody_outbox (seq, execution_id, receipt_digest, envelope_hash, envelope_json, created_at)
		 VALUES ($1,$2,$3,$4,$5,$6)`,
		seq, execID, "legacy-"+execID, hash, string(raw), time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
}

func integrityGrant(t *testing.T, outbox *witness.Outbox, deploymentID, operation string) (witness.MigrationAuthorization, *custody.TrustSet) {
	t.Helper()
	signer, err := evidence.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	trust := custody.NewTrustSet(custody.TrustedKey{
		Role: custody.RoleRepairAuthority, KeyID: signer.Fingerprint(),
		PublicKey: signer.PublicKey(), DeploymentID: deploymentID,
	})
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	g := &witness.OperatorGrant{
		Subject:      "alice@example.com",
		DeploymentID: deploymentID,
		Operations:   []string{operation},
		NotBefore:    now.Add(-time.Minute).Format(time.RFC3339),
		ExpiresAt:    now.Add(10 * time.Minute).Format(time.RFC3339),
		Nonce:        hex.EncodeToString(b[:]),
	}
	if err := witness.SignOperatorGrant(signer, g); err != nil {
		t.Fatal(err)
	}
	if err := outbox.ConsumeOperatorNonce(context.Background(), g, operation); err != nil {
		t.Fatal(err)
	}
	return witness.MigrationAuthorization{Grant: g, Trust: trust, DeploymentID: deploymentID}, trust
}

// TestUnverifiableLegacyJournalCannotAdvanceHWM: a quarantined
// unverifiable-legacy classification is not coverage. Reconcile must
// fail closed, keep REPAIR_REQUIRED open, and leave the high-water mark
// below the unresolved sequence.
func TestUnverifiableLegacyJournalCannotAdvanceHWM(t *testing.T) {
	store := openExecutorSQLiteStore(t, idempotency.DefaultLeaseConfig)
	exec := NewDispatchExecutor(&simProvider{effect: true}, store)
	exec.SetEvidenceSigner(custodySigner(t))
	execID := terminalize(t, exec, "ci-unverifiable")

	outbox, db := openIntegrityOutbox(t)
	dep := "dep-ci"
	prod := obligationProducer(t, dep, custodySigner(t))
	insertIntegrityLegacyRow(t, db, prod, 1, execID, "")

	auth, repairTrust := integrityGrant(t, outbox, dep, witness.OperationMigrate)
	if err := outbox.JournalUnverifiable(context.Background(), 1, execID,
		"operator alice: no authoritative terminal record — quarantined", auth); err != nil {
		t.Fatalf("quarantine: %v", err)
	}

	policy := CustodyCoveragePolicy{DeploymentID: dep, RepairTrust: repairTrust, CustodianTrust: custody.NewTrustSet()}
	err := reconcileCustodyObligations(context.Background(), store, outbox, prod, 0, policy)
	if err == nil {
		t.Fatal("unverifiable-legacy journal was accepted as coverage")
	}
	hw, _ := outbox.ObligationHighWater(context.Background())
	if hw != 0 {
		t.Fatalf("high-water advanced to %d across an unresolved contradiction", hw)
	}
	st, _ := outbox.CustodyStatus(context.Background())
	if st.RepairReason == "" {
		t.Fatal("unresolved legacy row did not preserve REPAIR_REQUIRED")
	}
	if !strings.Contains(st.RepairReason, "UNRESOLVED") {
		t.Fatalf("repair reason does not record the typed verdict: %q", st.RepairReason)
	}
}

// TestTerminalArrivesAfterQuarantine: a row quarantined before its
// terminal record existed must not become covered automatically when
// the record appears. The stale quarantine stays unresolved until an
// operator re-migrates it with fresh authorization.
func TestTerminalArrivesAfterQuarantine(t *testing.T) {
	store := openExecutorSQLiteStore(t, idempotency.DefaultLeaseConfig)
	exec := NewDispatchExecutor(&simProvider{effect: true}, store)
	exec.SetEvidenceSigner(custodySigner(t))
	execID := terminalize(t, exec, "ci-late-terminal")

	outbox, db := openIntegrityOutbox(t)
	dep := "dep-ci-late"
	prod := obligationProducer(t, dep, custodySigner(t))
	insertIntegrityLegacyRow(t, db, prod, 1, execID, "")

	auth, repairTrust := integrityGrant(t, outbox, dep, witness.OperationMigrate)
	if err := outbox.JournalUnverifiable(context.Background(), 1, execID,
		"operator alice: terminal record not yet established — quarantined", auth); err != nil {
		t.Fatal(err)
	}
	journal, err := outbox.MigrationJournal(context.Background())
	if err != nil || len(journal) != 1 {
		t.Fatalf("journal = %+v, %v", journal, err)
	}
	if journal[0].TerminalReceiptDigest != "" {
		t.Fatal("quarantine unexpectedly bound a terminal digest")
	}
	rec, err := store.Lookup(context.Background(), execID)
	if err != nil || rec.TerminalReceiptDigest == "" {
		t.Fatalf("authoritative terminal record missing its digest: %+v, %v", rec, err)
	}

	policy := CustodyCoveragePolicy{DeploymentID: dep, RepairTrust: repairTrust, CustodianTrust: custody.NewTrustSet()}
	if err := reconcileCustodyObligations(context.Background(), store, outbox, prod, 0, policy); err == nil {
		t.Fatal("stale quarantine became coverage when the terminal record arrived")
	}
	hw, _ := outbox.ObligationHighWater(context.Background())
	if hw != 0 {
		t.Fatalf("high-water advanced to %d after a stale quarantine", hw)
	}
}

// TestMalformedLegacyJournalFailsClosed: an unknown disposition is not
// coverage and does not crash the scanner into silently skipping the
// row.
func TestMalformedLegacyJournalFailsClosed(t *testing.T) {
	store := openExecutorSQLiteStore(t, idempotency.DefaultLeaseConfig)
	exec := NewDispatchExecutor(&simProvider{effect: true}, store)
	exec.SetEvidenceSigner(custodySigner(t))
	execID := terminalize(t, exec, "ci-malformed")

	outbox, db := openIntegrityOutbox(t)
	dep := "dep-ci-malformed"
	prod := obligationProducer(t, dep, custodySigner(t))
	insertIntegrityLegacyRow(t, db, prod, 1, execID, "")
	if _, err := db.Exec(
		`INSERT INTO custody_migration_journal (row_seq, execution_id, action, detail, created_at)
		 VALUES (1, $1, 'definitely-not-a-disposition', 'forged', $2)`,
		execID, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}

	policy := CustodyCoveragePolicy{DeploymentID: dep, RepairTrust: custody.NewTrustSet(), CustodianTrust: custody.NewTrustSet()}
	if err := reconcileCustodyObligations(context.Background(), store, outbox, prod, 0, policy); err == nil {
		t.Fatal("malformed journal disposition was accepted as coverage")
	}
	hw, _ := outbox.ObligationHighWater(context.Background())
	if hw != 0 {
		t.Fatalf("high-water advanced to %d over a malformed journal", hw)
	}
	st, _ := outbox.CustodyStatus(context.Background())
	if st.RepairReason == "" {
		t.Fatal("malformed journal did not fail closed to REPAIR_REQUIRED")
	}
}

// TestLegacyWitnessedWithoutVerifiedAckIsNotCovered: a legacy-witnessed
// journal entry without a cryptographically verified acknowledgement is
// not coverage — the entry records a claim, the ack is the evidence.
func TestLegacyWitnessedWithoutVerifiedAckIsNotCovered(t *testing.T) {
	store := openExecutorSQLiteStore(t, idempotency.DefaultLeaseConfig)
	exec := NewDispatchExecutor(&simProvider{effect: true}, store)
	exec.SetEvidenceSigner(custodySigner(t))
	execID := terminalize(t, exec, "ci-bogus-ack")
	rec, err := store.Lookup(context.Background(), execID)
	if err != nil || rec.TerminalReceiptDigest == "" {
		t.Fatalf("terminal record: %v", err)
	}

	outbox, db := openIntegrityOutbox(t)
	dep := "dep-ci-ack"
	prod := obligationProducer(t, dep, custodySigner(t))
	insertIntegrityLegacyRow(t, db, prod, 1, execID, "")
	if _, err := db.Exec(
		`UPDATE custody_outbox SET ack = $1, delivered_at = $2 WHERE seq = 1`,
		`{"seq":1,"signature":"forged-ack"}`, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	auth, repairTrust := integrityGrant(t, outbox, dep, witness.OperationMigrate)
	if err := outbox.JournalLegacyWitnessed(context.Background(), 1, rec.TerminalReceiptDigest,
		"operator alice: claimed RC8.1 divergence", auth); err != nil {
		t.Fatal(err)
	}

	policy := CustodyCoveragePolicy{DeploymentID: dep, RepairTrust: repairTrust, CustodianTrust: custody.NewTrustSet()}
	if err := reconcileCustodyObligations(context.Background(), store, outbox, prod, 0, policy); err == nil {
		t.Fatal("witnessed-legacy classification without a verified ack was accepted as coverage")
	}
	hw, _ := outbox.ObligationHighWater(context.Background())
	if hw != 0 {
		t.Fatalf("high-water advanced to %d without a verified ack", hw)
	}
}
