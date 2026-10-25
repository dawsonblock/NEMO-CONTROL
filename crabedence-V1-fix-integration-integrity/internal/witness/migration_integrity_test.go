package witness

// RC8.3 PR-01 — journal read integrity and verified witnessed-legacy
// coverage.

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/openclaw/crabbox/internal/custody"
)

// TestJournalDBErrorNotSwallowed: a broken journal read is an error,
// never "no classification recorded". Swallowing it would let an
// admission decision rest on a database failure.
func TestJournalDBErrorNotSwallowed(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	if err := h.outbox.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := h.outbox.LegacyJournalAction(context.Background(), "any-exec"); err == nil {
		t.Fatal("LegacyJournalAction swallowed a database failure")
	}

	h2 := newHarness(t, true)
	defer h2.cancel()
	if _, err := h2.outbox.db.ExecContext(context.Background(), `DROP TABLE custody_migration_journal`); err != nil {
		t.Fatal(err)
	}
	if _, err := h2.outbox.LegacyJournalAction(context.Background(), "any-exec"); err == nil {
		t.Fatal("LegacyJournalAction swallowed a missing-journal failure")
	}
}

// TestLegacyWitnessedWithVerifiedAckIsCovered is the positive control
// for the witnessed-legacy path: unchanged bytes plus a custodian-signed
// acknowledgement plus a signed operator classification verify. Without
// this control, a verifier that denied everything would pass the
// negative tests.
func TestLegacyWitnessedWithVerifiedAckIsCovered(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	const execID = "legacy-verified"
	insertLegacyRow(t, h, 1, execID, "")
	row := h.row(t, 1)
	envHash, err := row.Envelope.Hash()
	if err != nil {
		t.Fatal(err)
	}
	ack := &Ack{
		WitnessFP: h.wsigner.Fingerprint(), SignerEpoch: 0, DeploymentID: h.dep,
		Family: custody.FamilyReceipt, Seq: 1, ExecutionID: execID, EnvelopeHash: envHash,
	}
	sig, err := h.wsigner.SignRecord(ackDomain, ackFields(ack)...)
	if err != nil {
		t.Fatal(err)
	}
	ack.Signature = sig
	raw, err := json.Marshal(ack)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.outbox.db.ExecContext(context.Background(),
		`UPDATE custody_outbox SET ack = $1, delivered_at = $2 WHERE seq = 1`,
		string(raw), time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}

	authority, trust := testRepairAuthority(t, h.dep)
	auth := testAuth(t, h.outbox, authority, trust, h.dep, OperationMigrate)
	if err := h.outbox.JournalLegacyWitnessed(context.Background(), 1, "digest-verified",
		"operator alice: verified RC8.1 divergence", auth); err != nil {
		t.Fatal(err)
	}

	cov, err := h.outbox.ResolveLegacyCoverage(context.Background(), LegacyCoverageRequest{
		ExecutionID: execID, TerminalReceiptDigest: "digest-verified",
		DeploymentID: h.dep, RepairTrust: trust, CustodianTrust: h.ctrust, Now: time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if cov.Disposition != LegacyCoverageVerified {
		t.Fatalf("verified witnessed-legacy coverage = %s (%s), want %s", cov.Disposition, cov.Reason, LegacyCoverageVerified)
	}
}

// TestLegacyCoverageRejectsForgedAuthorization: a journal entry whose
// embedded grant is signed by an ordinary evidence key (not the pinned
// repair authority) is not coverage.
func TestLegacyCoverageRejectsForgedAuthorization(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	const execID = "legacy-forged-auth"
	insertLegacyRow(t, h, 1, execID, "")
	// A grant signed by the kernel-relay evidence key: valid signature,
	// wrong role and wrong pinned key.
	now := time.Now().UTC()
	g := &OperatorGrant{
		Subject: "mallory@example.com", DeploymentID: h.dep,
		Operations: []string{OperationMigrate},
		NotBefore:  now.Add(-time.Minute).Format(time.RFC3339),
		ExpiresAt:  now.Add(time.Minute).Format(time.RFC3339),
		Nonce:      testNonce(t),
	}
	if err := SignOperatorGrant(h.kernel, g); err != nil {
		t.Fatal(err)
	}
	digest, err := GrantDigest(g)
	if err != nil {
		t.Fatal(err)
	}
	authJSON, _ := json.Marshal(g)
	if _, err := h.outbox.db.ExecContext(context.Background(),
		`INSERT INTO custody_migration_journal (
			row_seq, execution_id, action, detail, created_at,
			original_envelope_hash, result_envelope_hash, terminal_receipt_digest,
			authorization_json, authorization_digest, authorized_by, nonce)
		 VALUES (1,$1,$2,'forged',$3,$4,$4,$5,$6,$7,$8,$9)`,
		execID, JournalLegacyWitnessed, now.Format(time.RFC3339Nano),
		"", "digest-forged", string(authJSON), digest, g.Subject, g.Nonce); err != nil {
		t.Fatal(err)
	}

	cov, err := h.outbox.ResolveLegacyCoverage(context.Background(), LegacyCoverageRequest{
		ExecutionID: execID, TerminalReceiptDigest: "digest-forged",
		DeploymentID: h.dep, RepairTrust: custody.NewTrustSet(), CustodianTrust: h.ctrust, Now: time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if cov.Disposition == LegacyCoverageVerified {
		t.Fatal("ordinary evidence signer authorized legacy coverage")
	}
}
