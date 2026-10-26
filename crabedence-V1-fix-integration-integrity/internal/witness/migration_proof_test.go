package witness

// RC8.3 PR-03 — complete migration-proof binding. A proof is evidence
// only if it describes the exact rewrite the journal records, under the
// exact epoch the custodian froze, and still matches the durable chain.
// Each test below constructs a *correctly signed* proof that differs
// from the journal in one dimension: signature validity alone must not
// carry it.

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/openclaw/crabbox/internal/custody"
)

// signedProofEntry swaps an arbitrary, validly signed proof into a
// journal entry while keeping the entry's own recorded fields. That is
// the adversary that matters: a signature that is genuinely the
// kernel's over a proof that does not describe this journal row.
func signedProofEntry(t *testing.T, h *harness, base MigrationJournalEntry, proof migrationProof) MigrationJournalEntry {
	t.Helper()
	raw, err := canonicalJSON(proof)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := h.kernel.SignRecord(MigrationProofDomain, string(raw))
	if err != nil {
		t.Fatal(err)
	}
	base.ProofJSON = string(raw)
	base.ProofSignature = sig
	return base
}

func realProof(t *testing.T, h *harness) (MigrationJournalEntry, migrationProof) {
	t.Helper()
	insertLegacyRow(t, h, 1, "proof-a", "")
	authority, trust := testRepairAuthority(t, h.dep)
	auth := testAuth(t, h.outbox, authority, trust, h.dep, OperationMigrate)
	if _, err := h.migrate(t, auth, 1, "digest-a", []byte(`{"canonical":"a"}`)); err != nil {
		t.Fatalf("migration: %v", err)
	}
	journal, err := h.outbox.MigrationJournal(context.Background())
	if err != nil || len(journal) != 1 {
		t.Fatalf("journal = %+v, %v", journal, err)
	}
	var proof migrationProof
	if err := json.Unmarshal([]byte(journal[0].ProofJSON), &proof); err != nil {
		t.Fatal(err)
	}
	return journal[0], proof
}

func proofTrust(h *harness) MigrationProofTrust {
	return MigrationProofTrust{DeploymentID: h.dep, ProofTrust: h.ktrust, CustodianTrust: h.ctrust}
}

func TestMigrationProofRejectsAlteredRows(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	base, proof := realProof(t, h)

	// A validly signed proof whose rows no longer hash to its own
	// before/after digests describes a rewrite that never happened.
	proof.Rows[0].AfterHash = "00"
	entry := signedProofEntry(t, h, base, proof)
	if err := VerifyMigrationProof(entry, proofTrust(h)); err == nil {
		t.Fatal("proof with a forged row hash verified")
	}
}

func TestMigrationProofRejectsJournalIdentityMismatch(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	base, proof := realProof(t, h)

	cases := map[string]func(*MigrationJournalEntry){
		"execution":       func(e *MigrationJournalEntry) { e.ExecutionID = "someone-else" },
		"terminal digest": func(e *MigrationJournalEntry) { e.TerminalReceiptDigest = "other-digest" },
		"row seq":         func(e *MigrationJournalEntry) { e.RowSeq = 7 },
		"action":          func(e *MigrationJournalEntry) { e.Action = JournalLegacyWitnessed },
		"result hash":     func(e *MigrationJournalEntry) { e.ResultEnvelopeHash = "ff" },
		"authorization":   func(e *MigrationJournalEntry) { e.AuthorizationDigest = "ff" },
		"checkpoint":      func(e *MigrationJournalEntry) { e.CheckpointSeq = 42 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			entry := signedProofEntry(t, h, base, proof)
			mutate(&entry)
			if err := VerifyMigrationProof(entry, proofTrust(h)); err == nil {
				t.Fatalf("proof verified with a mismatched %s", name)
			}
		})
	}
}

func TestMigrationProofRejectsNonOpenEpoch(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	base, proof := realProof(t, h)

	// Re-sign a proof that claims the rewrite committed under a closed
	// epoch: the custodian never authorized a rewrite there.
	proof.Fence.State = FenceClosed
	proof.Fence.Signature = ""
	if _, err := SignFenceReceipt(h.wsigner, 0, &proof.Fence); err != nil {
		t.Fatal(err)
	}
	entry := signedProofEntry(t, h, base, proof)
	if err := VerifyMigrationProof(entry, proofTrust(h)); err == nil {
		t.Fatal("proof committed under a closed epoch verified")
	}
}

func TestMigrationProofRejectsCustodianSignedProof(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	base, proof := realProof(t, h)

	raw, err := canonicalJSON(proof)
	if err != nil {
		t.Fatal(err)
	}
	// The custodian attests custody; it does not attest kernel
	// rewrites. A custodian signature must not satisfy ProofTrust.
	sig, err := h.wsigner.SignRecord(MigrationProofDomain, string(raw))
	if err != nil {
		t.Fatal(err)
	}
	entry := signedProofEntry(t, h, base, proof)
	entry.ProofSignature = sig
	if err := VerifyMigrationProof(entry, proofTrust(h)); err == nil {
		t.Fatal("a custodian key signed a migration proof and it verified")
	}
}

func TestMigrationProofRejectsFenceFromAnotherEpoch(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	base, proof := realProof(t, h)

	// An epoch that verifies but was opened by a different grant is not
	// this rewrite's authority: the journal still records the grant the
	// rewrite actually ran under.
	proof.Fence.GrantDigest = "different-grant"
	proof.Fence.Signature = ""
	if _, err := SignFenceReceipt(h.wsigner, 0, &proof.Fence); err != nil {
		t.Fatal(err)
	}
	entry := signedProofEntry(t, h, base, proof)
	if err := VerifyMigrationProof(entry, proofTrust(h)); err == nil {
		t.Fatal("proof bound to another grant's epoch verified")
	}
}

func TestMigrationProofAgainstChainDetectsLaterRewrite(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	entry, _ := realProof(t, h)
	if err := h.outbox.VerifyMigrationProofAgainstChain(context.Background(), entry, proofTrust(h)); err != nil {
		t.Fatalf("fresh proof against chain: %v", err)
	}

	// Someone rewrites the row after the fact — a different canonical
	// payload, validly signed — so the proof no longer describes the
	// durable chain and cannot be coverage.
	row := h.row(t, 1)
	env := *row.Envelope
	env.Content = custody.Content{}
	rebuilt := custody.New(env.Family, env.DeploymentID, env.ReleaseIdentity, env.PolicyDigest,
		env.Subject, env.Sequence, env.Content.Encoding, []byte(`{"canonical":"substituted"}`))
	if err := custody.Sign(rebuilt, custody.RoleKernelRelay, h.kernel); err != nil {
		t.Fatal(err)
	}
	newHash, err := rebuilt.Hash()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(rebuilt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.outbox.db.ExecContext(context.Background(),
		`UPDATE custody_outbox SET envelope_hash = $1, envelope_json = $2 WHERE seq = 1`,
		newHash, string(raw)); err != nil {
		t.Fatal(err)
	}
	chainErr := h.outbox.VerifyMigrationProofAgainstChain(context.Background(), entry, proofTrust(h))
	if !errors.Is(chainErr, ErrEvidenceContradiction) {
		t.Fatalf("post-hoc rewrite was not a contradiction: %v", chainErr)
	}
}
