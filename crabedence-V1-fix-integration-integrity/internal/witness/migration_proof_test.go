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

// resignPermit re-countersigns a permit the test has altered, under the
// real custodian key, so the adversarial proof differs from the journal
// in the one dimension the test names rather than in its signature.
func resignPermit(t *testing.T, h *harness, permit *FencePermit) {
	t.Helper()
	permit.Signature = ""
	if _, err := SignFencePermit(h.wsigner, permit.SignerEpoch, permit); err != nil {
		t.Fatalf("re-sign permit: %v", err)
	}
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

func TestMigrationProofRejectsForeignPermitTarget(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	base, proof := realProof(t, h)
	if proof.Permit == nil {
		t.Fatal("v2 proof carries no admission permit")
	}

	// Re-sign a proof whose admission names a different target than the
	// journal row it claims to describe: the custodian never admitted a
	// rewrite there. The permit is re-signed by the real custodian key,
	// so signature validity cannot be what refuses it.
	proof.Permit.TargetSeq = base.RowSeq + 7
	resignPermit(t, h, proof.Permit)
	entry := signedProofEntry(t, h, base, proof)
	if err := VerifyMigrationProof(entry, proofTrust(h)); err == nil {
		t.Fatal("proof whose permit admits a foreign target verified")
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

func TestMigrationProofRejectsPermitFromAnotherGrant(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	base, proof := realProof(t, h)
	if proof.Permit == nil {
		t.Fatal("v2 proof carries no admission permit")
	}

	// A permit that verifies but admits a different grant is not this
	// rewrite's authority: the journal still records the grant the
	// rewrite actually ran under. The permit is re-signed by the real
	// custodian key, so the grant binding is what refuses it.
	proof.Permit.GrantDigest = "different-grant"
	resignPermit(t, h, proof.Permit)
	entry := signedProofEntry(t, h, base, proof)
	if err := VerifyMigrationProof(entry, proofTrust(h)); err == nil {
		t.Fatal("proof bound to another grant's admission verified")
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
