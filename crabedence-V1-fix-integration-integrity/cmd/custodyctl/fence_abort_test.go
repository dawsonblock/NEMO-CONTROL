package main

// RC8.3 PR-02 — an epoch that already rewrote evidence is closed, never
// aborted. Releasing the fence would let the sender resume with the
// envelopes the migration has replaced, which is the in-flight
// corruption the epoch exists to prevent.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openclaw/crabbox/internal/custody"
	"github.com/openclaw/crabbox/internal/evidence"
	"github.com/openclaw/crabbox/internal/witness"
)

func TestFenceAbortRefusesEpochWithCommittedMigration(t *testing.T) {
	bin := buildCLI(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	const dep = "dep-cli"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	kernel, _ := evidence.GenerateSigner()
	wsigner, _ := evidence.GenerateSigner()
	authority, _ := evidence.GenerateSigner()
	signerPath := filepath.Join(dir, "evidence.pem")
	pem, _ := kernel.MarshalPEM()
	writeOwnerFile(t, signerPath, pem)
	custodianPath := filepath.Join(dir, "custodian-trust.json")
	writeTrustFile(t, custodianPath, custody.RoleCustodian, dep, wsigner)
	kernelPath := filepath.Join(dir, "kernel-trust.json")
	writeTrustFile(t, kernelPath, custody.RoleKernelRelay, dep, kernel)
	repairPath := filepath.Join(dir, "repair-trust.json")
	writeTrustFile(t, repairPath, custody.RoleRepairAuthority, dep, authority)

	ledger, err := witness.OpenLedger(filepath.Join(dir, "witness.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	ktrust := custody.NewTrustSet(custody.TrustedKey{
		Role: custody.RoleKernelRelay, KeyID: kernel.Fingerprint(),
		PublicKey: kernel.PublicKey(), DeploymentID: dep,
	})
	svc := witness.NewService(ledger, wsigner, dep, ktrust, nil)
	sockDir, err := os.MkdirTemp("/tmp", "abort")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(sockDir)
	sock := filepath.Join(sockDir, "w.sock")
	go func() { _ = svc.Serve(ctx, sock) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("witness socket never appeared")
		}
		time.Sleep(10 * time.Millisecond)
	}

	storePath := filepath.Join(dir, "effects.db")
	ids := finalizeExecutions(t, storePath, 1)
	outboxPath := filepath.Join(dir, "outbox.db")
	seedLegacyOutboxFor(t, outboxPath, dep, kernel, ids)

	now := time.Now().UTC()
	grant := &witness.OperatorGrant{
		Subject: "alice@example.com", DeploymentID: dep,
		Operations: []string{witness.OperationMigrate},
		NotBefore:  now.Add(-time.Minute).Format(time.RFC3339),
		ExpiresAt:  now.Add(10 * time.Minute).Format(time.RFC3339),
		Nonce:      strings.Repeat("9", 32),
	}
	if err := witness.SignOperatorGrant(authority, grant); err != nil {
		t.Fatal(err)
	}
	grantRaw, _ := json.Marshal(grant)
	grantPath := filepath.Join(dir, "grant.json")
	writeOwnerFile(t, grantPath, grantRaw)

	// Migrate one row so the epoch has committed evidence, then crash
	// the epoch open by ending the run before the close: simulate that
	// by running migrate with a limit that leaves the epoch... the CLI
	// always closes, so instead open an epoch directly and write a
	// journal entry the way a crashed run would.
	o, err := witness.OpenOutbox(outboxPath)
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	digest, err := witness.GrantDigest(grant)
	if err != nil {
		t.Fatal(err)
	}
	if err := o.ConsumeOperatorNonce(ctx, grant, witness.OperationMigrate); err != nil {
		t.Fatal(err)
	}
	client := witness.NewClient(sock)
	ctrust := custody.NewTrustSet(custody.TrustedKey{
		Role: custody.RoleCustodian, KeyID: wsigner.Fingerprint(),
		PublicKey: wsigner.PublicKey(), DeploymentID: dep,
	})
	fc := &witness.FenceClient{
		Client: client, Signer: kernel, DeploymentID: dep, GrantDigest: digest,
		KernelTrust: ktrust, CustodianTrust: ctrust,
	}
	fence, err := fc.Begin(ctx)
	if err != nil {
		t.Fatalf("open epoch: %v", err)
	}
	if err := o.RecordFenceIntent(ctx, witness.FenceIntent{
		FenceID: fence.FenceID, DeploymentID: dep, GrantDigest: digest,
		BaseSeq: fence.BaseSeq, BaseHash: fence.BaseHash, State: witness.FenceOpen,
		OpenedAt: time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano),
	}); err != nil {
		t.Fatal(err)
	}
	producer := witness.Producer{
		DeploymentID: dep,
		Release:      custody.ReleaseIdentity{Version: "0.55.0-rc8.3-dev"},
		Signer:       kernel,
	}
	auth := witness.OperatorAuthorization{Grant: grant, Trust: repairPathTrust(t, repairPath), DeploymentID: dep}
	pf, err := o.MigrationPreflight(ctx, 1, witness.CheckpointRef{})
	if err != nil {
		t.Fatalf("preflight: %v", err)
	}
	permit, err := fc.Prepare(ctx, fence, 1, pf.EnvelopeHash)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if _, err := o.AdmitMigration(ctx, &permit); err != nil {
		t.Fatalf("admit: %v", err)
	}
	res, err := o.MigrateLegacySuffix(ctx, producer, witness.MigrationRequest{
		RowSeq: 1, TerminalReceiptDigest: "digest-1", Native: []byte(`{"canonical":"1"}`),
		Permit: permit, Authorization: auth, CustodianTrust: ctrust,
	})
	if err != nil {
		t.Fatalf("migration: %v", err)
	}
	if _, err := fc.Finalize(ctx, permit, witness.FinalizeReport{
		ProofDigest: res.ProofDigest, JournalSeq: res.JournalSeq,
		BeforeDigest: res.BeforeDigest, AfterDigest: res.AfterDigest, ResultDigest: res.AfterDigest,
	}); err != nil {
		t.Fatalf("finalize: %v", err)
	}

	// Abort must now refuse: the epoch rewrote a row, so releasing it
	// would resume submissions against the rewritten suffix.
	_, stderr, code := runCLI(t, bin, "fence", "abort",
		"-outbox", outboxPath, "-effect-store", storePath, "-deployment", dep,
		"-signer-key", signerPath,
		"-custodian-trust-roots", custodianPath,
		"-kernel-trust-roots", kernelPath,
		"-repair-trust-roots", repairPath,
		"-operator-token", grantPath,
		"-witness-socket", sock,
		"-actor", "alice@example.com")
	if code != 1 || !strings.Contains(stderr, "already committed") {
		t.Fatalf("abort over a committed epoch exit=%d stderr=%s", code, stderr)
	}
	active, err := ledger.ActiveFence(ctx, dep)
	if err != nil {
		t.Fatal(err)
	}
	if active == nil || active.FenceID != fence.FenceID {
		t.Fatalf("refused abort still released the epoch: %+v", active)
	}

	// Closing it is the correct terminal path.
	if _, err := fc.End(ctx, fence, "result-digest"); err != nil {
		t.Fatalf("close epoch: %v", err)
	}
	if err := o.CompleteFenceIntent(ctx, fence.FenceID, witness.FenceClosed, "result-digest"); err != nil {
		t.Fatal(err)
	}
}

func repairPathTrust(t *testing.T, path string) *custody.TrustSet {
	t.Helper()
	set, err := custody.LoadTrustSetForRole(path, custody.RoleRepairAuthority)
	if err != nil {
		t.Fatal(err)
	}
	return set
}
