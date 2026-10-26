package main

// RC8.3 PR-05 — end-to-end operator migration through the shipped
// binary: a real witness service, a real outbox, a real effect store,
// and role-separated trust roots. The epoch opens before the first
// rewrite and closes after the last, and the result is auditable from
// the outbox alone.

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openclaw/crabbox/internal/custody"
	"github.com/openclaw/crabbox/internal/evidence"
	"github.com/openclaw/crabbox/internal/idempotency"
	"github.com/openclaw/crabbox/internal/witness"
)

// seedLegacyOutboxFor writes the RC8.1 durable shape for exactly the
// named executions, signed by the deployment's kernel-relay key.
func seedLegacyOutboxFor(t *testing.T, path, deployment string, signer *evidence.Signer, execs []string) {
	t.Helper()
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	o, err := witness.OpenOutbox(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	release := custody.ReleaseIdentity{Version: "0.55.0-rc8.3-dev"}
	prev := ""
	for i, exec := range execs {
		env := custody.New(custody.FamilyReceipt, deployment, release, "",
			custody.Subject{EffectID: exec, ExecutionID: exec},
			custody.Sequence{Domain: custody.FamilyReceipt, Epoch: 0, Index: int64(i + 1), PreviousCheckpointHash: prev},
			custody.EncodingWitnessFrame, nil)
		if err := custody.Sign(env, custody.RoleKernelRelay, signer); err != nil {
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
			i+1, exec, "legacy", hash, string(raw), time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
		prev = hash
	}
}

// finalizeExecutions drives the real store lifecycle and returns the
// terminal execution ids in acquisition order.
func finalizeExecutions(t *testing.T, storePath string, n int) []string {
	t.Helper()
	db, err := idempotency.OpenSQLiteDB(storePath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := idempotency.NewSQLiteStore(db)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	var ids []string
	for i := 0; i < n; i++ {
		key := "idem-" + time.Unix(int64(i), 0).UTC().Format("150405")
		res, err := store.Acquire(ctx, key, "alice@example.com", "test.capability", "digest", "", "STANDARD", time.Minute)
		if err != nil {
			t.Fatalf("acquire %d: %v", i, err)
		}
		if res.Record == nil {
			t.Fatalf("acquire %d returned no record", i)
		}
		id := res.Record.ExecutionID
		if err := store.BeginExecution(ctx, id, res.LeaseToken, res.Generation); err != nil {
			t.Fatalf("begin %s: %v", id, err)
		}
		if err := store.MarkInFlight(ctx, id, res.LeaseToken, res.Generation, "test-provider", nil); err != nil {
			t.Fatalf("in-flight %s: %v", id, err)
		}
		if err := store.Finalize(ctx, id, res.LeaseToken, res.Generation, idempotency.StateInFlight,
			idempotency.TerminalReceipt{
				TerminalStatus:  idempotency.StateCommitted,
				CanonicalResult: json.RawMessage(`{"ok":true}`),
			}); err != nil {
			t.Fatalf("finalize %s: %v", id, err)
		}
		ids = append(ids, id)
	}
	return ids
}

func TestMigrateEndToEndFencedEpoch(t *testing.T) {
	bin := buildCLI(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	const dep = "dep-cli"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	kernel, err := evidence.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	wsigner, err := evidence.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	authority, err := evidence.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}

	signerPath := filepath.Join(dir, "evidence.pem")
	pem, err := kernel.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	writeOwnerFile(t, signerPath, pem)
	custodianPath := filepath.Join(dir, "custodian-trust.json")
	writeTrustFile(t, custodianPath, custody.RoleCustodian, dep, wsigner)
	kernelPath := filepath.Join(dir, "kernel-trust.json")
	writeTrustFile(t, kernelPath, custody.RoleKernelRelay, dep, kernel)
	repairPath := filepath.Join(dir, "repair-trust.json")
	writeTrustFile(t, repairPath, custody.RoleRepairAuthority, dep, authority)

	// The witness is a real service on a real socket.
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
	sockDir, err := os.MkdirTemp("/tmp", "e2e")
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

	// Two durably terminal executions whose legacy outbox rows carry
	// empty payloads.
	storePath := filepath.Join(dir, "effects.db")
	ids := finalizeExecutions(t, storePath, 2)
	outboxPath := filepath.Join(dir, "outbox.db")
	seedLegacyOutboxFor(t, outboxPath, dep, kernel, ids)

	now := time.Now().UTC()
	grant := &witness.OperatorGrant{
		Subject: "alice@example.com", DeploymentID: dep,
		Operations: []string{witness.OperationMigrate},
		NotBefore:  now.Add(-time.Minute).Format(time.RFC3339),
		ExpiresAt:  now.Add(10 * time.Minute).Format(time.RFC3339),
		Nonce:      strings.Repeat("e", 32),
	}
	if err := witness.SignOperatorGrant(authority, grant); err != nil {
		t.Fatal(err)
	}
	grantRaw, _ := json.Marshal(grant)
	grantPath := filepath.Join(dir, "grant.json")
	writeOwnerFile(t, grantPath, grantRaw)

	stdout, stderr, code := runCLI(t, bin, "migrate",
		"-outbox", outboxPath, "-effect-store", storePath, "-deployment", dep,
		"-signer-key", signerPath,
		"-custodian-trust-roots", custodianPath,
		"-kernel-trust-roots", kernelPath,
		"-repair-trust-roots", repairPath,
		"-operator-token", grantPath,
		"-witness-socket", sock,
		"-actor", "alice@example.com", "-json")
	if code != 0 {
		t.Fatalf("migrate exit=%d\nstdout=%s\nstderr=%s", code, stdout, stderr)
	}
	var out migrateOutput
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("migrate JSON: %v\n%s", err, stdout)
	}
	if out.Compensated != 2 || !out.Checkpoint {
		t.Fatalf("migrate summary = %+v", out)
	}
	if out.FenceID == "" || out.FenceEpoch < 1 || out.FenceResult == "" {
		t.Fatalf("migrate did not report a closed epoch: %+v", out)
	}

	// The epoch is closed at the witness, and the outbox chain holds
	// canonical payloads with intact linkage.
	fence, err := ledger.Fence(context.Background(), dep, out.FenceID)
	if err != nil {
		t.Fatal(err)
	}
	if fence == nil || fence.State != witness.FenceClosed {
		t.Fatalf("witness epoch state = %+v, want CLOSED", fence)
	}
	if fence.ResultDigest != out.FenceResult {
		t.Fatalf("fence result %s != reported %s", fence.ResultDigest, out.FenceResult)
	}
	o, err := witness.OpenOutbox(outboxPath)
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	if _, err := o.VerifyChain(context.Background()); err != nil {
		t.Fatalf("chain after migration: %v", err)
	}
	rows, err := o.Pending(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("outbox rows = %d", len(rows))
	}
	for _, r := range rows {
		content, err := r.Envelope.ContentBytes()
		if err != nil || len(content) == 0 {
			t.Fatalf("seq %d still holds no canonical payload", r.Seq)
		}
	}

	// After the epoch closes, the rewritten rows drain to the witness.
	client := witness.NewClient(sock)
	ctrust := custody.NewTrustSet(custody.TrustedKey{
		Role: custody.RoleCustodian, KeyID: wsigner.Fingerprint(),
		PublicKey: wsigner.PublicKey(), DeploymentID: dep,
	})
	prod := witness.Producer{DeploymentID: dep, Release: custody.ReleaseIdentity{Version: "0.55.0-rc8.3-dev"}, Signer: kernel}
	sender := witness.NewSender(client, o, dep, ctrust, nil)
	drainCtx, stopDrain := context.WithCancel(context.Background())
	defer stopDrain()
	go sender.Run(drainCtx, 10*time.Millisecond)
	deadline = time.Now().Add(10 * time.Second)
	for sender.CustodyState(context.Background()) != "HEALTHY" {
		if time.Now().After(deadline) {
			t.Fatalf("custody never reached verified readiness after the epoch closed: %s (%s)",
				sender.CustodyState(context.Background()), sender.LastError())
		}
		time.Sleep(10 * time.Millisecond)
	}
	stopDrain()
	if n, err := ledger.Records(context.Background(), dep); err != nil || n != 2 {
		t.Fatalf("custody records = %d, %v", n, err)
	}
	_ = prod

	// A second run under the same grant is a replay and must be
	// refused: the epoch it closed cannot be reopened.
	_, stderr, code = runCLI(t, bin, "migrate",
		"-outbox", outboxPath, "-effect-store", storePath, "-deployment", dep,
		"-signer-key", signerPath,
		"-custodian-trust-roots", custodianPath,
		"-kernel-trust-roots", kernelPath,
		"-repair-trust-roots", repairPath,
		"-operator-token", grantPath,
		"-witness-socket", sock,
		"-actor", "alice@example.com")
	if code != 1 || !strings.Contains(stderr, "already consumed") {
		t.Fatalf("grant replay exit=%d stderr=%s", code, stderr)
	}
}

// TestMigrateRoleSeparatedTrustRequired: the shipped binary refuses a
// configuration that cannot separate the three authorities.
func TestMigrateRoleSeparatedTrustRequired(t *testing.T) {
	bin := buildCLI(t)
	dir := t.TempDir()
	outboxPath := filepath.Join(dir, "outbox.db")
	seedLegacyOutbox(t, outboxPath, 1)
	storePath := filepath.Join(dir, "effects.db")
	db, err := idempotency.OpenSQLiteDB(storePath)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()

	kernel, _ := evidence.GenerateSigner()
	wsigner, _ := evidence.GenerateSigner()
	authority, _ := evidence.GenerateSigner()
	signerPath := filepath.Join(dir, "evidence.pem")
	pem, _ := kernel.MarshalPEM()
	writeOwnerFile(t, signerPath, pem)
	custodianPath := filepath.Join(dir, "custodian-trust.json")
	writeTrustFile(t, custodianPath, custody.RoleCustodian, "dep-cli", wsigner)
	kernelPath := filepath.Join(dir, "kernel-trust.json")
	writeTrustFile(t, kernelPath, custody.RoleKernelRelay, "dep-cli", kernel)
	repairPath := filepath.Join(dir, "repair-trust.json")
	writeTrustFile(t, repairPath, custody.RoleRepairAuthority, "dep-cli", authority)

	now := time.Now().UTC()
	grant := &witness.OperatorGrant{
		Subject: "alice@example.com", DeploymentID: "dep-cli",
		Operations: []string{witness.OperationMigrate},
		NotBefore:  now.Add(-time.Minute).Format(time.RFC3339),
		ExpiresAt:  now.Add(10 * time.Minute).Format(time.RFC3339),
		Nonce:      strings.Repeat("f", 32),
	}
	if err := witness.SignOperatorGrant(authority, grant); err != nil {
		t.Fatal(err)
	}
	grantRaw, _ := json.Marshal(grant)
	grantPath := filepath.Join(dir, "grant.json")
	writeOwnerFile(t, grantPath, grantRaw)

	// The custodian file is offered as the kernel-relay set.
	_, stderr, code := runCLI(t, bin, "migrate",
		"-outbox", outboxPath, "-effect-store", storePath, "-deployment", "dep-cli",
		"-signer-key", signerPath,
		"-custodian-trust-roots", custodianPath,
		"-kernel-trust-roots", custodianPath,
		"-repair-trust-roots", repairPath,
		"-operator-token", grantPath, "-actor", "alice@example.com")
	if code != 1 || !strings.Contains(stderr, "role-separated configuration") {
		t.Fatalf("mixed-role trust exit=%d stderr=%s", code, stderr)
	}
}
