package main

// RC8.3 PR-04 — custodyctl is exercised as a subprocess, exactly as an
// operator invokes it: subcommand-first flags, bounded pagination,
// machine-readable output, dry-run, and authority failures.

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
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

func buildCLI(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "custodyctl")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=go1.26.5")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build custodyctl: %v\n%s", err, out)
	}
	return bin
}

func runCLI(t *testing.T, bin string, args ...string) (string, string, int) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if !errorsAs(err, &ee) {
			t.Fatalf("run custodyctl: %v", err)
		}
		code = ee.ExitCode()
	}
	return stdout.String(), stderr.String(), code
}

func errorsAs(err error, target **exec.ExitError) bool {
	ee, ok := err.(*exec.ExitError)
	if ok {
		*target = ee
	}
	return ok
}

func seedLegacyOutbox(t *testing.T, path string, rows int) {
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
	signer, err := evidence.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	prod := witness.Producer{
		DeploymentID: "dep-cli",
		Release:      custody.ReleaseIdentity{Version: "0.55.0-rc8.3-dev"},
		Signer:       signer,
	}
	prev := ""
	for i := 1; i <= rows; i++ {
		exec := "legacy-" + strings.Repeat("x", i%5) + "-" + time.Unix(int64(i), 0).UTC().Format("150405")
		env := custody.New(custody.FamilyReceipt, prod.DeploymentID, prod.Release, "",
			custody.Subject{EffectID: exec, ExecutionID: exec},
			custody.Sequence{Domain: custody.FamilyReceipt, Epoch: 0, Index: int64(i), PreviousCheckpointHash: prev},
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
			i, exec, "legacy", hash, string(raw), time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
		prev = hash
	}
}

func seedPayloadOutbox(t *testing.T, path string, rows int) {
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
	defer o.Close()
	signer, err := evidence.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	prod := witness.Producer{
		DeploymentID: "dep-cli",
		Release:      custody.ReleaseIdentity{Version: "0.55.0-rc8.3-dev"},
		Signer:       signer,
	}
	for i := 1; i <= rows; i++ {
		if _, err := o.Enqueue(t.Context(), prod, "exec-"+time.Unix(int64(i), 0).UTC().Format("150405.000000000"), "digest", []byte(`{"payload":true}`)); err != nil {
			t.Fatal(err)
		}
	}
}

func writeOwnerFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeTrustFile(t *testing.T, path, role, deployment string, signer *evidence.Signer) {
	t.Helper()
	doc := map[string]any{
		"version": 1,
		"keys": []map[string]any{{
			"role": role, "key_id": signer.Fingerprint(),
			"public_key":    base64.StdEncoding.EncodeToString(signer.PublicKey()),
			"deployment_id": deployment, "valid_from_index": 0, "valid_until_index": 0,
		}},
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	writeOwnerFile(t, path, raw)
}

func TestPreflightSubcommandFlagsAndJSON(t *testing.T) {
	bin := buildCLI(t)
	path := filepath.Join(t.TempDir(), "outbox.db")
	seedLegacyOutbox(t, path, 2)

	stdout, stderr, code := runCLI(t, bin, "preflight", "-outbox", path, "-json")
	if code != 3 {
		t.Fatalf("preflight exit = %d, want 3 (migration pending)\nstdout=%s\nstderr=%s", code, stdout, stderr)
	}
	var out preflightOutput
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("preflight JSON: %v\n%s", err, stdout)
	}
	if out.LegacyCount != 2 || out.UnackedCount != 2 || !out.MigrationPending {
		t.Fatalf("preflight summary = %+v", out)
	}
	if len(out.Rows) != 2 {
		t.Fatalf("preflight rows = %d, want 2", len(out.Rows))
	}
}

func TestInspectPaginationBounded(t *testing.T) {
	bin := buildCLI(t)
	path := filepath.Join(t.TempDir(), "outbox.db")
	seedPayloadOutbox(t, path, 250)

	stdout, stderr, code := runCLI(t, bin, "inspect", "-outbox", path, "-page-size", "100", "-limit", "150", "-json")
	if code != 0 {
		t.Fatalf("inspect exit = %d\nstdout=%s\nstderr=%s", code, stdout, stderr)
	}
	var out inspectOutput
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("inspect JSON: %v\n%s", err, stdout)
	}
	if len(out.Rows) != 150 {
		t.Fatalf("inspect rendered %d rows, want 150", len(out.Rows))
	}
	if out.NextCursor != 150 || !out.HasMore {
		t.Fatalf("pagination = cursor %d has_more %v, want 150/true", out.NextCursor, out.HasMore)
	}
}

func TestMigrateDryRunDoesNotMutate(t *testing.T) {
	bin := buildCLI(t)
	dir := t.TempDir()
	outboxPath := filepath.Join(dir, "outbox.db")
	seedLegacyOutbox(t, outboxPath, 1)
	storePath := filepath.Join(dir, "effects.db")
	db, err := idempotency.OpenSQLiteDB(storePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := idempotency.NewSQLiteStore(db); err != nil {
		t.Fatal(err)
	}
	db.Close()

	evidenceSigner, err := evidence.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	authority, err := evidence.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	signerPath := filepath.Join(dir, "evidence.pem")
	pem, err := evidenceSigner.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	writeOwnerFile(t, signerPath, pem)
	trustPath := filepath.Join(dir, "custodian-trust.json")
	writeTrustFile(t, trustPath, custody.RoleCustodian, "dep-cli", authority)
	repairTrustPath := filepath.Join(dir, "repair-trust.json")
	writeTrustFile(t, repairTrustPath, custody.RoleRepairAuthority, "dep-cli", authority)
	now := time.Now().UTC()
	grant := &witness.OperatorGrant{
		Subject: "alice@example.com", DeploymentID: "dep-cli",
		Operations: []string{witness.OperationMigrate},
		NotBefore:  now.Add(-time.Minute).Format(time.RFC3339),
		ExpiresAt:  now.Add(10 * time.Minute).Format(time.RFC3339),
		Nonce:      strings.Repeat("a", 32),
	}
	if err := witness.SignOperatorGrant(authority, grant); err != nil {
		t.Fatal(err)
	}
	grantRaw, _ := json.Marshal(grant)
	grantPath := filepath.Join(dir, "grant.json")
	writeOwnerFile(t, grantPath, grantRaw)

	stdout, stderr, code := runCLI(t, bin, "migrate",
		"-outbox", outboxPath, "-effect-store", storePath, "-deployment", "dep-cli",
		"-signer-key", signerPath, "-trust-roots", trustPath,
		"-repair-trust-roots", repairTrustPath, "-operator-token", grantPath,
		"-actor", "alice@example.com", "-dry-run", "-json")
	// Dry-run reports the quarantine it would perform (exit 3 = pending
	// forensic action) without mutating anything.
	if code != 3 {
		t.Fatalf("migrate dry-run exit = %d, want 3\nstdout=%s\nstderr=%s", code, stdout, stderr)
	}
	var out migrateOutput
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("migrate JSON: %v\n%s", err, stdout)
	}
	if !out.DryRun {
		t.Fatal("migrate output does not mark dry-run")
	}
	// The legacy row is still empty and no journal entry was written.
	o, err := witness.OpenOutbox(outboxPath)
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	legacy, err := o.LegacyRows(t.Context())
	if err != nil || len(legacy) != 1 {
		t.Fatalf("dry-run mutated the outbox: %+v, %v", legacy, err)
	}
	journal, err := o.MigrationJournal(t.Context())
	if err != nil || len(journal) != 0 {
		t.Fatalf("dry-run wrote a journal entry: %+v, %v", journal, err)
	}
}

func TestRepairAuthorityRequired(t *testing.T) {
	bin := buildCLI(t)
	dir := t.TempDir()
	outboxPath := filepath.Join(dir, "outbox.db")
	seedLegacyOutbox(t, outboxPath, 0)
	storePath := filepath.Join(dir, "effects.db")
	db, err := idempotency.OpenSQLiteDB(storePath)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	evidenceSigner, _ := evidence.GenerateSigner()
	authority, _ := evidence.GenerateSigner()
	signerPath := filepath.Join(dir, "evidence.pem")
	pem, _ := evidenceSigner.MarshalPEM()
	writeOwnerFile(t, signerPath, pem)
	trustPath := filepath.Join(dir, "custodian-trust.json")
	writeTrustFile(t, trustPath, custody.RoleCustodian, "dep-cli", authority)
	repairTrustPath := filepath.Join(dir, "repair-trust.json")
	writeTrustFile(t, repairTrustPath, custody.RoleRepairAuthority, "dep-cli", authority)

	_, stderr, code := runCLI(t, bin, "repair",
		"-outbox", outboxPath, "-effect-store", storePath, "-deployment", "dep-cli",
		"-signer-key", signerPath, "-trust-roots", trustPath,
		"-repair-trust-roots", repairTrustPath, "-reason", "test")
	if code != 1 || !strings.Contains(stderr, "operator grant required") {
		t.Fatalf("repair without grant exit=%d stderr=%s", code, stderr)
	}

	now := time.Now().UTC()
	grant := &witness.OperatorGrant{
		Subject: "alice@example.com", DeploymentID: "dep-cli",
		Operations: []string{witness.OperationRepair},
		NotBefore:  now.Add(-time.Minute).Format(time.RFC3339),
		ExpiresAt:  now.Add(10 * time.Minute).Format(time.RFC3339),
		Nonce:      strings.Repeat("b", 32),
	}
	if err := witness.SignOperatorGrant(authority, grant); err != nil {
		t.Fatal(err)
	}
	grantRaw, _ := json.Marshal(grant)
	grantPath := filepath.Join(dir, "grant.json")
	writeOwnerFile(t, grantPath, grantRaw)

	// A caller-supplied actor that disagrees with the signed subject is
	// refused before any scan.
	_, stderr, code = runCLI(t, bin, "repair",
		"-outbox", outboxPath, "-effect-store", storePath, "-deployment", "dep-cli",
		"-signer-key", signerPath, "-trust-roots", trustPath,
		"-repair-trust-roots", repairTrustPath, "-operator-token", grantPath,
		"-actor", "mallory@example.com", "-reason", "test")
	if code != 1 || !strings.Contains(stderr, "does not match the signed grant subject") {
		t.Fatalf("actor spoof exit=%d stderr=%s", code, stderr)
	}

	// Valid authority but no witness transport: repair must refuse.
	_, stderr, code = runCLI(t, bin, "repair",
		"-outbox", outboxPath, "-effect-store", storePath, "-deployment", "dep-cli",
		"-signer-key", signerPath, "-trust-roots", trustPath,
		"-repair-trust-roots", repairTrustPath, "-operator-token", grantPath,
		"-actor", "alice@example.com", "-reason", "test")
	if code != 1 || !strings.Contains(stderr, "requires -witness-socket or -witness-tls") {
		t.Fatalf("repair without witness exit=%d stderr=%s", code, stderr)
	}
}
