package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/openclaw/crabbox/internal/idempotency"
)

// seedUnknownRecord drives a record to UNKNOWN in a fresh sqlite store —
// the same lifecycle the dispatcher walks (acquire, begin, in-flight,
// ambiguous outcome → recovery), without standing a service up.
func seedUnknownRecord(t *testing.T, storePath string) (executionID string, version int) {
	t.Helper()
	ctx := context.Background()
	db, err := idempotency.OpenSQLiteDB(storePath)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()
	store, err := idempotency.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	digest := strings.Repeat("ab", 32)
	acq, err := store.Acquire(ctx, "key-1", "alice@example.com", "test.mut", digest, "", "MUTATION", 5*time.Minute)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	executionID = acq.Record.ExecutionID
	if err := store.BeginExecution(ctx, executionID, acq.LeaseToken, acq.Generation); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := store.MarkInFlight(ctx, executionID, acq.LeaseToken, acq.Generation, "prov-a",
		json.RawMessage(`{"v":1,"provider_id":"prov-a","strategy":"idempotency-token","external_token":"tok-1"}`)); err != nil {
		t.Fatalf("mark in flight: %v", err)
	}
	rec, err := store.Lookup(ctx, executionID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if err := store.EnterRecovery(ctx, executionID, idempotency.StateInFlight, rec.Version); err != nil {
		t.Fatalf("enter recovery: %v", err)
	}
	rec, err = store.Lookup(ctx, executionID)
	if err != nil {
		t.Fatalf("lookup after recovery: %v", err)
	}
	if rec.State != idempotency.StateUnknown {
		t.Fatalf("seeded state = %s, want UNKNOWN", rec.State)
	}
	return executionID, rec.Version
}

func recoveryTestEnv(t *testing.T) (storePath string) {
	t.Helper()
	// The durable ledger demands its directory be 0700; t.TempDir() is
	// 0755, so the store lives one level down under a tightened dir.
	dir := filepath.Join(t.TempDir(), "store")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	storePath = filepath.Join(dir, "crabedence.db")
	t.Setenv("CRABEDENCE_STORE_BACKEND", "sqlite")
	t.Setenv("CRABEDENCE_STORE_PATH", storePath)
	t.Setenv("CRABEDENCE_DATABASE_URL", "")
	t.Setenv("CRABBOX_EVIDENCE_TRUSTED_SIGNERS", "")
	return storePath
}

func runRecoveryApp(args ...string) (stdout, stderr string, err error) {
	var out, errBuf bytes.Buffer
	err = (App{Stdout: &out, Stderr: &errBuf}).Run(context.Background(), args)
	return out.String(), errBuf.String(), err
}

func openSeededStore(t *testing.T, storePath string) *idempotency.SQLiteStore {
	t.Helper()
	db, err := idempotency.OpenSQLiteDB(storePath)
	if err != nil {
		t.Fatalf("reopen sqlite: %v", err)
	}
	store, err := idempotency.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return store
}

func TestRecoveryListEmpty(t *testing.T) {
	recoveryTestEnv(t)
	stdout, _, err := runRecoveryApp("recovery", "list")
	if err != nil {
		t.Fatalf("recovery list: %v", err)
	}
	if !strings.Contains(stdout, "no UNKNOWN") {
		t.Fatalf("expected empty-list message, got %q", stdout)
	}
}

func TestRecoveryListShowsUnknown(t *testing.T) {
	storePath := recoveryTestEnv(t)
	execID, _ := seedUnknownRecord(t, storePath)

	stdout, _, err := runRecoveryApp("recovery", "list")
	if err != nil {
		t.Fatalf("recovery list: %v", err)
	}
	for _, want := range []string{execID, "test.mut", "alice@example.com", "MUTATION"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("list output missing %q:\n%s", want, stdout)
		}
	}
}

func TestRecoveryShowUnknownRecord(t *testing.T) {
	storePath := recoveryTestEnv(t)
	execID, _ := seedUnknownRecord(t, storePath)

	stdout, stderr, err := runRecoveryApp("recovery", "show", execID)
	if err != nil {
		t.Fatalf("recovery show: %v", err)
	}
	for _, want := range []string{execID, `"state": "UNKNOWN"`, "recovery_locator", "tok-1"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("show output missing %q:\n%s", want, stdout)
		}
	}
	if strings.Contains(stderr, "not UNKNOWN") {
		t.Errorf("unexpected not-UNKNOWN note for an UNKNOWN record: %s", stderr)
	}
}

func TestRecoveryResolveCommitted(t *testing.T) {
	storePath := recoveryTestEnv(t)
	execID, version := seedUnknownRecord(t, storePath)

	evidence := filepath.Join(t.TempDir(), "attestation.json")
	evidenceBytes := []byte(`{"operator":"ops@example.com","verified":"provider console shows run tok-1 committed","at":"2026-10-23T00:00:00Z"}`)
	if err := os.WriteFile(evidence, evidenceBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	wantSHA := sha256.Sum256(evidenceBytes)

	stdout, _, err := runRecoveryApp("recovery", "resolve", execID,
		"--expected-version", strconv.Itoa(version), "--decision", "committed",
		"--provider-id", "prov-a", "--provider-run-id", "tok-1",
		"--result", `{"state":"done"}`, "--evidence", evidence)
	if err != nil {
		t.Fatalf("recovery resolve: %v", err)
	}
	if !strings.Contains(stdout, "resolved COMMITTED") {
		t.Fatalf("expected resolution confirmation, got %q", stdout)
	}

	store := openSeededStore(t, storePath)
	rec, err := store.Lookup(context.Background(), execID)
	if err != nil {
		t.Fatalf("lookup resolved: %v", err)
	}
	if rec.State != idempotency.StateCommitted {
		t.Fatalf("state = %s, want COMMITTED", rec.State)
	}
	if rec.TerminalEvidenceDigest != hex.EncodeToString(wantSHA[:]) {
		t.Errorf("terminal_evidence_digest = %q, want sha256(evidence) %q",
			rec.TerminalEvidenceDigest, hex.EncodeToString(wantSHA[:]))
	}
	if string(rec.Result) != `{"state":"done"}` {
		t.Errorf("result = %s, want the asserted terminal result", rec.Result)
	}
}

func TestRecoveryResolveStaleVersionFails(t *testing.T) {
	storePath := recoveryTestEnv(t)
	execID, version := seedUnknownRecord(t, storePath)

	evidence := filepath.Join(t.TempDir(), "attestation.json")
	if err := os.WriteFile(evidence, []byte(`{"operator":"ops@example.com"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := runRecoveryApp("recovery", "resolve", execID,
		"--expected-version", strconv.Itoa(version+99), "--decision", "committed", "--evidence", evidence)
	if err == nil || !strings.Contains(err.Error(), "CAS failed") {
		t.Fatalf("expected CAS conflict for a stale version, got %v", err)
	}

	store := openSeededStore(t, storePath)
	rec, err := store.Lookup(context.Background(), execID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if rec.State != idempotency.StateUnknown {
		t.Fatalf("failed resolve must leave the record UNKNOWN, got %s", rec.State)
	}
}

func TestRecoveryResolveNonUnknownFails(t *testing.T) {
	storePath := recoveryTestEnv(t)
	execID, version := seedUnknownRecord(t, storePath)

	evidence := filepath.Join(t.TempDir(), "attestation.json")
	if err := os.WriteFile(evidence, []byte(`{"operator":"ops@example.com"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runRecoveryApp("recovery", "resolve", execID,
		"--expected-version", strconv.Itoa(version), "--decision", "committed", "--evidence", evidence); err != nil {
		t.Fatalf("first resolve: %v", err)
	}

	store := openSeededStore(t, storePath)
	rec, err := store.Lookup(context.Background(), execID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	_, _, err = runRecoveryApp("recovery", "resolve", execID,
		"--expected-version", strconv.Itoa(rec.Version), "--decision", "failed", "--evidence", evidence)
	if err == nil {
		t.Fatal("resolving a COMMITTED record must fail — terminal states are final")
	}
}

func TestRecoveryResolveEmptyEvidenceRefused(t *testing.T) {
	storePath := recoveryTestEnv(t)
	execID, version := seedUnknownRecord(t, storePath)

	evidence := filepath.Join(t.TempDir(), "empty.json")
	if err := os.WriteFile(evidence, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := runRecoveryApp("recovery", "resolve", execID,
		"--expected-version", strconv.Itoa(version), "--decision", "committed", "--evidence", evidence)
	if err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("empty evidence must be refused before touching the store, got %v", err)
	}
}

func TestRecoveryAdvanceEpochAndComplete(t *testing.T) {
	recoveryTestEnv(t)
	storePath := os.Getenv("CRABEDENCE_STORE_PATH")

	// Seed the store so the epoch row exists before the operator acts.
	openSeededStore(t, storePath)

	stdout, _, err := runRecoveryApp("recovery", "advance-epoch", "--expected", "1", "--reason", "restored from 2026-10-22 snapshot")
	if err != nil {
		t.Fatalf("advance-epoch: %v", err)
	}
	if !strings.Contains(stdout, "epoch advanced to 2") {
		t.Fatalf("expected epoch advance confirmation, got %q", stdout)
	}

	// While recovery mode is declared the list command warns operators.
	_, stderr, err := runRecoveryApp("recovery", "list")
	if err != nil {
		t.Fatalf("list during recovery mode: %v", err)
	}
	if !strings.Contains(stderr, "recovery mode") {
		t.Fatalf("expected recovery-mode warning, got %q", stderr)
	}

	// A stale expected epoch cannot clear the mode.
	_, _, err = runRecoveryApp("recovery", "complete", "--expected", "1", "--resolution", "premature")
	if err == nil || !strings.Contains(err.Error(), "epoch") {
		t.Fatalf("stale complete must fail with an epoch error, got %v", err)
	}

	stdout, _, err = runRecoveryApp("recovery", "complete", "--expected", "2", "--resolution", "backlog reconciled manually")
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if !strings.Contains(stdout, "recovery mode cleared") {
		t.Fatalf("expected clear confirmation, got %q", stdout)
	}
}
