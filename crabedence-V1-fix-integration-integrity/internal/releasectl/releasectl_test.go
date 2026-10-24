package releasectl

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openclaw/crabbox/internal/evidence"
)

func newSigner(t *testing.T) *evidence.Signer {
	t.Helper()
	s, err := evidence.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func trusted(fp string) map[string]bool { return map[string]bool{fp: true} }

func TestHaltDeniesAndResumeRestores(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "control")
	op := newSigner(t)
	if denial := Check(dir, "1.0.0", trusted(op.Fingerprint()), false); denial != "" {
		t.Fatalf("unexpected denial before halt: %s", denial)
	}
	rec, err := Issue(op, ActionHalt, "", "", "incident-42", "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := Halt(dir, rec); err != nil {
		t.Fatal(err)
	}
	denial := Check(dir, "1.0.0", trusted(op.Fingerprint()), false)
	if denial == "" || !strings.Contains(denial, "incident-42") {
		t.Fatalf("halt not enforced: %q", denial)
	}
	if err := Resume(dir); err != nil {
		t.Fatal(err)
	}
	if denial := Check(dir, "1.0.0", trusted(op.Fingerprint()), false); denial != "" {
		t.Fatalf("denial after resume: %s", denial)
	}
}

func TestRevokeIsReleaseScoped(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "control")
	op := newSigner(t)
	rec, err := Issue(op, ActionRevoke, "1.0.0-bad", "", "bad evidence", "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := Revoke(dir, "1.0.0-bad", rec); err != nil {
		t.Fatal(err)
	}
	if denial := Check(dir, "1.0.0-bad", trusted(op.Fingerprint()), false); denial == "" {
		t.Fatal("revoked release not denied")
	}
	// A different release identity is unaffected — revocation is scoped.
	if denial := Check(dir, "1.0.0-good", trusted(op.Fingerprint()), false); denial != "" {
		t.Fatalf("unrelated release denied: %s", denial)
	}
	if err := Unrevoke(dir, "1.0.0-bad"); err != nil {
		t.Fatal(err)
	}
	if denial := Check(dir, "1.0.0-bad", trusted(op.Fingerprint()), false); denial != "" {
		t.Fatalf("denial after unrevoke: %s", denial)
	}
}

func TestForgedAndForeignRecordsFailClosed(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "control")
	op := newSigner(t)
	foreign := newSigner(t)

	// A record signed by a key not in the operator trust root.
	rec, _ := Issue(foreign, ActionHalt, "", "", "foreign halt", "mallory@example.com")
	if err := Halt(dir, rec); err != nil {
		t.Fatal(err)
	}
	denial := Check(dir, "1.0.0", trusted(op.Fingerprint()), false)
	if !strings.Contains(denial, "untrusted") {
		t.Fatalf("foreign-signed halt: want untrusted denial, got %q", denial)
	}

	// Tampered record — signature no longer covers the payload.
	rec, _ = Issue(op, ActionHalt, "", "", "real reason", "alice@example.com")
	rec.Reason = "forged reason"
	path := filepath.Join(dir, "halt.json")
	if err := Write(path, rec); err != nil {
		t.Fatal(err)
	}
	if denial := Check(dir, "1.0.0", trusted(op.Fingerprint()), false); !strings.Contains(denial, "fail closed") {
		t.Fatalf("tampered halt: want fail-closed denial, got %q", denial)
	}

	// Malformed bytes — deny rather than treat as absent.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if denial := Check(dir, "1.0.0", trusted(op.Fingerprint()), false); denial == "" {
		t.Fatal("corrupt halt record did not fail closed")
	}
}

func TestRecordsRequireReasonAndRelease(t *testing.T) {
	op := newSigner(t)
	if _, err := Issue(op, ActionHalt, "", "", "", "a"); err == nil {
		t.Fatal("halt without reason issued")
	}
	if _, err := Issue(op, ActionRevoke, "", "", "r", "a"); err == nil {
		t.Fatal("revoke without release issued")
	}
}

func TestStageGateRequiresSignedPromotion(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "control")
	op := newSigner(t)
	trust := trusted(op.Fingerprint())

	// requireStage on, no record → admission denied: promotion must be
	// an explicit operator act, not an absence of prohibition.
	if denial := Check(dir, "2.0.0", trust, true); !strings.Contains(denial, "no signed rollout stage") {
		t.Fatalf("unstaged release: want promotion denial, got %q", denial)
	}
	// Same check with the gate off stays open.
	if denial := Check(dir, "2.0.0", trust, false); denial != "" {
		t.Fatalf("gate-off check denied: %s", denial)
	}
	rec, err := Issue(op, ActionStage, "2.0.0", StageCanary, "5% canary", "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := SetStage(dir, "2.0.0", rec); err != nil {
		t.Fatal(err)
	}
	if denial := Check(dir, "2.0.0", trust, true); denial != "" {
		t.Fatalf("staged release denied: %s", denial)
	}
	// A foreign-signed stage record fails closed.
	foreign := newSigner(t)
	rec, _ = Issue(foreign, ActionStage, "2.0.0", StageFull, "rush it", "mallory@example.com")
	if err := SetStage(dir, "2.0.0", rec); err != nil {
		t.Fatal(err)
	}
	if denial := Check(dir, "2.0.0", trust, true); !strings.Contains(denial, "untrusted") {
		t.Fatalf("foreign stage record: want untrusted denial, got %q", denial)
	}
	// Invalid stage values are refused at issue.
	if _, err := Issue(op, ActionStage, "2.0.0", "bogus", "r", "a"); err == nil {
		t.Fatal("invalid stage issued")
	}
}

func TestIssueVerifyRoundtrip(t *testing.T) {
	op := newSigner(t)
	rec, err := Issue(op, ActionRevoke, "2.0.0", "", "supply-chain advisory", "ops@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(rec, trusted(op.Fingerprint())); err != nil {
		t.Fatalf("valid record failed verify: %v", err)
	}
	// Swapped-in foreign key embedded in the record must not verify.
	other := newSigner(t)
	rec.PublicKey = rec.PublicKey[:4] + rec.PublicKey[4:]
	rec.Signer = other.Fingerprint()
	if err := Verify(rec, trusted(other.Fingerprint())); err == nil {
		t.Fatal("record with mismatched signer/public_key verified")
	}
}
