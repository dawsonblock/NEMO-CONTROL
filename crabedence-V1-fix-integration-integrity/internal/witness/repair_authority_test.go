package witness

// RC8.3 PR-03 — repair authority. Forensic repair requires an
// independent full-history scanner, a signed grant from a pinned
// repair-authority key, a single-use nonce, and a transactionally safe
// marker clear. Neither an AI agent nor an ordinary evidence signer can
// authorize it.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestOperatorRepairWithoutFullScannerFailsClosed(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	if err := h.outbox.MarkRepairRequired(context.Background(), "custody fork"); err != nil {
		t.Fatal(err)
	}
	authority, trust := testRepairAuthority(t, h.dep)
	auth := testAuth(t, h.outbox, authority, trust, h.dep, OperationRepair)
	err := h.sender.OperatorRepair(context.Background(), auth, "operator believes it is fixed")
	if !errors.Is(err, ErrRepairScannerUnavailable) {
		t.Fatalf("repair without a full scanner = %v, want ErrRepairScannerUnavailable", err)
	}
	if got := h.sender.CustodyState(context.Background()); got != "REPAIR_REQUIRED" {
		t.Fatalf("scanner-less repair cleared the marker: %s", got)
	}
}

func TestUnauthorizedEvidenceSignerDeniedRepair(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	h.sender.SetFullRescanScanner(func(context.Context) error { return nil })
	if err := h.outbox.MarkRepairRequired(context.Background(), "custody fork"); err != nil {
		t.Fatal(err)
	}
	// A grant signed by the ordinary kernel-relay evidence key. The
	// signature is valid; the key is not a pinned repair authority.
	g := testGrant(t, h.kernel, h.dep, "alice@example.com", OperationRepair)
	if err := h.outbox.ConsumeOperatorNonce(context.Background(), g, OperationRepair); err != nil {
		t.Fatal(err)
	}
	authority, repairTrust := testRepairAuthority(t, h.dep)
	_ = authority
	auth := OperatorAuthorization{Grant: g, Trust: repairTrust, DeploymentID: h.dep}
	err := h.sender.OperatorRepair(context.Background(), auth, "evidence signer tries to repair")
	if !errors.Is(err, ErrOperatorAuthorization) {
		t.Fatalf("ordinary evidence signer repair = %v, want ErrOperatorAuthorization", err)
	}
	// Even pinning the evidence key under the custodian role must not
	// make it a repair authority.
	auth.Trust = h.ctrust
	if err := h.sender.OperatorRepair(context.Background(), auth, "custodian key tries to repair"); !errors.Is(err, ErrOperatorAuthorization) {
		t.Fatalf("custodian-scoped key repair = %v, want ErrOperatorAuthorization", err)
	}
	if got := h.sender.CustodyState(context.Background()); got != "REPAIR_REQUIRED" {
		t.Fatalf("unauthorized repair cleared the marker: %s", got)
	}
}

func TestCallerSuppliedActorSpoofRejected(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	h.sender.SetFullRescanScanner(func(context.Context) error { return nil })
	if err := h.outbox.MarkRepairRequired(context.Background(), "custody fork"); err != nil {
		t.Fatal(err)
	}
	authority, trust := testRepairAuthority(t, h.dep)
	g := testGrant(t, authority, h.dep, "alice@example.com", OperationRepair)
	// The subject is covered by the signature. Mutating it after signing
	// must invalidate the grant — a caller cannot assert another actor.
	g.Subject = "root@example.com"
	if err := h.outbox.ConsumeOperatorNonce(context.Background(), g, OperationRepair); err != nil {
		t.Fatal(err)
	}
	err := h.sender.OperatorRepair(context.Background(), OperatorAuthorization{Grant: g, Trust: trust, DeploymentID: h.dep}, "spoofed actor")
	if !errors.Is(err, ErrOperatorAuthorization) {
		t.Fatalf("tampered subject = %v, want ErrOperatorAuthorization", err)
	}
	// And an empty authorization carries no identity at all.
	if err := h.sender.OperatorRepair(context.Background(), OperatorAuthorization{}, "no identity"); !errors.Is(err, ErrOperatorAuthorization) {
		t.Fatalf("empty authorization = %v, want ErrOperatorAuthorization", err)
	}
	if got := h.sender.CustodyState(context.Background()); got != "REPAIR_REQUIRED" {
		t.Fatalf("spoofed repair cleared the marker: %s", got)
	}
}

func TestExpiredOperatorApprovalRejected(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	h.sender.SetFullRescanScanner(func(context.Context) error { return nil })
	if err := h.outbox.MarkRepairRequired(context.Background(), "custody fork"); err != nil {
		t.Fatal(err)
	}
	authority, trust := testRepairAuthority(t, h.dep)
	now := time.Now().UTC()
	g := &OperatorGrant{
		Subject: "alice@example.com", DeploymentID: h.dep,
		Operations: []string{OperationRepair},
		NotBefore:  now.Add(-2 * time.Hour).Format(time.RFC3339),
		ExpiresAt:  now.Add(-time.Hour).Format(time.RFC3339),
		Nonce:      testNonce(t),
	}
	if err := SignOperatorGrant(authority, g); err != nil {
		t.Fatal(err)
	}
	if err := h.outbox.ConsumeOperatorNonce(context.Background(), g, OperationRepair); err != nil {
		t.Fatal(err)
	}
	err := h.sender.OperatorRepair(context.Background(), OperatorAuthorization{Grant: g, Trust: trust, DeploymentID: h.dep}, "expired grant")
	if !errors.Is(err, ErrOperatorAuthorization) || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired approval = %v, want ErrOperatorAuthorization/expired", err)
	}
	if got := h.sender.CustodyState(context.Background()); got != "REPAIR_REQUIRED" {
		t.Fatalf("expired approval cleared the marker: %s", got)
	}
}

func TestConcurrentContradictionPreventsClear(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	h.sender.SetFullRescanScanner(func(context.Context) error { return nil })
	if err := h.outbox.MarkRepairRequired(context.Background(), "fork-A"); err != nil {
		t.Fatal(err)
	}
	authority, trust := testRepairAuthority(t, h.dep)
	auth := testAuth(t, h.outbox, authority, trust, h.dep, OperationRepair)
	h.sender.repairHook = func(stage string) error {
		if stage == "after_scan" {
			// A concurrent writer lands a new contradiction while the
			// verified scan is still in flight.
			return h.outbox.MarkRepairRequired(context.Background(), "fork-B")
		}
		return nil
	}
	err := h.sender.OperatorRepair(context.Background(), auth, "stale repair")
	if !errors.Is(err, ErrStaleRepairVerification) {
		t.Fatalf("concurrent contradiction repair = %v, want ErrStaleRepairVerification", err)
	}
	st, err := h.outbox.CustodyStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.RepairReason != "fork-B" {
		t.Fatalf("marker = %q, want the concurrent contradiction preserved", st.RepairReason)
	}
	if got := h.sender.CustodyState(context.Background()); got != "REPAIR_REQUIRED" {
		t.Fatalf("stale repair cleared a newer contradiction: %s", got)
	}
}

func TestRepairGrantNonceReplayRejected(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	h.sender.SetFullRescanScanner(func(context.Context) error { return nil })
	if err := h.outbox.MarkRepairRequired(context.Background(), "fork-A"); err != nil {
		t.Fatal(err)
	}
	authority, trust := testRepairAuthority(t, h.dep)
	auth := testAuth(t, h.outbox, authority, trust, h.dep, OperationRepair)
	if err := h.sender.OperatorRepair(context.Background(), auth, "first repair"); err != nil {
		t.Fatalf("first repair: %v", err)
	}
	// The durable fence: the same grant can never be consumed twice.
	if err := h.outbox.ConsumeOperatorNonce(context.Background(), auth.Grant, OperationRepair); !errors.Is(err, ErrOperatorAuthorization) {
		t.Fatalf("replayed nonce = %v, want ErrOperatorAuthorization", err)
	}
	// Reopen a contradiction. An unconsumed grant is not live authority
	// even if its signature is valid.
	if err := h.outbox.MarkRepairRequired(context.Background(), "fork-C"); err != nil {
		t.Fatal(err)
	}
	unconsumed := testGrant(t, authority, h.dep, "alice@example.com", OperationRepair)
	err := h.sender.OperatorRepair(context.Background(), OperatorAuthorization{Grant: unconsumed, Trust: trust, DeploymentID: h.dep}, "unconsumed grant")
	if !errors.Is(err, ErrOperatorAuthorization) {
		t.Fatalf("unconsumed grant = %v, want ErrOperatorAuthorization", err)
	}
	if got := h.sender.CustodyState(context.Background()); got != "REPAIR_REQUIRED" {
		t.Fatalf("replayed grant cleared the marker: %s", got)
	}
}

func TestRepairGrantDeploymentScopeRejected(t *testing.T) {
	h := newHarness(t, true)
	defer h.cancel()
	h.sender.SetFullRescanScanner(func(context.Context) error { return nil })
	if err := h.outbox.MarkRepairRequired(context.Background(), "fork-A"); err != nil {
		t.Fatal(err)
	}
	authority, trust := testRepairAuthority(t, "other-deployment")
	g := testGrant(t, authority, "other-deployment", "alice@example.com", OperationRepair)
	if err := h.outbox.ConsumeOperatorNonce(context.Background(), g, OperationRepair); err != nil {
		t.Fatal(err)
	}
	err := h.sender.OperatorRepair(context.Background(), OperatorAuthorization{Grant: g, Trust: trust, DeploymentID: "other-deployment"}, "cross-deployment")
	if !errors.Is(err, ErrOperatorAuthorization) {
		t.Fatalf("cross-deployment grant = %v, want ErrOperatorAuthorization", err)
	}
}
