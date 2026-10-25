package witness

// Shared test fixtures for privileged operator authority: a repair
// authority key pinned separately from the kernel-relay evidence key,
// and a signed single-use grant.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"

	"github.com/openclaw/crabbox/internal/custody"
	"github.com/openclaw/crabbox/internal/evidence"
)

func testRepairAuthority(t *testing.T, deploymentID string) (*evidence.Signer, *custody.TrustSet) {
	t.Helper()
	signer, err := evidence.GenerateSigner()
	if err != nil {
		t.Fatalf("repair authority signer: %v", err)
	}
	trust := custody.NewTrustSet(custody.TrustedKey{
		Role: custody.RoleRepairAuthority, KeyID: signer.Fingerprint(),
		PublicKey: signer.PublicKey(), DeploymentID: deploymentID,
	})
	return signer, trust
}

func testNonce(t *testing.T) string {
	t.Helper()
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("nonce: %v", err)
	}
	return hex.EncodeToString(b[:])
}

// testGrant builds and signs a grant valid from one minute ago for ten
// minutes, authorizing exactly the requested operations.
func testGrant(t *testing.T, signer *evidence.Signer, deploymentID, subject string, ops ...string) *OperatorGrant {
	t.Helper()
	now := time.Now().UTC()
	g := &OperatorGrant{
		Subject:      subject,
		DeploymentID: deploymentID,
		Operations:   ops,
		NotBefore:    now.Add(-time.Minute).Format(time.RFC3339),
		ExpiresAt:    now.Add(10 * time.Minute).Format(time.RFC3339),
		Nonce:        testNonce(t),
	}
	if err := SignOperatorGrant(signer, g); err != nil {
		t.Fatalf("sign grant: %v", err)
	}
	return g
}

// testAuth builds a grant and durably consumes its nonce, returning the
// authorization a privileged call expects.
func testAuth(t *testing.T, outbox *Outbox, signer *evidence.Signer, trust *custody.TrustSet, deploymentID, operation string) OperatorAuthorization {
	t.Helper()
	g := testGrant(t, signer, deploymentID, "alice@example.com", operation)
	if err := outbox.ConsumeOperatorNonce(context.Background(), g, operation); err != nil {
		t.Fatalf("consume nonce: %v", err)
	}
	return OperatorAuthorization{Grant: g, Trust: trust, DeploymentID: deploymentID}
}
