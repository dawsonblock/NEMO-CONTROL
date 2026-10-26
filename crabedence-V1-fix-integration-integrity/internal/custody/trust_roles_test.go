package custody

// RC8.3 PR-04 — role-separated trust roots. Custodian, kernel-relay,
// and repair-authority keys are three authorities; a configuration that
// lets one file or one key hold more than one of them collapses the
// distinction the custody boundary exists to preserve.

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/openclaw/crabbox/internal/evidence"
)

func writeRoleFile(t *testing.T, path string, keys ...TrustedKey) {
	t.Helper()
	type keyFile struct {
		Role           string `json:"role"`
		KeyID          string `json:"key_id"`
		PublicKey      string `json:"public_key"`
		DeploymentID   string `json:"deployment_id,omitempty"`
		ValidFromIndex int64  `json:"valid_from_index"`
		ValidUntil     int64  `json:"valid_until_index"`
	}
	doc := struct {
		Version int       `json:"version"`
		Keys    []keyFile `json:"keys"`
	}{Version: 1}
	for _, k := range keys {
		doc.Keys = append(doc.Keys, keyFile{
			Role: k.Role, KeyID: k.KeyID,
			PublicKey:      base64.StdEncoding.EncodeToString(k.PublicKey),
			DeploymentID:   k.DeploymentID,
			ValidFromIndex: k.ValidFromIndex,
			ValidUntil:     k.ValidUntilIndex,
		})
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadTrustSetForRoleRefusesMixedFile(t *testing.T) {
	dir := t.TempDir()
	custodian, _ := evidence.GenerateSigner()
	kernel, _ := evidence.GenerateSigner()
	path := filepath.Join(dir, "mixed.json")
	writeRoleFile(t, path,
		TrustedKey{Role: RoleCustodian, KeyID: custodian.Fingerprint(), PublicKey: custodian.PublicKey(), DeploymentID: "dep-a"},
		TrustedKey{Role: RoleKernelRelay, KeyID: kernel.Fingerprint(), PublicKey: kernel.PublicKey(), DeploymentID: "dep-a"},
	)
	if _, err := LoadTrustSetForRole(path, RoleCustodian); err == nil {
		t.Fatal("a mixed trust file was accepted as the custodian set")
	}
	if _, err := LoadTrustSetForRole(path, RoleKernelRelay); err == nil {
		t.Fatal("a mixed trust file was accepted as the kernel-relay set")
	}
}

func TestLoadTrustSetForRoleAcceptsSingleRole(t *testing.T) {
	dir := t.TempDir()
	custodian, _ := evidence.GenerateSigner()
	path := filepath.Join(dir, "custodian.json")
	writeRoleFile(t, path,
		TrustedKey{Role: RoleCustodian, KeyID: custodian.Fingerprint(), PublicKey: custodian.PublicKey(), DeploymentID: "dep-a"},
	)
	set, err := LoadTrustSetForRole(path, RoleCustodian)
	if err != nil {
		t.Fatalf("single-role trust file: %v", err)
	}
	if err := set.RequireRole(RoleCustodian); err != nil {
		t.Fatalf("role check: %v", err)
	}
}

func TestCheckDisjointRolesRefusesSharedKey(t *testing.T) {
	shared, _ := evidence.GenerateSigner()
	custodianSet := NewTrustSet(TrustedKey{
		Role: RoleCustodian, KeyID: shared.Fingerprint(), PublicKey: shared.PublicKey(), DeploymentID: "dep-a",
	})
	repairSet := NewTrustSet(TrustedKey{
		Role: RoleRepairAuthority, KeyID: shared.Fingerprint(), PublicKey: shared.PublicKey(), DeploymentID: "dep-a",
	})
	if err := CheckDisjointRoles(map[string]*TrustSet{"custodian": custodianSet, "repair-authority": repairSet}); err == nil {
		t.Fatal("one key pinned as custodian and repair authority was accepted")
	}

	other, _ := evidence.GenerateSigner()
	separate := NewTrustSet(TrustedKey{
		Role: RoleRepairAuthority, KeyID: other.Fingerprint(), PublicKey: other.PublicKey(), DeploymentID: "dep-a",
	})
	if err := CheckDisjointRoles(map[string]*TrustSet{"custodian": custodianSet, "repair-authority": separate}); err != nil {
		t.Fatalf("distinct keys were refused: %v", err)
	}
}

// TestRolesCannotCrossVerify is the runtime half of role separation: a
// key pinned for one role never resolves for another, even when the
// caller asks for it explicitly.
func TestRolesCannotCrossVerify(t *testing.T) {
	custodian, _ := evidence.GenerateSigner()
	set := NewTrustSet(TrustedKey{
		Role: RoleCustodian, KeyID: custodian.Fingerprint(), PublicKey: custodian.PublicKey(), DeploymentID: "dep-a",
	})
	if _, err := set.ResolveAny(RoleKernelRelay, "dep-a", custodian.Fingerprint()); err == nil {
		t.Fatal("a custodian key resolved as a kernel-relay key")
	}
	if _, err := set.ResolveAny(RoleRepairAuthority, "dep-a", custodian.Fingerprint()); err == nil {
		t.Fatal("a custodian key resolved as a repair authority")
	}
}

func TestValidateRoleSeparationRefusesDualRoleKey(t *testing.T) {
	shared, _ := evidence.GenerateSigner()
	set := NewTrustSet(
		TrustedKey{Role: RoleCustodian, KeyID: shared.Fingerprint(), PublicKey: shared.PublicKey(), DeploymentID: "dep-a"},
		TrustedKey{Role: RoleKernelRelay, KeyID: shared.Fingerprint(), PublicKey: shared.PublicKey(), DeploymentID: "dep-a"},
	)
	if err := set.ValidateRoleSeparation(); err == nil {
		t.Fatal("a key pinned under two roles passed role separation")
	}
	if got := set.Roles(); len(got) != 2 {
		t.Fatalf("roles = %v", got)
	}
}
