package custody

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/openclaw/crabbox/internal/evidence"
	"github.com/openclaw/crabbox/internal/sockfile"
)

// RotationDomain separates key-rotation authorizations from every other
// signed record — a rotation record can never be presented as evidence.
const RotationDomain = "custody-key-rotation-v1\x00"

// TrustedKey is one pinned verification key. Keys are resolved by role
// and key_id, optionally scoped to a deployment, and bounded to a
// sequence-index window: a retired key verifies only for indexes below
// its rotation point, so post-rotation forgeries under the old key are
// refused even though historical records still verify.
type TrustedKey struct {
	Role           string
	KeyID          string // evidence.Fingerprint of PublicKey
	PublicKey      ed25519.PublicKey
	DeploymentID   string // "" = unscoped (development posture)
	ValidFromIndex int64
	// ValidUntilIndex bounds the window closed at the rotation point;
	// 0 means unbounded.
	ValidUntilIndex int64
}

// ValidAt reports whether index falls inside the key's window.
func (k TrustedKey) ValidAt(index int64) bool {
	return index >= k.ValidFromIndex && (k.ValidUntilIndex == 0 || index <= k.ValidUntilIndex)
}

// TrustSet is the externally administered pinned-key set for envelope
// verification. Keys are resolved only from this set — never from
// records, acknowledgements, or untrusted storage. An empty set fails
// closed: every record is unverifiable.
type TrustSet struct {
	keys []TrustedKey
}

// NewTrustSet builds a trust set over explicit keys. Keys with
// ValidFromIndex > 0 are rotation successors; use LoadTrustSet for the
// rotation-authorization check, or add authorized keys with
// AddAuthorized.
func NewTrustSet(keys ...TrustedKey) *TrustSet {
	t := &TrustSet{}
	for _, k := range keys {
		k.KeyID = strings.ToLower(strings.TrimSpace(k.KeyID))
		t.keys = append(t.keys, k)
	}
	return t
}

// Empty reports whether the set pins no key — verification over an
// empty set must refuse every record.
func (t *TrustSet) Empty() bool { return t == nil || len(t.keys) == 0 }

// Keys returns the pinned keys (for inspection/tests).
func (t *TrustSet) Keys() []TrustedKey {
	out := make([]TrustedKey, len(t.keys))
	copy(out, t.keys)
	return out
}

// Roles returns the distinct roles the set pins, sorted.
func (t *TrustSet) Roles() []string {
	seen := map[string]bool{}
	var out []string
	for _, k := range t.keys {
		if !seen[k.Role] {
			seen[k.Role] = true
			out = append(out, k.Role)
		}
	}
	sort.Strings(out)
	return out
}

// RequireRole refuses a set that pins any key outside role. Custodian,
// kernel-relay, and repair-authority keys are three authorities; a set
// that mixes them lets one administrative file authorize three
// different acts, which is exactly the confusion role separation
// exists to prevent.
func (t *TrustSet) RequireRole(role string) error {
	if t.Empty() {
		return fmt.Errorf("trust set pins no key — an empty set verifies nothing")
	}
	for _, k := range t.keys {
		if k.Role != role {
			return fmt.Errorf("trust set pins a %s key (%s) but is configured as the %s set — role-separated configuration requires one role per trust root", k.Role, k.KeyID, role)
		}
	}
	return nil
}

// ValidateRoleSeparation refuses a set that pins one key under more
// than one role. A single key trusted for two roles collapses the
// distinction between "the custodian attests" and "the kernel attests".
func (t *TrustSet) ValidateRoleSeparation() error {
	roles := map[string][]string{}
	for _, k := range t.keys {
		roles[k.KeyID] = append(roles[k.KeyID], k.Role)
	}
	for keyID, rs := range roles {
		if len(rs) < 2 {
			continue
		}
		sort.Strings(rs)
		distinct := rs[0]
		for _, r := range rs[1:] {
			if r != distinct {
				return fmt.Errorf("key %s is pinned under %v — one key cannot hold two authorities", keyID, rs)
			}
		}
	}
	return nil
}

// CheckDisjointRoles refuses trust sets that share a key across roles.
// Role separation is a property of the whole custody configuration, not
// of one file: pinning the same key as custodian in one file and
// repair authority in another is the same collapse.
func CheckDisjointRoles(sets map[string]*TrustSet) error {
	owners := map[string][]string{}
	for name, set := range sets {
		if set == nil {
			continue
		}
		for _, k := range set.keys {
			owners[k.KeyID] = append(owners[k.KeyID], name+"/"+k.Role)
		}
	}
	for keyID, names := range owners {
		if len(names) < 2 {
			continue
		}
		sort.Strings(names)
		return fmt.Errorf("key %s is pinned for %v — kernel-relay, custodian, and repair authorities must be distinct keys in distinct trust roots", keyID, names)
	}
	return nil
}

// LoadTrustSetForRole loads a trust file and enforces that it pins only
// keys of the expected role. This is the role-separated loader: the
// custodian set, the kernel-relay set, and the repair-authority set are
// three files, each of which may only name its own authority.
func LoadTrustSetForRole(path, role string) (*TrustSet, error) {
	switch role {
	case RoleCustodian, RoleKernelRelay, RoleRepairAuthority:
	default:
		return nil, fmt.Errorf("unknown trust role %q", role)
	}
	set, err := LoadTrustSet(path)
	if err != nil {
		return nil, err
	}
	if err := set.RequireRole(role); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := set.ValidateRoleSeparation(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return set, nil
}

// Resolve returns the pinned public key for (role, key_id) valid at the
// record's sequence index and scoped to the deployment. Deployment-
// scoped keys never resolve for another deployment; exactly one key may
// resolve — an ambiguous window is a configuration fault, not a choice.
func (t *TrustSet) Resolve(role, deploymentID, keyID string, index int64) (ed25519.PublicKey, error) {
	if t.Empty() {
		return nil, fmt.Errorf("%w: empty trust set — no record is verifiable", ErrUntrustedKey)
	}
	keyID = strings.ToLower(strings.TrimSpace(keyID))
	var found *TrustedKey
	matches := 0
	for i := range t.keys {
		k := &t.keys[i]
		if k.Role != role || k.KeyID != keyID {
			continue
		}
		if k.DeploymentID != "" && k.DeploymentID != deploymentID {
			continue
		}
		if !k.ValidAt(index) {
			continue
		}
		found = k
		matches++
	}
	if matches == 0 {
		return nil, fmt.Errorf("%w: no pinned %s key %s valid at index %d for deployment %q", ErrUntrustedKey, role, keyID, index, deploymentID)
	}
	if matches > 1 {
		return nil, fmt.Errorf("%w: %d pinned keys claim %s/%s at index %d — ambiguous trust window", ErrUntrustedKey, matches, role, keyID, index)
	}
	return found.PublicKey, nil
}

// ResolveCurrent answers "is this key authorized now" — used for live
// reports (checkpoint heads), which are statements at report time, not
// record attestations at a sequence index. A retired key fails here:
// its window has closed, so it cannot sign new reports; a key whose
// window has not yet opened also fails.
func (t *TrustSet) ResolveCurrent(role, deploymentID, keyID string) (ed25519.PublicKey, error) {
	return t.Resolve(role, deploymentID, keyID, 1<<62)
}

// ResolveAny returns the pinned key for (role, key_id) scoped to the
// deployment regardless of sequence window — for live reports whose
// integrity rests on signer identity rather than per-index authority.
// Record attestations must use Resolve with the record's index.
func (t *TrustSet) ResolveAny(role, deploymentID, keyID string) (ed25519.PublicKey, error) {
	if t.Empty() {
		return nil, fmt.Errorf("%w: empty trust set — no record is verifiable", ErrUntrustedKey)
	}
	keyID = strings.ToLower(strings.TrimSpace(keyID))
	for i := range t.keys {
		k := &t.keys[i]
		if k.Role == role && k.KeyID == keyID && (k.DeploymentID == "" || k.DeploymentID == deploymentID) {
			return k.PublicKey, nil
		}
	}
	return nil, fmt.Errorf("%w: no pinned %s key %s for deployment %q", ErrUntrustedKey, role, keyID, deploymentID)
}

// rotationFields is the signing vector a rotation authorization
// commits to: the incumbent vouches for its successor, its successor's
// role and deployment scope, and the exact index authority transfers.
func rotationFields(prevKeyID string, next TrustedKey) []string {
	return []string{
		prevKeyID,
		next.KeyID,
		next.Role,
		next.DeploymentID,
		strconv.FormatInt(next.ValidFromIndex, 10),
	}
}

// SignKeyRotation produces the authorization an incumbent custodian key
// issues for its successor — copied into the trust file's successor
// entry by the operator. Rotation is an explicit act of the incumbent
// key plus pre-authorization in controlled configuration; a new key can
// never claim authority by appearing alone.
func SignKeyRotation(signer *evidence.Signer, next TrustedKey) (string, error) {
	return signer.SignRecord(RotationDomain, rotationFields(signer.Fingerprint(), next)...)
}

// AddAuthorized appends a rotation successor after proving the
// authorization: signed by the incumbent named in authorizedBy, whose
// validity window must end exactly where the successor's begins.
// Returns an error (and leaves the set unchanged) when authorization
// fails — a successor never inherits authority undeclared.
func (t *TrustSet) AddAuthorized(authorizedBy string, next TrustedKey, authorization string) error {
	next.KeyID = strings.ToLower(strings.TrimSpace(next.KeyID))
	if next.ValidFromIndex < 1 {
		return fmt.Errorf("rotation successor must start at index >= 1")
	}
	authorizedBy = strings.ToLower(strings.TrimSpace(authorizedBy))
	var prev *TrustedKey
	for i := range t.keys {
		k := &t.keys[i]
		if k.KeyID == authorizedBy && k.Role == next.Role &&
			k.ValidUntilIndex == next.ValidFromIndex-1 {
			prev = k
			break
		}
	}
	if prev == nil {
		return fmt.Errorf("rotation: no incumbent %s key %s ends at index %d — the successor has no authorized predecessor",
			next.Role, authorizedBy, next.ValidFromIndex-1)
	}
	if prev.DeploymentID != next.DeploymentID {
		return fmt.Errorf("rotation: deployment scope %q != incumbent scope %q — rotation cannot widen scope",
			next.DeploymentID, prev.DeploymentID)
	}
	if err := evidence.VerifyRecordSignature(prev.PublicKey, RotationDomain, authorization,
		rotationFields(authorizedBy, next)...); err != nil {
		return fmt.Errorf("rotation not authorized by the incumbent key: %w", err)
	}
	t.keys = append(t.keys, next)
	return nil
}

// trustSetFile is the controlled-configuration format for a pinned key
// set. The first key per (role, deployment) chain is the operator-named
// anchor; each later entry must prove a signed rotation authorization
// from the incumbent whose window it extends.
type trustSetFile struct {
	Version int               `json:"version"`
	Keys    []trustSetKeyFile `json:"keys"`
}

type trustSetKeyFile struct {
	Role            string `json:"role"`
	KeyID           string `json:"key_id"`
	PublicKey       string `json:"public_key"`
	DeploymentID    string `json:"deployment_id,omitempty"`
	ValidFromIndex  int64  `json:"valid_from_index"`
	ValidUntilIndex int64  `json:"valid_until_index"`
	AuthorizedBy    string `json:"authorized_by,omitempty"`
	Authorization   string `json:"authorization,omitempty"`
}

// LoadTrustSet reads a controlled custody trust file with the same
// discipline as the sandboxcustody root loader: regular file,
// owner-only, never a symlink — a trust file another user could edit
// is not a trust set.
func LoadTrustSet(path string) (*TrustSet, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect custody trust set %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("custody trust set %s is a symlink", path)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("custody trust set %s is not a regular file", path)
	}
	if err := sockfile.VerifyOwnership(path, info, "custody trust set"); err != nil {
		return nil, err
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("custody trust set %s is group/world accessible (mode %04o)", path, perm)
	}
	if info.Size() == 0 || info.Size() > 1<<20 {
		return nil, fmt.Errorf("custody trust set %s has invalid size %d", path, info.Size())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read custody trust set %s: %w", path, err)
	}
	f := &trustSetFile{}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(f); err != nil {
		return nil, fmt.Errorf("custody trust set %s malformed: %w", path, err)
	}
	if f.Version != 1 {
		return nil, fmt.Errorf("custody trust set %s: unsupported version %d", path, f.Version)
	}
	set := &TrustSet{}
	// Anchors first, then successors in file order — a successor's
	// authorization is checked against keys already proven.
	var pending []trustSetKeyFile
	for i, kf := range f.Keys {
		key, err := decodeTrustKey(kf)
		if err != nil {
			return nil, fmt.Errorf("custody trust set %s key %d: %w", path, i+1, err)
		}
		if key.ValidFromIndex == 0 {
			if kf.Authorization != "" || kf.AuthorizedBy != "" {
				return nil, fmt.Errorf("custody trust set %s key %d: an anchor must not carry a rotation authorization", path, i+1)
			}
			set.keys = append(set.keys, key)
			continue
		}
		pending = append(pending, kf)
	}
	for _, kf := range pending {
		key, _ := decodeTrustKey(kf)
		if kf.AuthorizedBy == "" || kf.Authorization == "" {
			return nil, fmt.Errorf("custody trust set %s key %s: a rotation successor must carry incumbent authorization — authority is never inherited silently", path, key.KeyID)
		}
		if err := set.AddAuthorized(kf.AuthorizedBy, key, kf.Authorization); err != nil {
			return nil, fmt.Errorf("custody trust set %s key %s: %w", path, key.KeyID, err)
		}
	}
	if set.Empty() {
		return nil, fmt.Errorf("custody trust set %s contains no keys", path)
	}
	// No two keys may claim the same (role, key_id, deployment) at the
	// same index — an ambiguous window is a load-time fault.
	seen := map[string][]int64{}
	for _, k := range set.keys {
		id := k.Role + "|" + k.KeyID + "|" + k.DeploymentID
		seen[id] = append(seen[id], k.ValidFromIndex)
	}
	for id, starts := range seen {
		if len(starts) > 1 {
			sort.Slice(starts, func(a, b int) bool { return starts[a] < starts[b] })
			return nil, fmt.Errorf("custody trust set %s: key %s is pinned twice", path, id)
		}
	}
	return set, nil
}

func decodeTrustKey(kf trustSetKeyFile) (TrustedKey, error) {
	k := TrustedKey{
		Role:            strings.TrimSpace(kf.Role),
		KeyID:           strings.ToLower(strings.TrimSpace(kf.KeyID)),
		DeploymentID:    strings.TrimSpace(kf.DeploymentID),
		ValidFromIndex:  kf.ValidFromIndex,
		ValidUntilIndex: kf.ValidUntilIndex,
	}
	switch k.Role {
	case RoleCustodian, RoleKernelRelay, RoleRepairAuthority:
	default:
		return k, fmt.Errorf("unknown signer role %q", kf.Role)
	}
	pub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(kf.PublicKey))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return k, fmt.Errorf("malformed public key")
	}
	k.PublicKey = ed25519.PublicKey(pub)
	if fp := evidence.Fingerprint(k.PublicKey); k.KeyID != "" && k.KeyID != fp {
		return k, fmt.Errorf("key_id %s does not match the pinned key's fingerprint %s", k.KeyID, fp)
	} else {
		k.KeyID = fp
	}
	if k.ValidFromIndex < 0 || k.ValidUntilIndex < 0 {
		return k, fmt.Errorf("negative validity bound")
	}
	if k.ValidUntilIndex != 0 && k.ValidUntilIndex < k.ValidFromIndex {
		return k, fmt.Errorf("valid_until_index %d precedes valid_from_index %d", k.ValidUntilIndex, k.ValidFromIndex)
	}
	return k, nil
}
