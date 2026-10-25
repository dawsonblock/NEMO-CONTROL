package witness

// RC8.3 integrity closure — privileged operator authorization.
//
// Custody repair and legacy migration rewrite durable evidence state.
// Possession of the ordinary kernel-relay evidence key is not authority
// for either: that key signs every routine receipt, so an AI agent or
// any process that can mint receipts must never be able to authorize
// forensic repair. Privileged operations therefore require a detached
// grant signed by a repair-authority key that is pinned separately from
// the kernel-relay and custodian sets.
//
// A grant binds the operator subject, the deployment, the exact
// operations, a validity window, and a single-use nonce. The actor name
// is never taken from the caller: it is the grant's subject, covered by
// the signature. Nonces are consumed durably before the operation runs,
// so a captured grant cannot be replayed.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openclaw/crabbox/internal/custody"
	"github.com/openclaw/crabbox/internal/evidence"
)

// OperatorGrantSchema is the exact grant document version.
const OperatorGrantSchema = "custody-operator-grant-v1"

// OperatorGrantDomain separates grant signatures from every other
// signed record in the deployment.
const OperatorGrantDomain = "custody-operator-grant-v1\x00"

// Privileged custody operations a grant may authorize.
const (
	OperationMigrate = "custody-migrate"
	OperationRepair  = "custody-repair"
	OperationRescan  = "custody-rescan"
)

// ErrOperatorAuthorization marks every authorization rejection. Callers
// must treat it as a refusal, never as a retryable transport failure.
var ErrOperatorAuthorization = errors.New("custody operator authorization")

// ErrRepairScannerUnavailable is returned when a repair is attempted on
// a sender with no independent full-history scanner installed. A repair
// that cannot re-prove the entire stream is not a repair.
var ErrRepairScannerUnavailable = errors.New("custody repair: full-history scanner unavailable")

// OperatorGrant is a detached, signed authorization for one privileged
// custody operation. Times are RFC3339. The signature covers the
// canonical grant with the signature field cleared.
type OperatorGrant struct {
	Schema       string   `json:"schema"`
	Subject      string   `json:"subject"`
	Role         string   `json:"role"`
	DeploymentID string   `json:"deployment_id"`
	Operations   []string `json:"operations"`
	NotBefore    string   `json:"not_before"`
	ExpiresAt    string   `json:"expires_at"`
	Nonce        string   `json:"nonce"`
	IssuerKeyID  string   `json:"issuer_key_id"`
	Signature    string   `json:"signature,omitempty"`
}

func grantCanonical(g *OperatorGrant, includeSignature bool) ([]byte, error) {
	cp := *g
	if !includeSignature {
		cp.Signature = ""
	}
	raw, err := json.Marshal(cp)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(m); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// SignOperatorGrant fills the issuer identity and signature. It is the
// issuer-side helper; custodyctl only ever verifies grants.
func SignOperatorGrant(signer *evidence.Signer, g *OperatorGrant) error {
	if signer == nil {
		return fmt.Errorf("%w: no signing key", ErrOperatorAuthorization)
	}
	g.Schema = OperatorGrantSchema
	g.Role = custody.RoleRepairAuthority
	g.IssuerKeyID = signer.Fingerprint()
	canon, err := grantCanonical(g, false)
	if err != nil {
		return err
	}
	sig, err := signer.SignRecord(OperatorGrantDomain, string(canon))
	if err != nil {
		return err
	}
	g.Signature = sig
	return nil
}

// GrantDigest is the stable identity of a fully signed grant — bound
// into the audit journal and the nonce ledger.
func GrantDigest(g *OperatorGrant) (string, error) {
	canon, err := grantCanonical(g, true)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canon)
	return hex.EncodeToString(sum[:]), nil
}

// VerifyOperatorGrant checks signature, role, deployment scope,
// operation scope, validity window, and nonce shape. It deliberately
// does not consult the nonce ledger: replay state is a durable property
// of the deployment outbox, checked separately and atomically.
func VerifyOperatorGrant(g *OperatorGrant, trust *custody.TrustSet, deploymentID, operation string, now time.Time) error {
	if g == nil {
		return fmt.Errorf("%w: no operator grant supplied", ErrOperatorAuthorization)
	}
	if g.Schema != OperatorGrantSchema {
		return fmt.Errorf("%w: unsupported grant schema %q", ErrOperatorAuthorization, g.Schema)
	}
	if strings.TrimSpace(g.Subject) == "" {
		return fmt.Errorf("%w: grant has no operator subject", ErrOperatorAuthorization)
	}
	if g.Role != custody.RoleRepairAuthority {
		return fmt.Errorf("%w: grant role %q is not %s — an evidence signer cannot authorize repair", ErrOperatorAuthorization, g.Role, custody.RoleRepairAuthority)
	}
	if deploymentID == "" || g.DeploymentID != deploymentID {
		return fmt.Errorf("%w: grant is scoped to deployment %q, this outbox serves %q", ErrOperatorAuthorization, g.DeploymentID, deploymentID)
	}
	if !grantAllows(g.Operations, operation) {
		return fmt.Errorf("%w: grant does not authorize %q", ErrOperatorAuthorization, operation)
	}
	if len(strings.TrimSpace(g.Nonce)) < 16 {
		return fmt.Errorf("%w: grant nonce is missing or too short for replay protection", ErrOperatorAuthorization)
	}
	notBefore, err := time.Parse(time.RFC3339, g.NotBefore)
	if err != nil {
		return fmt.Errorf("%w: grant not_before is not RFC3339: %v", ErrOperatorAuthorization, err)
	}
	expires, err := time.Parse(time.RFC3339, g.ExpiresAt)
	if err != nil {
		return fmt.Errorf("%w: grant expires_at is not RFC3339: %v", ErrOperatorAuthorization, err)
	}
	if !expires.After(notBefore) {
		return fmt.Errorf("%w: grant validity window is empty", ErrOperatorAuthorization)
	}
	if now.Before(notBefore) {
		return fmt.Errorf("%w: grant is not valid before %s", ErrOperatorAuthorization, g.NotBefore)
	}
	if !now.Before(expires) {
		return fmt.Errorf("%w: grant expired at %s", ErrOperatorAuthorization, g.ExpiresAt)
	}
	if trust.Empty() {
		return fmt.Errorf("%w: no pinned repair-authority trust set — authorization cannot be verified", ErrOperatorAuthorization)
	}
	pub, err := trust.ResolveAny(custody.RoleRepairAuthority, deploymentID, g.IssuerKeyID)
	if err != nil {
		return fmt.Errorf("%w: grant issuer is not a pinned repair authority: %v", ErrOperatorAuthorization, err)
	}
	canon, err := grantCanonical(g, false)
	if err != nil {
		return err
	}
	if err := evidence.VerifyRecordSignature(pub, OperatorGrantDomain, g.Signature, string(canon)); err != nil {
		return fmt.Errorf("%w: grant signature invalid: %v", ErrOperatorAuthorization, err)
	}
	return nil
}

func grantAllows(ops []string, operation string) bool {
	for _, op := range ops {
		if op == operation {
			return true
		}
	}
	return false
}

// OperatorNonceUsed reports whether a grant nonce was already consumed
// for this exact grant. A consumed nonce with a different grant digest
// is a replay attempt, not a retry.
func (o *Outbox) OperatorNonceUsed(ctx context.Context, nonce, grantDigest string) (bool, error) {
	var stored string
	err := o.db.QueryRowContext(ctx,
		`SELECT grant_digest FROM operator_nonce_ledger WHERE nonce = $1`, nonce).Scan(&stored)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("operator nonce ledger read: %w", err)
	}
	if stored != grantDigest {
		return false, fmt.Errorf("%w: nonce %q was consumed by a different grant — replay refused", ErrOperatorAuthorization, nonce)
	}
	return true, nil
}

// ConsumeOperatorNonce durably records one grant use. It is the
// atomic replay fence: the PRIMARY KEY admits exactly one consumption.
func (o *Outbox) ConsumeOperatorNonce(ctx context.Context, g *OperatorGrant, operation string) error {
	digest, err := GrantDigest(g)
	if err != nil {
		return err
	}
	res, err := o.db.ExecContext(ctx,
		`INSERT INTO operator_nonce_ledger (nonce, subject, operation, grant_digest, used_at)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT(nonce) DO NOTHING`,
		g.Nonce, g.Subject, operation, digest, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("operator nonce ledger: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("%w: grant nonce %q was already consumed — replay refused", ErrOperatorAuthorization, g.Nonce)
	}
	return nil
}

// AuthorizeAndConsumeGrant verifies a grant against pinned repair
// authority and consumes its nonce. Every privileged operation calls
// this before touching evidence state.
func (o *Outbox) AuthorizeAndConsumeGrant(ctx context.Context, g *OperatorGrant, trust *custody.TrustSet, deploymentID, operation string, now time.Time) error {
	if err := VerifyOperatorGrant(g, trust, deploymentID, operation, now); err != nil {
		return err
	}
	return o.ConsumeOperatorNonce(ctx, g, operation)
}
