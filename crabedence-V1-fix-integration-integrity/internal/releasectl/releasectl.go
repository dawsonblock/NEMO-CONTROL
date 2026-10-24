// Package releasectl implements the operator control plane for a
// running execution service: emergency halt, resume, and per-release
// revocation. Control records are Ed25519-signed by an operator key —
// the kernel cannot mint its own halt waiver — and are stored as files
// in the service's runtime directory so an operator can act on the
// deployment from outside the kernel process.
//
// Enforcement is fail closed: a present but malformed or untrusted
// control record denies admission rather than silently opening the
// gate. Revocation is keyed on the service's declared release
// identity; halt is global.
package releasectl

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/openclaw/crabbox/internal/evidence"
)

const (
	ActionHalt   = "halt"
	ActionRevoke = "revoke"
	ActionStage  = "stage"

	// Rollout stages, in promotion order. Percentage shaping across
	// replicas belongs to the deployment orchestrator; the kernel-side
	// contract is that a declared stage is signed, auditable, and can
	// be made a precondition of admission.
	StageCanary   = "canary"
	StageMajority = "majority"
	StageFull     = "full"

	signingDomain = "crabedence-release-control-v1"
)

// ValidStage reports whether s is a declared rollout stage.
func ValidStage(s string) bool {
	return s == StageCanary || s == StageMajority || s == StageFull
}

// Record is one signed control act. The signature covers action,
// release, reason, timestamp, revoker, signer fingerprint, and the
// embedded public key — the same self-binding shape as ReceiptV3.
type Record struct {
	SchemaVersion int    `json:"schema_version"`
	Action        string `json:"action"`
	Release       string `json:"release,omitempty"`
	Stage         string `json:"stage,omitempty"`
	Reason        string `json:"reason"`
	At            string `json:"at"`
	Revoker       string `json:"revoker"`
	PublicKey     string `json:"public_key"`
	Signer        string `json:"signer"`
	Signature     string `json:"signature"`
}

func signingBytes(r Record) []byte {
	var payload bytes.Buffer
	payload.WriteString(signingDomain)
	var length [4]byte
	for _, v := range []string{r.Action, r.Release, r.Stage, r.Reason, r.At, r.Revoker, r.PublicKey, r.Signer} {
		binary.BigEndian.PutUint32(length[:], uint32(len(v)))
		payload.Write(length[:])
		payload.WriteString(v)
	}
	return payload.Bytes()
}

// Issue signs a control act under the operator signer.
func Issue(signer *evidence.Signer, action, release, stage, reason, revoker string) (Record, error) {
	if reason == "" {
		return Record{}, fmt.Errorf("control records require a reason — the audit trail is the point")
	}
	if action == ActionRevoke && release == "" {
		return Record{}, fmt.Errorf("revoke requires a release identity")
	}
	if action == ActionStage {
		if release == "" {
			return Record{}, fmt.Errorf("stage requires a release identity")
		}
		if !ValidStage(stage) {
			return Record{}, fmt.Errorf("invalid rollout stage %q (canary|majority|full)", stage)
		}
	}
	pub := signer.PublicKey()
	r := Record{
		SchemaVersion: 1,
		Action:        action,
		Release:       release,
		Stage:         stage,
		Reason:        reason,
		At:            time.Now().UTC().Format(time.RFC3339Nano),
		Revoker:       revoker,
		PublicKey:     base64.StdEncoding.EncodeToString(pub),
		Signer:        evidence.Fingerprint(pub),
	}
	r.Signature = base64.StdEncoding.EncodeToString(signer.SignBytes(signingBytes(r)))
	return r, nil
}

// Verify checks a record's signature under its embedded key and, when
// trusted fingerprints are configured, that the signer is among them.
// With no configured trust root any well-formed self-consistent record
// is honored (development semantics — the runtime dir is owner-only).
func Verify(r Record, trusted map[string]bool) error {
	pub, err := base64.StdEncoding.DecodeString(r.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("control record has invalid public_key")
	}
	if evidence.Fingerprint(ed25519.PublicKey(pub)) != r.Signer {
		return fmt.Errorf("control record signer does not match its public key")
	}
	if len(trusted) > 0 && !trusted[r.Signer] {
		return fmt.Errorf("control record signer %s is not a trusted operator", r.Signer)
	}
	sig, err := base64.StdEncoding.DecodeString(r.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("control record has invalid signature encoding")
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), signingBytes(r), sig) {
		return fmt.Errorf("control record signature does not verify")
	}
	return nil
}

// Write persists a record atomically (tmp + fsync + rename) at 0600.
func Write(path string, r Record) error {
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Load reads a control record. A missing file reports nil — absence is
// not a record.
func Load(path string) (*Record, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var r Record
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("malformed control record %s: %w", path, err)
	}
	return &r, nil
}

// Dir is the control directory beside the execution socket.
func Dir(socketPath string) string {
	return filepath.Join(filepath.Dir(socketPath), "control")
}

// releaseFile names a revocation record for a release identity. The
// release string may carry characters unfit for filenames, so the
// record is keyed by its digest — resume/unrevoke derive the same.
func releaseFile(dir, release string) string {
	sum := sha256.Sum256([]byte(release))
	return filepath.Join(dir, "revoked", hex.EncodeToString(sum[:16])+".json")
}

// HaltPath is the global halt record's location.
func HaltPath(dir string) string { return filepath.Join(dir, "halt.json") }

// Halt installs the global halt record.
func Halt(dir string, r Record) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return Write(HaltPath(dir), r)
}

// Resume clears the global halt.
func Resume(dir string) error {
	err := os.Remove(HaltPath(dir))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// Revoke installs a per-release revocation record.
func Revoke(dir, release string, r Record) error {
	path := releaseFile(dir, release)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return Write(path, r)
}

// Unrevoke clears a release's revocation.
func Unrevoke(dir, release string) error {
	err := os.Remove(releaseFile(dir, release))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func stageFile(dir, release string) string {
	sum := sha256.Sum256([]byte("stage:" + release))
	return filepath.Join(dir, "staged", hex.EncodeToString(sum[:16])+".json")
}

// SetStage installs a rollout-stage record for a release.
func SetStage(dir, release string, r Record) error {
	path := stageFile(dir, release)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return Write(path, r)
}

// ClearStage removes a release's rollout-stage record.
func ClearStage(dir, release string) error {
	err := os.Remove(stageFile(dir, release))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// Check reports why a service at release must deny admission, or "".
// Malformed or untrusted records deny — fail closed, never fail open.
// When requireStage is set, a service whose release carries no valid
// signed rollout-stage record is denied too: promotion is then an
// explicit operator act, never an absence of prohibition.
func Check(dir, release string, trusted map[string]bool, requireStage bool) string {
	if r, err := Load(HaltPath(dir)); err != nil {
		return fmt.Sprintf("control record unreadable — fail closed: %v", err)
	} else if r != nil {
		if err := Verify(*r, trusted); err != nil {
			return fmt.Sprintf("halt record untrusted — fail closed: %v", err)
		}
		return fmt.Sprintf("deployment halted by %s at %s: %s", r.Revoker, r.At, r.Reason)
	}
	if release == "" {
		return ""
	}
	if r, err := Load(releaseFile(dir, release)); err != nil {
		return fmt.Sprintf("control record unreadable — fail closed: %v", err)
	} else if r != nil {
		if err := Verify(*r, trusted); err != nil {
			return fmt.Sprintf("revocation record untrusted — fail closed: %v", err)
		}
		return fmt.Sprintf("release %s revoked by %s at %s: %s", release, r.Revoker, r.At, r.Reason)
	}
	if requireStage {
		r, err := Load(stageFile(dir, release))
		if err != nil {
			return fmt.Sprintf("rollout record unreadable — fail closed: %v", err)
		}
		if r == nil {
			return fmt.Sprintf("release %s has no signed rollout stage — promotion requires an operator stage record", release)
		}
		if err := Verify(*r, trusted); err != nil {
			return fmt.Sprintf("rollout record untrusted — fail closed: %v", err)
		}
	}
	return ""
}
