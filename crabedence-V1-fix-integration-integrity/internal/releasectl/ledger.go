package releasectl

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ErrUnavailable marks control-ledger read/write failures. Admission
// gates must treat ErrUnavailable as deny — a store that cannot prove
// its state cannot authorize relaxation or effect dispatch.
var ErrUnavailable = errors.New("control ledger unavailable")

// ErrDenied is returned by Authorize when the event is not permitted
// to be appended (unsigned relaxation, untrusted signer, stale epoch,
// broken chain).
var ErrDenied = errors.New("control event denied")

// TrustRoots is the externally provisioned set of authorized operator
// signer fingerprints, optionally scoped per trust-root epoch. It is
// never populated from event payloads.
//
// Epoch scoping is what makes rotation survivable: an event is
// authorized against the root set of ITS epoch, so retiring an epoch
// adds a new generation of signers without invalidating the history
// the old generation signed. Removing a fingerprint altogether stays
// a deliberate freeze — every relaxation that key ever signed fails
// verification on next open.
type TrustRoots struct {
	anyEpoch map[string]bool
	byEpoch  map[uint64]map[string]bool
}

// AnyRoots builds a trust root set valid at every epoch — the
// pre-rotation form and the correct shape for small deployments.
func AnyRoots(fingerprints ...string) TrustRoots {
	r := TrustRoots{anyEpoch: map[string]bool{}}
	for _, fp := range fingerprints {
		r.anyEpoch[fp] = true
	}
	return r
}

// trusted reports whether fp is authorized to sign events at epoch.
func (r TrustRoots) trusted(fp string, epoch uint64) bool {
	if r.anyEpoch[fp] {
		return true
	}
	if set, ok := r.byEpoch[epoch]; ok && set[fp] {
		return true
	}
	return false
}

// empty reports whether no signer is trusted at any epoch.
func (r TrustRoots) empty() bool { return r.count() == 0 }

// count reports the number of distinct trusted fingerprints.
func (r TrustRoots) count() int {
	seen := map[string]bool{}
	for fp := range r.anyEpoch {
		seen[fp] = true
	}
	for _, set := range r.byEpoch {
		for fp := range set {
			seen[fp] = true
		}
	}
	return len(seen)
}

// LoadTrustRoots parses an allowlist file: one entry per line, '#'
// comments and blank lines allowed. Entries are either a bare
// lowercase-hex fingerprint (trusted at every epoch) or
// "<epoch>:<fingerprint>" (trusted only for events at that epoch).
// The file is the trust root — it must come from operator-managed
// storage.
func LoadTrustRoots(path string) (TrustRoots, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return TrustRoots{}, err
	}
	roots := TrustRoots{anyEpoch: map[string]bool{}, byEpoch: map[uint64]map[string]bool{}}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if epochStr, fp, ok := strings.Cut(line, ":"); ok {
			epoch, err := strconv.ParseUint(strings.TrimSpace(epochStr), 10, 64)
			fp = strings.TrimSpace(fp)
			if err != nil || !isHexDigest(fp) {
				return TrustRoots{}, fmt.Errorf("invalid trust root entry %q", line)
			}
			if roots.byEpoch[epoch] == nil {
				roots.byEpoch[epoch] = map[string]bool{}
			}
			roots.byEpoch[epoch][fp] = true
			continue
		}
		if !isHexDigest(line) {
			return TrustRoots{}, fmt.Errorf("invalid trust root entry %q", line)
		}
		roots.anyEpoch[line] = true
	}
	return roots, nil
}

// Verifier decides whether an event is authorized to be appended or to
// contribute to folded state. roots comes from configuration only;
// AllowUnverified is the explicit development escape hatch — never
// enabled silently, and refused in production callers.
type Verifier struct {
	roots           TrustRoots
	allowUnverified bool
}

// NewVerifier builds a verifier. allowUnverified is an explicit
// development flag: when false (the only production posture), every
// relaxing event requires a signature from an allowlisted signer and
// an empty root set fails closed.
func NewVerifier(roots TrustRoots, allowUnverified bool) *Verifier {
	return &Verifier{roots: roots, allowUnverified: allowUnverified}
}

// Trusted reports whether a signer fingerprint is authorized at epoch.
func (v *Verifier) Trusted(keyID string, epoch uint64) bool {
	return v.roots.trusted(keyID, epoch)
}

// RootCount reports the number of configured roots (for reporting).
func (v *Verifier) RootCount() int { return v.roots.count() }

// authorize validates an event's authorization envelope: schema,
// signature requirements per kind, and trust-root membership. It does
// NOT check sequence/chain — the ledger does that.
func (v *Verifier) authorize(e Event) error {
	if err := e.validateSchema(); err != nil {
		return fmt.Errorf("%w: %v", ErrDenied, err)
	}
	if KindTightens(e.Kind) {
		// Tightening may be unsigned; if signed, the signature must be
		// self-consistent and valid — a malformed signature makes the
		// record corrupt, not "unsigned".
		if !e.HasSignature() {
			return nil
		}
		if err := e.VerifySignature(); err != nil {
			return fmt.Errorf("%w: %v", ErrDenied, err)
		}
		return nil
	}
	// Relaxing event: signature required, from a root trusted at the
	// event's epoch.
	if !e.HasSignature() {
		return fmt.Errorf("%w: %s requires an operator signature", ErrDenied, e.Kind)
	}
	if err := e.VerifySignature(); err != nil {
		return fmt.Errorf("%w: %v", ErrDenied, err)
	}
	if v.roots.empty() && !v.allowUnverified {
		return fmt.Errorf("%w: no operator trust roots configured", ErrDenied)
	}
	if !v.allowUnverified && !v.roots.trusted(e.SignerKeyID, e.Epoch) {
		return fmt.Errorf("%w: signer %s is not a trusted operator at epoch %d",
			ErrDenied, e.SignerKeyID, e.Epoch)
	}
	return nil
}

// Checkpoint is the monotonic anchor: it records the ledger prefix the
// operator-side checkpoint holder has authorized. Relaxations beyond
// it never take effect. It lives at a deployment-configurable path so
// deployments can hold it outside the writable runtime's authority.
type Checkpoint struct {
	SchemaVersion int    `json:"schema_version"`
	Sequence      uint64 `json:"sequence"` // events covered: seq < Sequence
	HeadHash      string `json:"head_hash"`
	Epoch         uint64 `json:"epoch"`
}

const checkpointSchemaVersion = 1

func writeCheckpoint(path string, cp Checkpoint) error {
	cp.SchemaVersion = checkpointSchemaVersion
	data, err := json.Marshal(cp)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".ckpt-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	// Commit the rename so the checkpoint survives power loss.
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	derr := d.Sync()
	cerr := d.Close()
	if derr != nil {
		return fmt.Errorf("checkpoint directory fsync failed: %w", derr)
	}
	return cerr
}

func readCheckpoint(path string) (Checkpoint, bool, error) {
	var cp Checkpoint
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cp, false, nil
		}
		return cp, false, err
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cp); err != nil {
		return cp, false, fmt.Errorf("checkpoint corrupt: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return cp, false, fmt.Errorf("checkpoint corrupt: trailing data")
		}
		return cp, false, fmt.Errorf("checkpoint corrupt: %w", err)
	}
	if cp.SchemaVersion != checkpointSchemaVersion || !isHexDigest(cp.HeadHash) {
		return cp, false, fmt.Errorf("checkpoint invalid")
	}
	return cp, true, nil
}

// DeploymentState is the folded effective control state for one
// deployment.
type DeploymentState struct {
	// Halted/Revoked are the admission-blocking restrictions.
	Halted  bool
	Revoked bool
	// StageLevel/StagedRelease record the latest authorized stage
	// transition (0/none means no staged restriction recorded).
	StageLevel    int
	StagedRelease string
	// PendingRelaxations counts relaxing events present in the ledger
	// but not covered by the checkpoint — an operator-visible signal
	// that a request is awaiting checkpoint authorization rather than
	// silently dropped.
	PendingRelaxations int
}

// Restricted reports whether new effect admission is denied.
func (s DeploymentState) Restricted() bool { return s.Halted || s.Revoked }

// Ledger is the append-only control-event store. The on-disk format is
// one canonical Event JSON per line; every record carries sequence and
// prev_event_hash, making truncation, rewrite, insertion, and reorder
// detectable on every open. State is never trusted from disk — the
// full chain is re-verified on open and before every sensitive read.
//
// A Ledger is not safe for concurrent goroutine use. Cross-process
// writers are serialized by an O_EXCL lockfile taken for each Append.
type Ledger struct {
	path       string
	checkpoint string
	verifier   *Verifier
	events     []Event
	states     map[string]*DeploymentState
	// rawStates folds every authorized event unconditionally — the
	// deployment history each event's prev_state_hash binds, free of
	// checkpoint coverage so that a checkpoint advance cannot stale a
	// later event's recorded binding.
	rawStates  map[string]*DeploymentState
	maxEpoch   uint64
	coveredSeq uint64 // checkpoint coverage at load
	noCkpt     bool   // ledger non-empty but checkpoint absent
}

// Open loads the ledger, verifies the complete chain, and folds
// effective state. Hard conflicts refuse to open: record corruption,
// chain breaks, checkpoint rollback (checkpoint ahead of ledger), and
// checkpoint/record hash mismatches are integrity failures — the
// caller must treat ErrUnavailable as deny-everything.
func Open(path, checkpointPath string, v *Verifier) (*Ledger, error) {
	l := &Ledger{
		path:       path,
		checkpoint: checkpointPath,
		verifier:   v,
		states:     map[string]*DeploymentState{},
	}
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 2*maxEventRecordSize)
	var lastHash = genesisHash
	var seq uint64
	var maxEpoch uint64
	raw := map[string]*DeploymentState{}
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		e, err := ParseEvent([]byte(line))
		if err != nil {
			return nil, fmt.Errorf("%w: record %d corrupt: %v", ErrUnavailable, seq, err)
		}
		if e.Sequence != seq {
			return nil, fmt.Errorf("%w: record sequence %d, expected %d", ErrUnavailable, e.Sequence, seq)
		}
		if e.PrevEventHash != lastHash {
			return nil, fmt.Errorf("%w: record %d chain break", ErrUnavailable, seq)
		}
		if err := v.authorize(e); err != nil {
			return nil, fmt.Errorf("%w: record %d unauthorized: %v", ErrUnavailable, seq, err)
		}
		if e.Epoch < maxEpoch {
			return nil, fmt.Errorf("%w: record %d stale epoch %d < %d", ErrUnavailable, seq, e.Epoch, maxEpoch)
		}
		if e.Epoch > maxEpoch {
			maxEpoch = e.Epoch
		}
		// prev_state_hash binds the deployment's folded history — an
		// event claiming a state the chain never produced is forged.
		if e.PrevStateHash != rawStateHash(raw[e.Deployment]) {
			return nil, fmt.Errorf("%w: record %d prev_state_hash does not match folded deployment state",
				ErrUnavailable, seq)
		}
		st := raw[e.Deployment]
		if st == nil {
			st = &DeploymentState{}
			raw[e.Deployment] = st
		}
		applyRaw(st, e)
		lastHash = EventHash(e)
		l.events = append(l.events, e)
		seq++
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	l.maxEpoch = maxEpoch

	// Checkpoint reconciliation. Hard conflicts (rollback, head
	// mismatch, a claimed epoch the chain never accepted) refuse to
	// open; absence or a stale tail degrade to "no uncheckpointed
	// relaxation may take effect".
	cp, present, err := readCheckpoint(checkpointPath)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	switch {
	case !present:
		if len(l.events) > 0 {
			l.noCkpt = true
		}
	case cp.Sequence > uint64(len(l.events)):
		return nil, fmt.Errorf("%w: checkpoint seq %d ahead of ledger %d — rollback detected",
			ErrUnavailable, cp.Sequence, len(l.events))
	case cp.Epoch > maxEpoch:
		return nil, fmt.Errorf("%w: checkpoint epoch %d ahead of ledger max epoch %d",
			ErrUnavailable, cp.Epoch, maxEpoch)
	default:
		if cp.Sequence > 0 {
			if got := EventHash(l.events[cp.Sequence-1]); got != cp.HeadHash {
				return nil, fmt.Errorf("%w: checkpoint head %s does not match record %d (%s) — replica conflict",
					ErrUnavailable, cp.HeadHash, cp.Sequence-1, got)
			}
		}
		l.coveredSeq = cp.Sequence
	}
	l.fold()
	return l, nil
}

// Create opens a ledger for writing, creating an empty store if the
// file does not exist. Verification rules are identical to Open.
func Create(path, checkpointPath string, v *Verifier) (*Ledger, error) {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		dir := filepath.Dir(path)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
		}
		f.Close()
	}
	return Open(path, checkpointPath, v)
}

// fold recomputes effective per-deployment state from verified events.
// Tightening events always apply — a valid halt can never be lost by
// checkpoint manipulation. Relaxing events apply only when covered by
// the checkpoint; uncovered relaxations are counted, never applied.
// rawStates folds every event unconditionally — the history binding
// prev_state_hash verifies against, independent of coverage.
func (l *Ledger) fold() {
	l.states = map[string]*DeploymentState{}
	l.rawStates = map[string]*DeploymentState{}
	for i, e := range l.events {
		st := l.states[e.Deployment]
		if st == nil {
			st = &DeploymentState{}
			l.states[e.Deployment] = st
		}
		raw := l.rawStates[e.Deployment]
		if raw == nil {
			raw = &DeploymentState{}
			l.rawStates[e.Deployment] = raw
		}
		applyRaw(raw, e)
		covered := !l.noCkpt && uint64(i) < l.coveredSeq
		switch e.Kind {
		case KindHalt:
			st.Halted = true
		case KindRevoke:
			st.Revoked = true
		case KindResume:
			if covered {
				st.Halted = false
			} else {
				st.PendingRelaxations++
			}
		case KindUnrevoke:
			if covered {
				st.Revoked = false
			} else {
				st.PendingRelaxations++
			}
		case KindStage:
			if covered {
				st.StageLevel = e.Stage
				st.StagedRelease = e.ReleaseDigest
			} else {
				st.PendingRelaxations++
			}
		case KindStageClear:
			if covered {
				st.StageLevel = 0
				st.StagedRelease = ""
			} else {
				st.PendingRelaxations++
			}
		}
	}
}

// applyRaw applies one authorized event to a fold that ignores
// checkpoint coverage — every verified transition takes effect.
func applyRaw(st *DeploymentState, e Event) {
	switch e.Kind {
	case KindHalt:
		st.Halted = true
	case KindRevoke:
		st.Revoked = true
	case KindResume:
		st.Halted = false
	case KindUnrevoke:
		st.Revoked = false
	case KindStage:
		st.StageLevel, st.StagedRelease = e.Stage, e.ReleaseDigest
	case KindStageClear:
		st.StageLevel, st.StagedRelease = 0, ""
	}
}

// rawStateHash is the canonical digest of a deployment fold used for
// prev_state_hash — PendingRelaxations is a coverage concern and is
// always zero here so the binding is a pure function of the event chain.
func rawStateHash(st *DeploymentState) string {
	var s DeploymentState
	if st != nil {
		s = *st
	}
	s.PendingRelaxations = 0
	data, _ := json.Marshal(s)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// state returns the folded state for a deployment (zero value = active).
func (l *Ledger) state(deployment string) DeploymentState {
	if st := l.states[deployment]; st != nil {
		return *st
	}
	return DeploymentState{}
}

// State exposes the folded state for inspection/reporting.
func (l *Ledger) State(deployment string) DeploymentState { return l.state(deployment) }

// Deployments lists every deployment with folded state, sorted.
func (l *Ledger) Deployments() []string {
	out := make([]string, 0, len(l.states))
	for dep := range l.states {
		out = append(out, dep)
	}
	sort.Strings(out)
	return out
}

// AdmitError is the dispatch-boundary check: nil admits new external
// effects for the deployment; non-nil denies them. It is deliberately
// separate from the append path so the kernel cannot grant itself a
// bypass — the folded ledger state is the only input.
func (l *Ledger) AdmitError(deployment string) error {
	st := l.state(deployment)
	switch {
	case st.Revoked:
		return fmt.Errorf("deployment %s revoked by operator control", deployment)
	case st.Halted:
		return fmt.Errorf("deployment %s halted by operator control", deployment)
	}
	return nil
}

// MaxEpoch reports the highest epoch accepted into the chain.
func (l *Ledger) MaxEpoch() uint64 { return l.maxEpoch }

// Len reports the number of chained records.
func (l *Ledger) Len() int { return len(l.events) }

// Append validates an event against the verifier and the chain head,
// assigns sequence/prev hash when unset by the caller (callers should
// prefer NewEvent), fsyncs the record, then advances the checkpoint.
// A relaxation whose checkpoint write fails stays durable in the
// ledger but never takes effect — fail closed.
//
// Concurrent writers are serialized by an O_EXCL lockfile at
// <ledger>.lock: two racing appends would both claim the same
// sequence and corrupt the chain into permanent fail-closed. A stale
// lock (writer killed between acquire and release) must be removed
// manually — deletion can only deny appends, never clear restrictions.
func (l *Ledger) Append(e Event) error {
	if e.Sequence == 0 && len(l.events) > 0 {
		return fmt.Errorf("%w: sequence 0 already taken", ErrDenied)
	}
	expectedSeq := uint64(len(l.events))
	if e.Sequence != expectedSeq {
		return fmt.Errorf("%w: event sequence %d, expected %d", ErrDenied, e.Sequence, expectedSeq)
	}
	expectedPrev := genesisHash
	if len(l.events) > 0 {
		expectedPrev = EventHash(l.events[len(l.events)-1])
	}
	if e.PrevEventHash != expectedPrev {
		return fmt.Errorf("%w: event prev_event_hash does not match chain head", ErrDenied)
	}
	if e.PrevStateHash != l.stateHash(e.Deployment) {
		return fmt.Errorf("%w: event prev_state_hash does not match folded deployment state", ErrDenied)
	}
	if err := l.verifier.authorize(e); err != nil {
		return err
	}
	if e.Epoch < l.maxEpoch {
		return fmt.Errorf("%w: stale epoch %d < %d", ErrDenied, e.Epoch, l.maxEpoch)
	}

	data, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	// ParseEvent refuses records larger than maxEventRecordSize — an
	// oversized append would be durable yet unverifiable, permanently
	// freezing the ledger. Reject it before it lands.
	if len(data) > maxEventRecordSize {
		return fmt.Errorf("%w: event record exceeds %d bytes", ErrDenied, maxEventRecordSize)
	}

	lock := l.path + ".lock"
	lf, err := os.OpenFile(lock, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("%w: control ledger locked by another writer — if stale, remove %s",
			ErrUnavailable, lock)
	}
	fmt.Fprintf(lf, "%d\n", os.Getpid())
	lf.Close()
	defer os.Remove(lock)

	f, err := os.OpenFile(l.path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if _, err := f.Write(append(data, '\n')); err != nil {
		f.Close()
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("%w: append fsync failed: %v", ErrUnavailable, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}

	l.events = append(l.events, e)
	if e.Epoch > l.maxEpoch {
		l.maxEpoch = e.Epoch
	}
	l.fold()

	// Advance the checkpoint. The record is already durable; a
	// checkpoint failure leaves the event present-but-uncovered,
	// which only withholds relaxations — fail closed, report the
	// error so the operator sees the checkpoint is behind.
	hash := EventHash(e)
	if err := writeCheckpoint(l.checkpoint, Checkpoint{
		Sequence: e.Sequence + 1, HeadHash: hash, Epoch: l.maxEpoch,
	}); err != nil {
		return fmt.Errorf("%w: event durable but checkpoint failed: %v", ErrUnavailable, err)
	}
	l.coveredSeq = uint64(len(l.events))
	l.noCkpt = false
	l.fold()
	return nil
}

// NewEvent builds an event with chain position filled in. The caller
// then signs (relaxing kinds) and appends. Kind-specific required
// fields (evidence refs for stage, release digest for stage binding)
// are enforced by schema validation at authorize time.
func (l *Ledger) NewEvent(kind, deployment, reason string) Event {
	prev := genesisHash
	if len(l.events) > 0 {
		prev = EventHash(l.events[len(l.events)-1])
	}
	return Event{
		SchemaVersion: SchemaVersion,
		EventID:       newEventID(),
		Kind:          kind,
		Deployment:    deployment,
		SignerRole:    RoleOperator,
		Sequence:      uint64(len(l.events)),
		Epoch:         l.maxEpoch,
		PrevEventHash: prev,
		PrevStateHash: l.stateHash(deployment),
		Timestamp:     nowUTC(),
		Reason:        reason,
	}
}

// stateHash is the SHA-256 of the deployment's raw fold — binds each
// event to the history it claims to follow.
func (l *Ledger) stateHash(deployment string) string {
	return rawStateHash(l.rawStates[deployment])
}

// PendingRelaxations reports the total relaxations present but not yet
// checkpoint-authorized, across every deployment — the count an
// append's checkpoint advance would activate.
func (l *Ledger) PendingRelaxations() int {
	total := 0
	for _, st := range l.states {
		total += st.PendingRelaxations
	}
	return total
}

// newEventID returns a random event identifier. Uniqueness is a
// convenience for operator audit — chain position, not the ID, is
// authoritative for ordering.
func newEventID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Event IDs are audit labels; a PRNG fallback still yields a
		// unique-enough value while the chain stays authoritative.
		sum := sha256.Sum256([]byte(fmt.Sprint(time.Now().UnixNano())))
		return "ev-" + hex.EncodeToString(sum[:8])
	}
	return "ev-" + hex.EncodeToString(b[:])
}

// nowUTC stamps audit timestamps. Ordering authority is the
// sequence/checkpoint, never the wall clock.
func nowUTC() string { return time.Now().UTC().Format(time.RFC3339Nano) }
