package witness

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/openclaw/crabbox/internal/custody"
)

// Sender drains the kernel custody outbox to the witness with
// restart-safe realignment: each pass reads the witness's signed
// custody head, verifies it under the pinned custodian trust set, then
// submits every outbox row from head+1 forward. A witness restored
// from an older checkpoint is re-custodied; a head that claims custody
// of a different record than the outbox holds is a contradictory
// checkpoint — the sender escalates, never overwrites history.
//
// Fencing is structural, not leased: the witness refuses any
// submission that does not extend its head, so a second sender cannot
// interleave divergent evidence; an identical re-offer is the same
// custody and returns the stored ack. Backoff bounds the reconnect
// rate; the gate consults health, not time.
type Sender struct {
	client         *Client
	outbox         *Outbox
	deploymentID   string
	custodianTrust *custody.TrustSet
	log            *slog.Logger

	lastErr    atomic.Value  // string — most recent transport/refusal error
	verifiedAt atomic.Value  // time.Time — last fully verified drain
	freshness  atomic.Int64  // readiness freshness bound, ns (0 = default)
	scanner    atomic.Value  // func(ctx) error — obligation replay scanner
	fullScan   atomic.Value  // func(ctx) error — seq-0 full-history rescan (operator repair)
	drainMu    sync.Mutex    // serializes drain attempts — linearizes pass ordering
	passGen    atomic.Uint64 // completed drain attempts, 1-based
	verifyGen  atomic.Uint64 // generation of the last verified pass (0 = never)
	stopped    chan struct{}
	once       sync.Once
	wake       chan struct{} // enqueue notification — prompt drain
	// repairHook is a test-only fault-injection seam between the
	// verified scan and the transactional marker clear. Nil in
	// production.
	repairHook func(stage string) error
}

// DefaultReadinessTTL bounds how old verified-custody evidence may be
// before the readiness claim goes stale — the fail-closed gate treats
// stale readiness as no readiness.
const DefaultReadinessTTL = 30 * time.Second

// NewSender wires the kernel-side drain loop. custodianTrust is the
// pinned custodian key set — checkpoints and acknowledgements verify
// under it at this boundary; an empty set fails closed.
func NewSender(client *Client, outbox *Outbox, deploymentID string, custodianTrust *custody.TrustSet, log *slog.Logger) *Sender {
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Sender{
		client:         client,
		outbox:         outbox,
		deploymentID:   deploymentID,
		custodianTrust: custodianTrust,
		log:            log,
		stopped:        make(chan struct{}),
		wake:           make(chan struct{}, 1),
	}
}

// SetFreshnessBound sets the verified-readiness freshness bound — the
// maximum age of the last verified drain the custody gate accepts.
// Zero restores DefaultReadinessTTL.
func (s *Sender) SetFreshnessBound(d time.Duration) {
	if d <= 0 {
		d = DefaultReadinessTTL
	}
	s.freshness.Store(int64(d))
}

func (s *Sender) freshnessBound() time.Duration {
	if d := time.Duration(s.freshness.Load()); d > 0 {
		return d
	}
	return DefaultReadinessTTL
}

// SetObligationScanner installs the terminal-obligation replay scanner
// run at the head of every drain pass. It must enumerate the committed
// terminal stream, enqueue every missing obligation into the outbox,
// and advance the high-water mark — after it completes clean, the
// outbox holds every obligation the authoritative ledger owes custody.
func (s *Sender) SetObligationScanner(fn func(ctx context.Context) error) {
	s.scanner.Store(fn)
}

// SetFullRescanScanner installs the independent full-history custody
// obligation verification (sequence 0 forward, bounded pages) used by
// the explicit operator repair path. It is deliberately distinct from
// the incremental HWM scanner: an operator repair that re-scanned only
// since the mark could inherit the same corruption it is meant to
// disprove.
func (s *Sender) SetFullRescanScanner(fn func(ctx context.Context) error) {
	s.fullScan.Store(fn)
}

// CustodyState reports the effective custody posture — the
// machine-readable state the authenticated operational status
// surfaces. States:
//
//	UNVERIFIED_STARTUP — no verified drain has completed this boot;
//	  nothing about custody is proven yet.
//	HEALTHY — verified drain within the freshness bound, no backlog,
//	  no durable degraded or repair markers.
//	DEGRADED — backlog pending, freshness stale, or a durable
//	  obligation-failure marker awaiting verified repair.
//	REPAIR_REQUIRED — a durable evidence contradiction (fork,
//	  conflicting ack, contradictory obligation) awaits an explicit
//	  verified operator repair.
func (s *Sender) CustodyState(ctx context.Context) string {
	st, err := s.outbox.CustodyStatus(ctx)
	if err != nil {
		return "DEGRADED"
	}
	if st.RepairReason != "" {
		return "REPAIR_REQUIRED"
	}
	if st.DegradedReason != "" {
		return "DEGRADED"
	}
	verified, ok := s.verifiedAt.Load().(time.Time)
	if !ok {
		return "UNVERIFIED_STARTUP"
	}
	if s.verifyGen.Load() != s.passGen.Load() {
		// The newest completed drain failed — a prior success inside
		// the freshness bound can never mask a current failure. Only
		// another complete verified pass restores readiness.
		return "DEGRADED"
	}
	if err, _ := s.lastErr.Load().(string); err != "" {
		// A recorded failure with no completed pass yet (e.g. a
		// degraded-marker write failure) never reads HEALTHY.
		return "DEGRADED"
	}
	if time.Since(verified) > s.freshnessBound() {
		return "DEGRADED"
	}
	n, err := s.outbox.Undelivered(ctx)
	if err != nil || n > 0 {
		return "DEGRADED"
	}
	return "HEALTHY"
}

// CustodyHealthy reports whether the custody path is verified clean:
// a drain pass that reached the witness, verified its signed
// checkpoint, reconciled obligations, and delivered the backlog
// completed inside the freshness bound — and no durable degraded or
// repair marker is open. A fresh sender is UNVERIFIED_STARTUP, not
// healthy: CRITICAL admission never rests on the absence of an
// observed failure.
func (s *Sender) CustodyHealthy(ctx context.Context) bool {
	return s.CustodyState(ctx) == "HEALTHY"
}

// LastError is the most recent sender failure, for diagnostics.
func (s *Sender) LastError() string {
	err, _ := s.lastErr.Load().(string)
	return err
}

// MarkDegraded records an outbox-side obligation failure (enqueue or
// persistence) in the durable custody state — a receipt that never
// reached the outbox must not look like delivered custody, and a
// restart or an unrelated successful drain can never erase the
// record. It is discharged only by the verified repair path.
func (s *Sender) MarkDegraded(msg string) {
	s.lastErr.Store(msg)
	if err := s.outbox.MarkDegraded(context.Background(), msg); err != nil {
		s.log.Error("custody degraded marker could not be persisted — custody state is itself degraded", "error", err)
	}
}

// Stop ends the drain loop.
func (s *Sender) Stop() {
	s.once.Do(func() { close(s.stopped) })
}

// Wake prompts an immediate drain pass after an enqueue.
func (s *Sender) Wake() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// Run drains until ctx ends or Stop fires, with bounded exponential
// backoff between failed passes — the outage never produces verified
// custody and the backlog persists for reconnect.
func (s *Sender) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 2 * time.Second
	}
	backoff := interval
	const maxBackoff = 60 * time.Second
	for {
		if s.drain(ctx) {
			backoff = interval
		} else if backoff < maxBackoff {
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
		t := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-s.stopped:
			t.Stop()
			return
		case <-s.wake:
			t.Stop()
		case <-t.C:
		}
	}
}

// drain runs one checkpoint-and-submit pass. It reports whether the
// pass ended clean — a clean pass records the verified-readiness mark
// and discharges any degraded marker the verified rescan repaired;
// a failed pass leaves the sender degraded.
//
// Order matters: the obligation replay scanner runs first so a gap
// the kernel committed but never queued is restored before the
// custody-head exchange. A scanner failure fails the pass — custody
// cannot prove completeness it never verified.
// drain serializes a pass and assigns its generation. The mutex makes
// attempt ordering linearizable — a stale in-flight pass cannot
// complete after a newer failure and overwrite the generation — and
// every completed attempt advances passGen, so a failed pass renders a
// previous success stale the moment it returns, not when the TTL
// expires.
func (s *Sender) drain(ctx context.Context) bool {
	s.drainMu.Lock()
	ok := s.drainPass(ctx)
	gen := s.passGen.Add(1)
	s.drainMu.Unlock()
	if ok {
		s.verifyGen.Store(gen)
	}
	return ok
}

func (s *Sender) drainPass(ctx context.Context) bool {
	if fn, ok := s.scanner.Load().(func(context.Context) error); ok && fn != nil {
		if err := fn(ctx); err != nil {
			s.lastErr.Store(fmt.Sprintf("custody obligation rescan: %v", err))
			s.log.Warn("custody obligation rescan failed", "error", err)
			return false
		}
	}
	head, err := s.client.Checkpoint(ctx, s.deploymentID)
	if err != nil {
		s.lastErr.Store(fmt.Sprintf("witness checkpoint: %v", err))
		s.log.Warn("custody witness unreachable", "error", err)
		return false
	}
	if head.WitnessFP == "" || head.Signature == "" {
		s.lastErr.Store("witness checkpoint unsigned — not a realignment authority")
		return false
	}
	if err := VerifyCheckpoint(head, s.deploymentID, s.custodianTrust); err != nil {
		s.lastErr.Store(fmt.Sprintf("witness checkpoint unverifiable: %v", err))
		s.log.Warn("custody checkpoint failed verification — refusing to realign", "error", err)
		return false
	}
	// Contradictory-head check: if the witness claims a custody head
	// whose record differs from the one this outbox holds at that
	// index, the two stores have forked — escalate; never overwrite.
	if head.Seq > 0 {
		if local, err := s.outbox.StoredHash(ctx, head.Seq); err != nil {
			s.lastErr.Store(fmt.Sprintf("custody outbox read: %v", err))
			return false
		} else if local != "" && local != head.Hash {
			reason := fmt.Sprintf("contradictory custody head: witness seq %d custodies %s, outbox holds %s — escalated, never reconciled silently", head.Seq, head.Hash, local)
			s.lastErr.Store(reason)
			s.log.Error("custody stores have forked", "seq", head.Seq, "witness", head.Hash, "local", local)
			if err := s.outbox.MarkRepairRequired(ctx, reason); err != nil {
				s.log.Error("custody repair marker could not be persisted", "error", err)
			}
			return false
		}
	}
	// Resume from the custody head: delivers pending rows and, after a
	// witness restore to an older checkpoint, re-delivers rows the
	// witness no longer holds. Identical resubmissions return the
	// stored ack — divergence is refused by the witness.
	rows, err := s.outbox.rowsFrom(ctx, head.Seq+1)
	if err != nil {
		s.lastErr.Store(fmt.Sprintf("custody outbox read: %v", err))
		return false
	}
	for _, r := range rows {
		// An already-acked row inside the resend window needs no new
		// submission — its custody is recorded. (Reached when the
		// witness advanced past a row we hold acked.)
		if r.Ack != nil && r.Seq <= head.Seq {
			continue
		}
		ack, err := s.client.Submit(ctx, s.deploymentID, r.Envelope)
		if err != nil {
			s.lastErr.Store(fmt.Sprintf("witness submit seq %d: %v", r.Seq, err))
			s.log.Warn("custody submission failed — sender degraded until next pass",
				"seq", r.Seq, "execution", r.ExecutionID, "error", err)
			return false
		}
		// The boundary verifies independently — the client's transport
		// result is not evidence until the countersignature checks out.
		if err := VerifyAck(ack, r.Envelope, s.custodianTrust); err != nil {
			s.lastErr.Store(fmt.Sprintf("witness ack seq %d unverifiable: %v", r.Seq, err))
			s.log.Warn("custody acknowledgement failed boundary verification — not recorded", "seq", r.Seq, "error", err)
			return false
		}
		if existing, err := s.outbox.StoredAck(ctx, r.Seq); err != nil {
			s.lastErr.Store(fmt.Sprintf("custody outbox read: %v", err))
			return false
		} else if existing != nil && existing.Signature != ack.Signature {
			reason := fmt.Sprintf("custody ack seq %d conflicts with the recorded acknowledgement — escalated, never overwritten", r.Seq)
			s.lastErr.Store(reason)
			if err := s.outbox.MarkRepairRequired(ctx, reason); err != nil {
				s.log.Error("custody repair marker could not be persisted", "error", err)
			}
			return false
		}
		if err := s.outbox.markDelivered(ctx, r.Seq, ack); err != nil {
			s.lastErr.Store(fmt.Sprintf("custody ack persist: %v", err))
			return false
		}
	}
	s.lastErr.Store("")
	s.verifiedAt.Store(time.Now())
	// Verified repair: this pass re-scanned the obligation stream
	// (when a scanner is installed) and completed a verified drain —
	// the only path that may discharge a degraded marker. A repair
	// marker is untouched: contradiction repair is an operator act.
	if err := s.outbox.RepairDegraded(ctx, "obligation rescan + verified drain completed"); err != nil {
		s.lastErr.Store(fmt.Sprintf("custody degraded repair: %v", err))
		return false
	}
	return true
}

// readinessFresh reports whether the generation-scoped readiness
// claim holds right now: a verified pass is the newest completed
// attempt and sits inside the freshness bound. The repair/degraded
// markers and backlog are checked separately by the caller.
func (s *Sender) readinessFresh(ctx context.Context) (bool, string) {
	verified, ok := s.verifiedAt.Load().(time.Time)
	if !ok {
		return false, "no verified drain this boot"
	}
	if s.verifyGen.Load() != s.passGen.Load() {
		return false, "the newest completed drain failed — a newer verified pass is required"
	}
	if time.Since(verified) > s.freshnessBound() {
		return false, "verified readiness is stale"
	}
	return true, ""
}

// OperatorAuthorization is the privileged authority a repair carries.
// It is the same signed-grant shape migration uses, verified against a
// repair-authority trust set pinned separately from the evidence keys.
type OperatorAuthorization = MigrationAuthorization

// RepairEvidence is the verified full-history receipt a repair binds
// into its audit record: structural chain state plus obligation
// coverage, with a digest over the canonical document.
type RepairEvidence struct {
	Schema        string `json:"schema"`
	DeploymentID  string `json:"deployment_id"`
	GrantDigest   string `json:"grant_digest"`
	Subject       string `json:"subject"`
	Nonce         string `json:"nonce"`
	ChainRows     int64  `json:"chain_rows"`
	HeadSeq       int64  `json:"head_seq"`
	HeadHash      string `json:"head_hash"`
	ChainDigest   string `json:"chain_digest"`
	ObligationHWM int64  `json:"obligation_hwm"`
	Undelivered   int64  `json:"undelivered"`
	ScannedAt     string `json:"scanned_at"`
	Digest        string `json:"digest"`
}

// RepairEvidence independently re-reads the durable outbox and proves
// the chain is structurally intact. It never trusts the scanner's own
// report: the scanner restores obligations, this recomputes the state
// those obligations live in.
func (o *Outbox) RepairEvidence(ctx context.Context, deploymentID string, grant *OperatorGrant) (RepairEvidence, error) {
	chain, err := o.VerifyChain(ctx)
	if err != nil {
		return RepairEvidence{}, err
	}
	st, err := o.CustodyStatus(ctx)
	if err != nil {
		return RepairEvidence{}, err
	}
	undelivered, err := o.Undelivered(ctx)
	if err != nil {
		return RepairEvidence{}, err
	}
	grantDigest, err := GrantDigest(grant)
	if err != nil {
		return RepairEvidence{}, err
	}
	ev := RepairEvidence{
		Schema:        "custody-repair-evidence-v1",
		DeploymentID:  deploymentID,
		GrantDigest:   grantDigest,
		Subject:       grant.Subject,
		Nonce:         grant.Nonce,
		ChainRows:     chain.Rows,
		HeadSeq:       chain.HeadSeq,
		HeadHash:      chain.HeadHash,
		ChainDigest:   chain.Digest,
		ObligationHWM: st.ObligationHWM,
		Undelivered:   undelivered,
		ScannedAt:     time.Now().UTC().Format(time.RFC3339Nano),
	}
	raw, err := json.Marshal(ev)
	if err != nil {
		return RepairEvidence{}, err
	}
	sum := sha256.Sum256(raw)
	ev.Digest = hex.EncodeToString(sum[:])
	return ev, nil
}

// OperatorRepair is the explicit repair path for a REPAIR_REQUIRED
// custody state. It refuses outright when no independent full-history
// scanner is installed: an incremental scan since the high-water mark
// could inherit exactly the corruption the repair must disprove.
//
// Authority is a signed grant, never a caller-supplied name: the actor
// is the grant's subject, covered by a repair-authority signature, and
// its nonce is consumed durably before any scan runs. The repair then
// requires a verified full-history obligation rescan, a verified drain
// (signed checkpoint, outbox contents, acks, backlog), a recomputed
// chain/coverage receipt, and a final readiness check. Only when every
// stage verifies is the marker cleared — transactionally, and only if
// the marker is still the exact contradiction the scan observed, so a
// concurrent new contradiction can never be cleared by stale work.
func (s *Sender) OperatorRepair(ctx context.Context, auth OperatorAuthorization, reason string) error {
	if reason == "" {
		return fmt.Errorf("custody repair requires a non-empty operator reason")
	}
	if auth.Grant == nil {
		return fmt.Errorf("%w: repair requires a signed operator grant — a self-supplied actor name never establishes identity", ErrOperatorAuthorization)
	}
	if auth.DeploymentID == "" || auth.DeploymentID != s.deploymentID {
		return fmt.Errorf("%w: repair grant is scoped to %q, this sender serves %q", ErrOperatorAuthorization, auth.DeploymentID, s.deploymentID)
	}
	if err := VerifyOperatorGrant(auth.Grant, auth.Trust, s.deploymentID, OperationRepair, time.Now()); err != nil {
		return err
	}
	fn, ok := s.fullScan.Load().(func(context.Context) error)
	if !ok || fn == nil {
		return fmt.Errorf("%w: refusing repair — no independent full-history scanner is installed, so the stream cannot be re-proven", ErrRepairScannerUnavailable)
	}
	st, err := s.outbox.CustodyStatus(ctx)
	if err != nil {
		return fmt.Errorf("custody status before repair: %w", err)
	}
	if st.RepairReason == "" {
		return fmt.Errorf("custody repair refused: no REPAIR_REQUIRED marker is open (state %s)", s.CustodyState(ctx))
	}
	expectedReason := st.RepairReason
	expectedGeneration := st.RepairGeneration
	// The operator surface consumes the grant nonce exactly once before
	// calling in; an unconsumed grant is not live authority. This is the
	// durable replay fence — a captured grant presented to a later
	// invocation finds its nonce already spent at the entry point.
	grantDigest, err := GrantDigest(auth.Grant)
	if err != nil {
		return err
	}
	used, err := s.outbox.OperatorNonceUsed(ctx, auth.Grant.Nonce, grantDigest)
	if err != nil {
		return err
	}
	if !used {
		return fmt.Errorf("%w: repair grant nonce was never consumed — authorization is not live", ErrOperatorAuthorization)
	}
	if err := fn(ctx); err != nil {
		return fmt.Errorf("custody repair: full-history obligation rescan failed: %w", err)
	}
	preEvidence, err := s.outbox.RepairEvidence(ctx, s.deploymentID, auth.Grant)
	if err != nil {
		return fmt.Errorf("custody repair: pre-drain evidence verification failed: %w", err)
	}
	if s.repairHook != nil {
		if err := s.repairHook("after_scan"); err != nil {
			return err
		}
	}
	if !s.drain(ctx) {
		return fmt.Errorf("custody repair: verified drain failed: %s", s.LastError())
	}
	// Readiness must hold independent of the open marker: the newest
	// pass verified inside the freshness bound, no backlog is
	// undelivered, and no durable degraded marker is open. The repair
	// marker itself is what this call clears — checking CustodyState
	// directly would fail on the marker still being open.
	if ok, why := s.readinessFresh(ctx); !ok {
		return fmt.Errorf("custody repair: post-repair readiness fails (%s) — marker stays open", why)
	}
	st2, err := s.outbox.CustodyStatus(ctx)
	if err != nil {
		return fmt.Errorf("custody status after repair: %w", err)
	}
	if st2.DegradedReason != "" {
		return fmt.Errorf("custody repair: durable degraded marker still open — marker stays open")
	}
	if n, err := s.outbox.Undelivered(ctx); err != nil || n > 0 {
		return fmt.Errorf("custody repair: %d obligations undelivered — marker stays open", n)
	}
	postEvidence, err := s.outbox.RepairEvidence(ctx, s.deploymentID, auth.Grant)
	if err != nil {
		return fmt.Errorf("custody repair: post-drain evidence verification failed: %w", err)
	}
	if postEvidence.HeadSeq != preEvidence.HeadSeq || postEvidence.ChainDigest != preEvidence.ChainDigest {
		return fmt.Errorf("custody repair: chain changed during repair (%d/%s → %d/%s) — a concurrent writer landed; marker stays open",
			preEvidence.HeadSeq, preEvidence.ChainDigest, postEvidence.HeadSeq, postEvidence.ChainDigest)
	}
	note := fmt.Sprintf("operator repair subject=%q reason=%q grant=%s pre=%s post=%s full-rescan=verified",
		auth.Grant.Subject, reason, postEvidence.GrantDigest, preEvidence.Digest, postEvidence.Digest)
	if err := s.outbox.ClearRepairRequiredIfUnchanged(ctx, expectedReason, expectedGeneration, note); err != nil {
		return fmt.Errorf("custody repair marker: %w", err)
	}
	return nil
}
