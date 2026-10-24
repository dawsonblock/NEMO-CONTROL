package witness

import (
	"context"
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

	lastErr atomic.Value // string — most recent transport/refusal error
	stopped chan struct{}
	once    sync.Once
	wake    chan struct{} // enqueue notification — prompt drain
}

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

// CustodyHealthy reports whether the custody path is clean: no pending
// backlog and no recent transport or refusal failure. The fail-closed
// gate for CRITICAL admissions consults it.
func (s *Sender) CustodyHealthy(ctx context.Context) bool {
	if err, _ := s.lastErr.Load().(string); err != "" {
		return false
	}
	n, err := s.outbox.Undelivered(ctx)
	return err == nil && n == 0
}

// LastError is the most recent sender failure, for diagnostics.
func (s *Sender) LastError() string {
	err, _ := s.lastErr.Load().(string)
	return err
}

// MarkDegraded records an outbox-side failure (enqueue/persist) so the
// custody gate and LastError reflect a broken local queue too — a
// receipt that never reached the outbox must not look like delivered
// custody.
func (s *Sender) MarkDegraded(msg string) { s.lastErr.Store(msg) }

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
// pass ended clean — a clean pass clears the error state; a failed
// pass leaves the sender degraded.
func (s *Sender) drain(ctx context.Context) bool {
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
			s.lastErr.Store(fmt.Sprintf("contradictory custody head: witness seq %d custodies %s, outbox holds %s — escalated, never reconciled silently", head.Seq, head.Hash, local))
			s.log.Error("custody stores have forked", "seq", head.Seq, "witness", head.Hash, "local", local)
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
			s.lastErr.Store(fmt.Sprintf("custody ack seq %d conflicts with the recorded acknowledgement — escalated, never overwritten", r.Seq))
			return false
		}
		if err := s.outbox.markDelivered(ctx, r.Seq, ack); err != nil {
			s.lastErr.Store(fmt.Sprintf("custody ack persist: %v", err))
			return false
		}
	}
	s.lastErr.Store("")
	return true
}
