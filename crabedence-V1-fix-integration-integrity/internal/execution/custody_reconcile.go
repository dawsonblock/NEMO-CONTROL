package execution

// F-02: the custody obligation replay scanner. The authoritative
// terminalization record lives in the idempotency store; the custody
// queue lives in a separate sqlite outbox, so no single transaction
// can cover both. This scanner is the reconciliation: it enumerates
// the store's append-only terminal_seq stream, restores every missing
// obligation into the outbox (byte-identical payload, so replay is
// idempotent), and advances the durable high-water mark. A crash
// between terminalization and enqueue can therefore lose nothing the
// ledger committed — the obligation is rebuilt on the next pass.
//
// The scan is bounded by the durable high-water mark: positions at or
// below it were verified covered and outbox rows have no delete path,
// so coverage there is structural. The operator-repair variant
// (fromSeq = 0) re-verifies the entire stream.

import (
	"context"
	"errors"
	"fmt"

	"github.com/openclaw/crabbox/internal/idempotency"
	"github.com/openclaw/crabbox/internal/witness"
)

// reconcileCustodyObligations restores missing custody obligations for
// every terminal record at positions beyond fromSeq. A record that
// cannot produce a payload, an enqueue that fails, and a contradiction
// the outbox refuses are distinct outcomes: the first two are
// retryable failures (the pass reports an error and custody stays
// degraded); a contradiction is an evidence fault escalated to
// REPAIR_REQUIRED — never overwritten, never silently skipped.
func reconcileCustodyObligations(ctx context.Context, store idempotency.EffectStore, outbox *witness.Outbox, producer witness.Producer, fromSeq int64) error {
	refs, err := store.TerminalEvidence(ctx)
	if err != nil {
		return fmt.Errorf("terminal evidence enumeration: %w", err)
	}
	ids := make([]string, 0, len(refs))
	var maxSeq int64
	for _, r := range refs {
		if r.TerminalReceiptDigest == "" {
			return fmt.Errorf("terminal record %s (seq %d, %s) has no receipt identity — the evidence ledger is incomplete", r.ExecutionID, r.Seq, r.State)
		}
		if r.Seq <= fromSeq {
			continue // below the verified high-water mark — covered durably
		}
		ids = append(ids, r.ExecutionID)
		if r.Seq > maxSeq {
			maxSeq = r.Seq
		}
	}
	if len(refs) > 0 && maxSeq == 0 {
		maxSeq = refs[len(refs)-1].Seq
	}
	missing, err := outbox.MissingObligations(ctx, ids)
	if err != nil {
		return fmt.Errorf("custody obligation scan: %w", err)
	}
	var repairErr error
	for _, r := range refs {
		if r.Seq <= fromSeq {
			continue
		}
		rec, err := store.Lookup(ctx, r.ExecutionID)
		if err != nil {
			return fmt.Errorf("obligation replay lookup %s: %w", r.ExecutionID, err)
		}
		payload, err := idempotency.TerminalReceiptFromRecord(rec).CustodyPayload()
		if err != nil || len(payload) == 0 {
			return fmt.Errorf("obligation replay %s cannot produce a custody payload: %v", r.ExecutionID, err)
		}
		if !missing[r.ExecutionID] {
			// Present is not covered: the same execution must hold
			// the same receipt bytes. A different byte stream means
			// the two stores forked — escalate, never reconcile.
			content, ok, err := outbox.StoredPayload(ctx, r.ExecutionID)
			if err != nil {
				return fmt.Errorf("obligation coverage read %s: %w", r.ExecutionID, err)
			}
			if !ok || string(content) == string(payload) {
				continue
			}
			if merr := outbox.MarkRepairRequired(ctx,
				fmt.Sprintf("obligation coverage contradiction on %s: outbox holds different receipt bytes than the authoritative terminal record", r.ExecutionID)); merr != nil {
				return fmt.Errorf("marking custody repair: %w", merr)
			}
			repairErr = witness.ErrEvidenceContradiction
			continue
		}
		if _, err := outbox.Enqueue(ctx, producer, rec.ExecutionID, rec.TerminalReceiptDigest, payload); err != nil {
			if errors.Is(err, witness.ErrEvidenceContradiction) {
				// The outbox holds a different byte stream for this
				// execution than the authoritative record produced —
				// the two stores have forked. Sticky escalation.
				if merr := outbox.MarkRepairRequired(ctx,
					fmt.Sprintf("obligation replay contradiction on %s: %v", r.ExecutionID, err)); merr != nil {
					return fmt.Errorf("marking custody repair: %w", merr)
				}
				repairErr = err
				continue
			}
			return fmt.Errorf("obligation replay enqueue %s: %w", r.ExecutionID, err)
		}
	}
	// High-water: advance only past a fully covered prefix — the mark
	// must never step over a row the outbox does not hold.
	if repairErr != nil {
		return fmt.Errorf("custody obligation replay hit an evidence contradiction — REPAIR_REQUIRED: %w", repairErr)
	}
	covered, err := outbox.MissingObligations(ctx, ids)
	if err != nil {
		return fmt.Errorf("custody obligation rescan: %w", err)
	}
	if len(covered) != 0 {
		return fmt.Errorf("custody obligation rescan found %d uncovered obligations after replay", len(covered))
	}
	if maxSeq > 0 {
		if err := outbox.AdvanceObligationHWM(ctx, maxSeq); err != nil {
			return fmt.Errorf("obligation high-water: %w", err)
		}
	}
	return nil
}

// CustodyObligationRescan is the operator/full-fidelity variant: it
// re-verifies the entire terminal stream from position 0 regardless
// of the recorded high-water mark — the forensic rescan a verified
// repair runs.
func CustodyObligationRescan(ctx context.Context, store idempotency.EffectStore, outbox *witness.Outbox, producer witness.Producer) error {
	return reconcileCustodyObligations(ctx, store, outbox, producer, 0)
}
