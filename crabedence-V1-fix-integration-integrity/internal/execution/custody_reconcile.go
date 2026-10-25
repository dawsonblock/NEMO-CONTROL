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

	"github.com/openclaw/crabbox/internal/evidence"
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
// custodyReconcilePageSize bounds the terminal-evidence rows one
// reconciliation page examines. Per-pass work scales with new
// terminal rows, never the total ledger.
const custodyReconcilePageSize = 256

func reconcileCustodyObligations(ctx context.Context, store idempotency.EffectStore, outbox *witness.Outbox, producer witness.Producer, fromSeq int64) error {
	cursor := fromSeq
	for {
		page, err := store.TerminalEvidenceAfter(ctx, cursor, custodyReconcilePageSize)
		if err != nil {
			return fmt.Errorf("terminal evidence page after seq %d: %w", cursor, err)
		}
		if len(page) == 0 {
			return nil
		}
		if err := reconcileCustodyPage(ctx, store, outbox, producer, page, fromSeq); err != nil {
			return err
		}
		last := page[len(page)-1].Seq
		if last <= cursor {
			return fmt.Errorf("terminal evidence page did not advance past seq %d — ordering violated", cursor)
		}
		cursor = last
		if len(page) < custodyReconcilePageSize {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
}

// reconcileCustodyPage verifies and restores obligations for one
// bounded page, then advances the durable high-water mark over the
// page's verified covered prefix — the mark never steps over a gap,
// a missing row, or a contradiction.
func reconcileCustodyPage(ctx context.Context, store idempotency.EffectStore, outbox *witness.Outbox, producer witness.Producer, refs []evidence.TerminalRef, fromSeq int64) error {
	ids := make([]string, 0, len(refs))
	var maxSeq int64
	for _, r := range refs {
		if r.TerminalReceiptDigest == "" {
			return fmt.Errorf("terminal record %s (seq %d, %s) has no receipt identity — the evidence ledger is incomplete", r.ExecutionID, r.Seq, r.State)
		}
		if r.Seq <= fromSeq {
			continue
		}
		ids = append(ids, r.ExecutionID)
		if r.Seq > maxSeq {
			maxSeq = r.Seq
		}
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
			if len(content) == 0 {
				// A legacy empty-payload row (RC8.1 durable shape):
				// classification lives in the migration journal —
				// an operator-approved entry covers it; an
				// unjournaled one blocks custody until `custodyctl
				// migrate` classifies it. Never silently blessed,
				// never re-faulted once recorded.
				action, aerr := outbox.LegacyJournalAction(ctx, r.ExecutionID)
				if aerr != nil {
					return fmt.Errorf("legacy journal read %s: %w", r.ExecutionID, aerr)
				}
				if action != "" {
					continue
				}
				if merr := outbox.MarkRepairRequired(ctx,
					fmt.Sprintf("legacy empty custody payload on %s requires operator migration (custodyctl preflight/migrate) — no classification recorded", r.ExecutionID)); merr != nil {
					return fmt.Errorf("marking custody repair: %w", merr)
				}
				repairErr = witness.ErrEvidenceContradiction
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

// ReconcileCustodyObligationsFrom is the incremental scanner exported
// for the shipped operator surface (custodyctl): identical semantics
// to the service's drain-time scanner — bounded pages strictly beyond
// the durable high-water mark.
func ReconcileCustodyObligationsFrom(ctx context.Context, store idempotency.EffectStore, outbox *witness.Outbox, producer witness.Producer, fromSeq int64) error {
	return reconcileCustodyObligations(ctx, store, outbox, producer, fromSeq)
}
