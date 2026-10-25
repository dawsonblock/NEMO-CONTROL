package witness

// RC8.3 PR-03 — lossless legacy custody migration. RC8.1-era outboxes
// hold rows whose envelope content is empty: non-CRITICAL executions
// enqueued a nil receipt, producing an envelope that can never verify
// under the canonical terminal-receipt preimage and wedging upgrades
// into unrecoverable REPAIR_REQUIRED.
//
// Migration is classification-first and operator-approved: preflight
// is read-only, compensation never touches a witnessed row's bytes,
// and every transition lands in an append-only journal. Nothing is
// silently overwritten, reclassified, or blessed.

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/openclaw/crabbox/internal/custody"
)

// Legacy journal actions.
const (
	// JournalCompensated — an unacknowledged empty-payload row was
	// rebuilt in place from the authoritative terminal record: same
	// sequence position and chain linkage, canonical receipt bytes
	// now inside. The row was never witnessed, so no historical
	// record was altered — the obligation was pending, not evidence.
	JournalCompensated = "payload-compensated"
	// JournalLegacyWitnessed — an acknowledged empty-payload row was
	// recorded as a known legacy divergence. Its bytes are evidence
	// the witness already holds and stay byte-identical; the journal
	// entry is the operator-approved classification, so reconcile
	// treats it as covered-with-recorded-divergence rather than a
	// fresh contradiction.
	JournalLegacyWitnessed = "legacy-witnessed"
	// JournalUnverifiable — an empty-payload row whose authoritative
	// terminal record cannot be established. Quarantined in place:
	// REPAIR_REQUIRED stays open and a forensic escalation is owed.
	JournalUnverifiable = "unverifiable-legacy"
)

// LegacyRow is one outbox row whose envelope content is empty — the
// RC8.1 durable shape that predates canonical terminal payloads.
type LegacyRow struct {
	Seq          int64
	ExecutionID  string
	EnvelopeHash string
	Acked        bool
}

// MigrationJournalEntry is one append-only migration transition.
type MigrationJournalEntry struct {
	Seq         int64  `json:"seq"`
	RowSeq      int64  `json:"row_seq"`
	ExecutionID string `json:"execution_id"`
	Action      string `json:"action"`
	Detail      string `json:"detail"`
	CreatedAt   string `json:"created_at"`
}

// legacyJournalDDL is appended to the outbox schema at open — an
// additive, non-destructive table for the migration journal.
const legacyJournalDDL = `CREATE TABLE IF NOT EXISTS custody_migration_journal (
	seq INTEGER PRIMARY KEY AUTOINCREMENT,
	row_seq INTEGER NOT NULL,
	execution_id TEXT NOT NULL,
	action TEXT NOT NULL,
	detail TEXT NOT NULL,
	created_at TEXT NOT NULL
)`

// LegacyRows classifies every outbox row whose envelope content is
// empty: unacknowledged rows are compensation candidates (their
// payload is a pending obligation, not witnessed evidence);
// acknowledged rows are witnessed-legacy records whose bytes are
// already history the witness holds.
func (o *Outbox) LegacyRows(ctx context.Context) ([]LegacyRow, error) {
	rows, err := o.db.QueryContext(ctx,
		`SELECT seq, execution_id, envelope_hash, envelope_json, COALESCE(ack, '')
		 FROM custody_outbox ORDER BY seq`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LegacyRow
	for rows.Next() {
		var r LegacyRow
		var envJSON, ackJSON string
		if err := rows.Scan(&r.Seq, &r.ExecutionID, &r.EnvelopeHash, &envJSON, &ackJSON); err != nil {
			return nil, err
		}
		var env custody.Envelope
		if err := json.Unmarshal([]byte(envJSON), &env); err != nil {
			return nil, fmt.Errorf("legacy scan seq %d: %w", r.Seq, err)
		}
		content, err := env.ContentBytes()
		if err != nil || len(content) != 0 {
			continue
		}
		r.Acked = ackJSON != ""
		out = append(out, r)
	}
	return out, rows.Err()
}

// journal writes one append-only migration transition.
func (o *Outbox) journal(ctx context.Context, rowSeq int64, executionID, action, detail string) error {
	_, err := o.db.ExecContext(ctx,
		`INSERT INTO custody_migration_journal (row_seq, execution_id, action, detail, created_at)
		 VALUES ($1, $2, $3, $4, $5)`,
		rowSeq, executionID, action, detail, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

// MigrationJournal lists every recorded migration transition.
func (o *Outbox) MigrationJournal(ctx context.Context) ([]MigrationJournalEntry, error) {
	rows, err := o.db.QueryContext(ctx,
		`SELECT seq, row_seq, execution_id, action, detail, created_at
		 FROM custody_migration_journal ORDER BY seq`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MigrationJournalEntry
	for rows.Next() {
		var e MigrationJournalEntry
		if err := rows.Scan(&e.Seq, &e.RowSeq, &e.ExecutionID, &e.Action, &e.Detail, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// LegacyJournalAction returns the latest journal action recorded for
// an execution, or "" — reconcile consults this before escalating an
// empty-content divergence: a journaled classification is the
// operator-approved record, not a fresh contradiction.
func (o *Outbox) LegacyJournalAction(ctx context.Context, executionID string) (string, error) {
	var action string
	err := o.db.QueryRowContext(ctx,
		`SELECT action FROM custody_migration_journal WHERE execution_id = $1
		 ORDER BY seq DESC LIMIT 1`, executionID).Scan(&action)
	if err != nil {
		return "", nil // no classification recorded — not an error
	}
	return action, nil
}

// CompensateLegacyRow rebuilds an unacknowledged empty-payload row in
// place: same sequence position, epoch, and chain linkage (the row's
// recorded prev-hash), with the canonical terminal payload inside,
// re-signed by the deployment's custody signer. The row was never
// witnessed — nothing it contained was evidence — so replacing the
// pending obligation's content falsifies no history. Acknowledged
// rows are refused: their bytes are evidence the witness holds.
func (o *Outbox) CompensateLegacyRow(ctx context.Context, p Producer, rowSeq int64, receiptDigest string, native []byte) error {
	if len(native) == 0 {
		return fmt.Errorf("%w: compensation requires a non-empty canonical payload", ErrEvidenceContradiction)
	}
	tx, err := o.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var execID, envJSON, ackJSON string
	err = tx.QueryRowContext(ctx,
		`SELECT execution_id, envelope_json, COALESCE(ack, '') FROM custody_outbox WHERE seq = $1`, rowSeq).
		Scan(&execID, &envJSON, &ackJSON)
	if err != nil {
		return fmt.Errorf("compensate seq %d: %w", rowSeq, err)
	}
	if ackJSON != "" {
		return fmt.Errorf("%w: seq %d is already witnessed — its bytes are evidence and never rewritten", ErrEvidenceContradiction, rowSeq)
	}
	var env custody.Envelope
	if err := json.Unmarshal([]byte(envJSON), &env); err != nil {
		return fmt.Errorf("compensate seq %d: %w", rowSeq, err)
	}
	if b, berr := env.ContentBytes(); berr != nil || len(b) != 0 {
		return fmt.Errorf("%w: seq %d is not an empty-payload legacy row", ErrEvidenceContradiction, rowSeq)
	}
	rebuilt := custody.New(env.Family, env.DeploymentID, env.ReleaseIdentity, env.PolicyDigest,
		env.Subject, env.Sequence, env.Content.Encoding, native)
	if err := custody.Sign(rebuilt, custody.RoleKernelRelay, p.Signer); err != nil {
		return fmt.Errorf("compensate seq %d sign: %w", rowSeq, err)
	}
	envHash, err := rebuilt.Hash()
	if err != nil {
		return err
	}
	raw, err := json.Marshal(rebuilt)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE custody_outbox SET envelope_hash = $1, envelope_json = $2, receipt_digest = $3 WHERE seq = $4`,
		envHash, string(raw), receiptDigest, rowSeq); err != nil {
		return fmt.Errorf("compensate seq %d: %w", rowSeq, err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO custody_migration_journal (row_seq, execution_id, action, detail, created_at)
		 VALUES ($1, $2, $3, $4, $5)`,
		rowSeq, execID, JournalCompensated,
		fmt.Sprintf("empty payload rebuilt from authoritative terminal record (digest %s, linkage preserved)", receiptDigest),
		time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return err
	}
	return tx.Commit()
}

// JournalLegacyWitnessed records the operator-approved classification
// of an acknowledged empty-payload row: bytes untouched, divergence
// recorded, reconcile treats it as covered.
func (o *Outbox) JournalLegacyWitnessed(ctx context.Context, rowSeq int64, detail string) error {
	var execID, ackJSON string
	if err := o.db.QueryRowContext(ctx,
		`SELECT execution_id, COALESCE(ack, '') FROM custody_outbox WHERE seq = $1`, rowSeq).
		Scan(&execID, &ackJSON); err != nil {
		return fmt.Errorf("journal seq %d: %w", rowSeq, err)
	}
	if ackJSON == "" {
		return fmt.Errorf("seq %d is unacknowledged — compensate it, never journal-over a pending obligation", rowSeq)
	}
	return o.journal(ctx, rowSeq, execID, JournalLegacyWitnessed, detail)
}

// JournalUnverifiable quarantines an empty-payload row whose
// authoritative terminal record cannot be established: the row stays,
// REPAIR_REQUIRED stays open, and the journal records the forensic
// escalation owed.
func (o *Outbox) JournalUnverifiable(ctx context.Context, rowSeq int64, executionID, detail string) error {
	return o.journal(ctx, rowSeq, executionID, JournalUnverifiable, detail)
}
