package witness

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/openclaw/crabbox/internal/custody"
	"github.com/openclaw/crabbox/internal/evidence"
)

// Producer builds the receipt-family envelopes the outbox stores — the
// kernel's custody identity: deployment, release binding, policy
// digest, and the kernel-relay signing key. Every field is controlled
// configuration, never learned from the evidence being wrapped.
type Producer struct {
	DeploymentID string
	Release      custody.ReleaseIdentity
	PolicyDigest string
	// Signer is the kernel-relay key. Custodian keys and release-control
	// operator keys are distinct classes — never substitute them here.
	Signer *evidence.Signer
}

// Outbox is the kernel-side durable custody queue. Terminal receipts
// are wrapped in signed custody-envelope-v1 records and queued before
// the dispatch or resolution response returns, so a crash cannot lose
// evidence the kernel already committed. Rows stay after delivery —
// if the witness restores from an older checkpoint the resend path can
// re-custody them.
//
// Chain construction is transactional: the next sequence index and the
// previous-record linkage are derived inside the same immediate
// transaction that inserts the row, so a concurrent or racing enqueuer
// cannot fork the stream.
type Outbox struct {
	db *sql.DB
	// migrationHook is a test-only fault-injection seam used to prove
	// crash-before-commit and crash-after-commit recovery. Nil in
	// production.
	migrationHook func(stage string) error
}

// OpenOutbox opens the kernel custody outbox. The containing directory
// is created at 0700 when absent — the outbox holds the same evidence
// the custody boundary protects.
func OpenOutbox(path string) (*Outbox, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("custody outbox dir: %w", err)
	}
	if st, err := os.Stat(dir); err == nil && st.Mode().Perm() != 0o700 {
		return nil, fmt.Errorf("custody outbox directory %q is accessible by group/other (mode %04o)", dir, st.Mode().Perm())
	}
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)"+
		"&_pragma=synchronous(FULL)&_pragma=busy_timeout(5000)"+
		"&_pragma=temp_store(MEMORY)&_txlock=immediate", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	for _, stmt := range []string{
		`CREATE TABLE IF NOT EXISTS custody_outbox (
			seq INTEGER PRIMARY KEY,
			execution_id TEXT NOT NULL,
			receipt_digest TEXT NOT NULL,
			envelope_hash TEXT NOT NULL,
			envelope_json TEXT NOT NULL,
			ack TEXT,
			delivered_at TEXT,
			created_at TEXT NOT NULL,
			UNIQUE (execution_id)
		)`,
		`CREATE TABLE IF NOT EXISTS outbox_meta (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS custody_events (
			seq INTEGER PRIMARY KEY AUTOINCREMENT,
			event TEXT NOT NULL,
			detail TEXT NOT NULL,
			created_at TEXT NOT NULL
		)`,
		legacyJournalDDL,
		nonceLedgerDDL,
		fenceIntentDDL,
	} {
		if _, err := db.Exec(stmt); err != nil {
			db.Close()
			return nil, fmt.Errorf("custody outbox schema: %w", err)
		}
	}
	if err := ensureLegacyJournalSchema(context.Background(), db); err != nil {
		db.Close()
		return nil, err
	}
	// SQLite creates the database and its WAL/SHM siblings with the
	// process umask (typically 0644). The outbox holds custody evidence;
	// tighten the files to owner-only at open so read-only inspection can
	// require an owner-only artifact without rejecting valid outboxes.
	if err := tightenOutboxPermissions(path); err != nil {
		db.Close()
		return nil, err
	}
	return &Outbox{db: db}, nil
}

func tightenOutboxPermissions(path string) error {
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		if err := os.Chmod(p, 0o600); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("custody outbox permissions %s: %w", p, err)
		}
	}
	return nil
}

// OpenOutboxReadOnly opens an existing custody outbox for forensic
// inspection without creating, migrating, or writing anything. A
// missing or group/other-accessible file is refused: a read-only
// operator command must never manufacture the evidence it inspects.
func OpenOutboxReadOnly(path string) (*Outbox, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("custody outbox %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("custody outbox %s is not a regular file", path)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("custody outbox %s mode %04o grants group/other access", path, perm)
	}
	dsn := fmt.Sprintf("file:%s?mode=ro&_pragma=busy_timeout(5000)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	return &Outbox{db: db}, nil
}

// Close releases the outbox.
func (o *Outbox) Close() error { return o.db.Close() }

// Enqueue wraps one terminal receipt in a signed receipt-family
// envelope and durably records the custody obligation, returning the
// assigned sequence index. The envelope's index and chain linkage are
// assigned inside the transaction, so the signed record's position is
// the durable position — a witness sees exactly the order the kernel
// committed. Re-enqueueing the same execution with the same receipt is
// idempotent; the same execution with different bytes is a
// contradiction the ledger refuses rather than overwriting.
func (o *Outbox) Enqueue(ctx context.Context, p Producer, executionID, receiptDigest string, native []byte) (int64, error) {
	// An empty payload is never a legitimate obligation — an envelope
	// with no content is evidence the witness can never verify, so the
	// obligation is refused here at the boundary and the caller marks
	// custody degraded.
	if len(native) == 0 {
		return 0, fmt.Errorf("%w: execution %s has no receipt payload to custody", ErrEvidenceContradiction, executionID)
	}
	tx, err := o.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("custody outbox enqueue: %w", err)
	}
	defer tx.Rollback()

	// Idempotent enqueue: an existing obligation for this execution is
	// the same obligation — unless the payload differs, which is an
	// evidence contradiction, not a retry.
	var existingSeq int64
	var existingEnv string
	err = tx.QueryRowContext(ctx,
		`SELECT seq, envelope_json FROM custody_outbox WHERE execution_id = $1`, executionID).
		Scan(&existingSeq, &existingEnv)
	if err == nil {
		var prior custody.Envelope
		if uerr := json.Unmarshal([]byte(existingEnv), &prior); uerr == nil {
			if b, berr := prior.ContentBytes(); berr == nil && string(b) == string(native) {
				tx.Rollback()
				return existingSeq, nil
			}
		}
		tx.Rollback()
		return 0, fmt.Errorf("%w: execution %s already queued with different receipt bytes — never overwritten", ErrEvidenceContradiction, executionID)
	}
	if err != sql.ErrNoRows {
		return 0, fmt.Errorf("custody outbox enqueue: %w", err)
	}

	var head int64
	var headHash string
	err = tx.QueryRowContext(ctx,
		`SELECT seq, envelope_hash FROM custody_outbox ORDER BY seq DESC LIMIT 1`).
		Scan(&head, &headHash)
	if err != nil && err != sql.ErrNoRows {
		return 0, fmt.Errorf("custody outbox head: %w", err)
	}
	next := int64(1)
	prev := ""
	if err == nil {
		next = head + 1
		prev = headHash
	}
	var epoch int64
	err = tx.QueryRowContext(ctx, `SELECT CAST(value AS INTEGER) FROM outbox_meta WHERE key='custody_epoch'`).Scan(&epoch)
	if err == sql.ErrNoRows {
		epoch = 0
	} else if err != nil {
		return 0, fmt.Errorf("custody outbox epoch: %w", err)
	}

	env := custody.New(custody.FamilyReceipt, p.DeploymentID, p.Release, p.PolicyDigest,
		custody.Subject{EffectID: executionID, ExecutionID: executionID},
		custody.Sequence{
			Domain:                 custody.FamilyReceipt,
			Epoch:                  epoch,
			Index:                  next,
			PreviousCheckpointHash: prev,
		},
		custody.EncodingWitnessFrame, native)
	if err := custody.Sign(env, custody.RoleKernelRelay, p.Signer); err != nil {
		return 0, fmt.Errorf("custody outbox sign: %w", err)
	}
	envHash, err := env.Hash()
	if err != nil {
		return 0, err
	}
	envJSON, err := json.Marshal(env)
	if err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO custody_outbox (seq, execution_id, receipt_digest, envelope_hash, envelope_json, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		next, executionID, receiptDigest, envHash, string(envJSON),
		time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return 0, fmt.Errorf("custody outbox enqueue: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("custody outbox enqueue commit: %w", err)
	}
	return next, nil
}

// AdvanceEpoch records a kernel custody-epoch advance. Epochs move
// only forward — the witness refuses prior-epoch replays.
func (o *Outbox) AdvanceEpoch(ctx context.Context, epoch int64) error {
	res, err := o.db.ExecContext(ctx,
		`INSERT INTO outbox_meta (key, value) VALUES ('custody_epoch', $1)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value
		 WHERE CAST(outbox_meta.value AS INTEGER) < excluded.value`,
		fmt.Sprintf("%d", epoch))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		var cur int64
		if err := o.db.QueryRowContext(ctx, `SELECT CAST(value AS INTEGER) FROM outbox_meta WHERE key='custody_epoch'`).Scan(&cur); err == nil && cur >= epoch {
			return fmt.Errorf("custody epoch regression refused: current %d, requested %d", cur, epoch)
		}
		return fmt.Errorf("custody epoch advance failed")
	}
	return nil
}

// Undelivered counts rows without a recorded acknowledgement — the
// custody backlog the fail-closed gate inspects.
func (o *Outbox) Undelivered(ctx context.Context) (int64, error) {
	var n int64
	err := o.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM custody_outbox WHERE delivered_at IS NULL`).Scan(&n)
	return n, err
}

// Pending lists every queued custody obligation from sequence 1 —
// the operator/forensic view of the durable queue (delivered rows
// are retained, so this includes obligations already acknowledged).
// It materializes the whole queue; bounded callers use PendingPage.
func (o *Outbox) Pending(ctx context.Context) ([]PendingRow, error) {
	return o.rowsFrom(ctx, 1)
}

// PendingPage returns at most limit queued obligations strictly after
// afterSeq — SQL cursor pagination with no whole-queue materialization.
// limit must be positive and is capped by the caller.
func (o *Outbox) PendingPage(ctx context.Context, afterSeq int64, limit int) ([]PendingRow, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("custody outbox page: limit must be positive")
	}
	return o.rowsPage(ctx, afterSeq, limit)
}

// PendingRow is one queued custody obligation.
type PendingRow struct {
	Seq          int64
	ExecutionID  string
	EnvelopeHash string
	Envelope     *custody.Envelope
	Ack          *Ack
}

func (o *Outbox) rowsFrom(ctx context.Context, fromSeq int64) ([]PendingRow, error) {
	return o.rowsPage(ctx, fromSeq-1, 0)
}

// rowsPage reads rows strictly after afterSeq, capped at limit (0 =
// unbounded). The cursor lives in SQL; only one page is materialized.
func (o *Outbox) rowsPage(ctx context.Context, afterSeq int64, limit int) ([]PendingRow, error) {
	q := `SELECT seq, execution_id, envelope_hash, envelope_json, COALESCE(ack, '')
	      FROM custody_outbox WHERE seq > $1 ORDER BY seq`
	args := []any{afterSeq}
	if limit > 0 {
		q += ` LIMIT $2`
		args = append(args, limit)
	}
	rows, err := o.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PendingRow
	for rows.Next() {
		var r PendingRow
		var envJSON, ackJSON string
		if err := rows.Scan(&r.Seq, &r.ExecutionID, &r.EnvelopeHash, &envJSON, &ackJSON); err != nil {
			return nil, err
		}
		r.Envelope = &custody.Envelope{}
		if err := json.Unmarshal([]byte(envJSON), r.Envelope); err != nil {
			return nil, fmt.Errorf("stored outbox envelope %d does not parse: %w", r.Seq, err)
		}
		if ackJSON != "" {
			if r.Ack, err = decodeAck(ackJSON); err != nil {
				return nil, err
			}
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// StoredPayload returns the custody content bytes recorded for an
// execution — the obligation replay scanner's byte-level coverage
// check: presence alone is not coverage, the same execution must
// hold the same receipt.
func (o *Outbox) StoredPayload(ctx context.Context, executionID string) ([]byte, bool, error) {
	var envJSON string
	err := o.db.QueryRowContext(ctx,
		`SELECT envelope_json FROM custody_outbox WHERE execution_id = $1`, executionID).Scan(&envJSON)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	var env custody.Envelope
	if err := json.Unmarshal([]byte(envJSON), &env); err != nil {
		return nil, false, fmt.Errorf("stored outbox envelope for %s does not parse: %w", executionID, err)
	}
	content, err := env.ContentBytes()
	if err != nil {
		return nil, false, fmt.Errorf("stored outbox envelope for %s has no verifiable content: %w", executionID, err)
	}
	return content, true, nil
}

// StoredHash returns the envelope hash recorded at seq — the
// contradiction check against a checkpoint head that claims custody of
// something else at that index.
func (o *Outbox) StoredHash(ctx context.Context, seq int64) (string, error) {
	var h string
	err := o.db.QueryRowContext(ctx, `SELECT envelope_hash FROM custody_outbox WHERE seq = $1`, seq).Scan(&h)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return h, err
}

// markDelivered records a verified acknowledgement — idempotently: a
// byte-identical re-ack is a redelivery, a conflicting ack on the same
// row is a contradiction and is refused rather than overwriting the
// custody record.
func (o *Outbox) markDelivered(ctx context.Context, seq int64, ack *Ack) error {
	ackJSON, err := json.Marshal(ack)
	if err != nil {
		return err
	}
	res, err := o.db.ExecContext(ctx,
		`UPDATE custody_outbox SET ack = $1, delivered_at = COALESCE(delivered_at, $2) WHERE seq = $3`,
		string(ackJSON), time.Now().UTC().Format(time.RFC3339Nano), seq)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("custody ack persist: row %d missing", seq)
	}
	return nil
}

// StoredAck returns the recorded acknowledgement for a row, if any —
// restart reconciliation treats an acked row as already custodied,
// never re-executed.
func (o *Outbox) StoredAck(ctx context.Context, seq int64) (*Ack, error) {
	var raw string
	err := o.db.QueryRowContext(ctx, `SELECT COALESCE(ack, '') FROM custody_outbox WHERE seq = $1`, seq).Scan(&raw)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if raw == "" {
		return nil, nil
	}
	return decodeAck(raw)
}

// ─── Durable custody state ───────────────────────────────────────────
//
// Custody health is durable state, not a process-memory observation:
// an enqueue failure or an evidence contradiction survives restart and
// can never be cleared by an unrelated successful drain. The events
// table is the append-only audit trail — every transition records what
// changed, why, and the evidence that authorized it.
//
// ErrEvidenceContradiction marks contradictions the store refuses to
// overwrite — an obligation queued under different bytes than the
// record claims, or a conflicting acknowledgement. Contradictions are
// sticky: they move custody to REPAIR_REQUIRED, which only an explicit
// verified repair clears.
var ErrEvidenceContradiction = errors.New("custody outbox: evidence contradiction")

const (
	metaDegradedReason   = "degraded_reason"
	metaRepairReason     = "repair_reason"
	metaRepairGeneration = "repair_generation"
	metaObligationHWM    = "obligation_hwm"
)

// CustodyStatus is the durable custody posture persisted in the outbox.
type CustodyStatus struct {
	// DegradedReason, when non-empty, is a recorded custody-obligation
	// failure (enqueue/persist) that has not been discharged by a
	// verified repair. Durable — survives restart.
	DegradedReason string
	// RepairReason, when non-empty, is a recorded evidence
	// contradiction or fork — sticky until an explicit verified
	// operator repair clears it.
	RepairReason string
	// RepairGeneration increments on every contradiction assertion,
	// including a repeat of the same reason. A repair captures it
	// before scanning and clears only if it is unchanged, so a
	// same-reason contradiction during the scan cannot be erased by a
	// string-only comparison (ABA).
	RepairGeneration int64
	// ObligationHWM is the high-water terminal_seq below which every
	// terminal record was verified to hold an outbox obligation.
	ObligationHWM int64
}

func (o *Outbox) meta(ctx context.Context, key string) (string, error) {
	var v string
	err := o.db.QueryRowContext(ctx, `SELECT value FROM outbox_meta WHERE key = $1`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return v, err
}

func (o *Outbox) setMeta(ctx context.Context, key, value string) error {
	_, err := o.db.ExecContext(ctx, `INSERT INTO outbox_meta (key, value) VALUES ($1, $2)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

func (o *Outbox) recordEvent(ctx context.Context, event, detail string) {
	// The event row is best-effort relative to the state write it
	// describes — a state write that landed but whose event failed is
	// still authoritative (the state itself is the evidence).
	_, _ = o.db.ExecContext(ctx,
		`INSERT INTO custody_events (event, detail, created_at) VALUES ($1, $2, $3)`,
		event, detail, time.Now().UTC().Format(time.RFC3339Nano))
}

// CustodyStatus reads the durable custody posture.
func (o *Outbox) CustodyStatus(ctx context.Context) (CustodyStatus, error) {
	var st CustodyStatus
	var err error
	if st.DegradedReason, err = o.meta(ctx, metaDegradedReason); err != nil {
		return st, err
	}
	if st.RepairReason, err = o.meta(ctx, metaRepairReason); err != nil {
		return st, err
	}
	gen, err := o.meta(ctx, metaRepairGeneration)
	if err != nil {
		return st, err
	}
	if gen != "" {
		st.RepairGeneration, err = strconv.ParseInt(gen, 10, 64)
		if err != nil {
			return st, fmt.Errorf("custody outbox: corrupt repair_generation %q", gen)
		}
	}
	hw, err := o.meta(ctx, metaObligationHWM)
	if err != nil {
		return st, err
	}
	if hw != "" {
		st.ObligationHWM, err = strconv.ParseInt(hw, 10, 64)
		if err != nil {
			return st, fmt.Errorf("custody outbox: corrupt obligation_hwm %q", hw)
		}
	}
	return st, nil
}

// MarkDegraded durably records a custody-obligation failure — a
// terminal receipt whose enqueue or persistence failed. The marker
// survives restart and is never cleared by an unrelated successful
// drain: only RepairDegraded's verified rescan discharges it. A write
// failure here is itself the custody failure domain — callers treat
// it as degraded.
func (o *Outbox) MarkDegraded(ctx context.Context, reason string) error {
	if err := o.setMeta(ctx, metaDegradedReason, reason); err != nil {
		return fmt.Errorf("custody degraded marker: %w", err)
	}
	o.recordEvent(ctx, "degraded", reason)
	return nil
}

// MarkRepairRequired durably records an evidence contradiction — a
// fork, a conflicting ack, or a contradictory obligation. Sticky:
// cleared only by an explicit verified operator repair. The reason and
// the monotonic repair generation are written in one transaction, so
// every assertion is observable even when the reason string repeats.
func (o *Outbox) MarkRepairRequired(ctx context.Context, reason string) error {
	tx, err := o.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("custody repair marker: %w", err)
	}
	defer tx.Rollback()
	var curRaw string
	if err := tx.QueryRowContext(ctx,
		`SELECT COALESCE((SELECT value FROM outbox_meta WHERE key = $1), '')`,
		metaRepairGeneration).Scan(&curRaw); err != nil {
		return fmt.Errorf("custody repair generation: %w", err)
	}
	var cur int64
	if curRaw != "" {
		if cur, err = strconv.ParseInt(curRaw, 10, 64); err != nil {
			return fmt.Errorf("custody outbox: corrupt repair_generation %q", curRaw)
		}
	}
	next := strconv.FormatInt(cur+1, 10)
	if err := setMetaTx(ctx, tx, metaRepairGeneration, next); err != nil {
		return fmt.Errorf("custody repair generation: %w", err)
	}
	if err := setMetaTx(ctx, tx, metaRepairReason, reason); err != nil {
		return fmt.Errorf("custody repair marker: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO custody_events (event, detail, created_at) VALUES ($1, $2, $3)`,
		"repair_required", fmt.Sprintf("generation=%s reason=%s", next, reason),
		time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return fmt.Errorf("custody repair event: %w", err)
	}
	return tx.Commit()
}

func setMetaTx(ctx context.Context, tx *sql.Tx, key, value string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO outbox_meta (key, value) VALUES ($1, $2)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

// RepairDegraded discharges a degraded marker after a verified repair:
// the caller must have re-scanned the terminal-obligation stream,
// restored every missing obligation, and completed a verified drain —
// the evidence string records that fact for audit. It never touches a
// repair-required marker: a contradiction is a separate operator act,
// and a degraded marker is never an excuse to clear it.
func (o *Outbox) RepairDegraded(ctx context.Context, evidence string) error {
	st, err := o.CustodyStatus(ctx)
	if err != nil {
		return err
	}
	if st.DegradedReason == "" {
		return nil
	}
	if err := o.setMeta(ctx, metaDegradedReason, ""); err != nil {
		return fmt.Errorf("custody degraded clear: %w", err)
	}
	o.recordEvent(ctx, "degraded_repaired", evidence+" | was: "+st.DegradedReason)
	return nil
}

// ClearRepairRequired is the operator repair path for a contradiction
// marker: it clears only after the caller's verified rescan, and
// records the operator-supplied evidence note. Refuses to run while a
// degraded marker is still open — the obligation failure must be
// discharged first.
func (o *Outbox) ClearRepairRequired(ctx context.Context, evidence string) error {
	st, err := o.CustodyStatus(ctx)
	if err != nil {
		return err
	}
	if st.DegradedReason != "" {
		return fmt.Errorf("custody still degraded (%s) — discharge it before clearing repair", st.DegradedReason)
	}
	if st.RepairReason == "" {
		return nil
	}
	if err := o.setMeta(ctx, metaRepairReason, ""); err != nil {
		return fmt.Errorf("custody repair clear: %w", err)
	}
	o.recordEvent(ctx, "repair_completed", evidence+" | was: "+st.RepairReason)
	return nil
}

// ErrStaleRepairVerification marks a repair whose verification no
// longer describes the marker it is about to clear — a concurrent
// contradiction or degraded event landed after the scan began.
var ErrStaleRepairVerification = errors.New("custody repair: verification is stale — the repair marker changed after the scan")

// ClearRepairRequiredIfUnchanged is the transactionally safe repair
// clear: it compares the marker reason and the monotonic repair
// generation the verified scan observed and refuses if either changed,
// so a same-reason contradiction or an ABA cycle cannot be discharged
// by stale work. The event row is written in the same transaction as
// the state change.
func (o *Outbox) ClearRepairRequiredIfUnchanged(ctx context.Context, expectedReason string, expectedGeneration int64, evidence string) error {
	if expectedReason == "" {
		return fmt.Errorf("custody repair clear: expected marker reason is empty")
	}
	tx, err := o.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var degraded, repair, genRaw string
	if err := tx.QueryRowContext(ctx,
		`SELECT COALESCE((SELECT value FROM outbox_meta WHERE key = $1), '')`,
		metaDegradedReason).Scan(&degraded); err != nil {
		return err
	}
	if err := tx.QueryRowContext(ctx,
		`SELECT COALESCE((SELECT value FROM outbox_meta WHERE key = $1), '')`,
		metaRepairReason).Scan(&repair); err != nil {
		return err
	}
	if err := tx.QueryRowContext(ctx,
		`SELECT COALESCE((SELECT value FROM outbox_meta WHERE key = $1), '')`,
		metaRepairGeneration).Scan(&genRaw); err != nil {
		return err
	}
	var gen int64
	if genRaw != "" {
		if gen, err = strconv.ParseInt(genRaw, 10, 64); err != nil {
			return fmt.Errorf("custody outbox: corrupt repair_generation %q", genRaw)
		}
	}
	if degraded != "" {
		return fmt.Errorf("custody still degraded (%s) — discharge it before clearing repair", degraded)
	}
	if repair == "" {
		return nil
	}
	if repair != expectedReason || gen != expectedGeneration {
		return fmt.Errorf("%w: marker is now reason=%q generation=%d, scan verified reason=%q generation=%d",
			ErrStaleRepairVerification, repair, gen, expectedReason, expectedGeneration)
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE outbox_meta SET value = '' WHERE key = $1`, metaRepairReason); err != nil {
		return fmt.Errorf("custody repair clear: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO custody_events (event, detail, created_at) VALUES ($1, $2, $3)`,
		"repair_completed", evidence+" | was: "+repair,
		time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return fmt.Errorf("custody repair event: %w", err)
	}
	return tx.Commit()
}

// ObligationHighWater records the verified obligation high-water mark:
// every terminal record at or below seq was confirmed to hold an
// outbox obligation. Monotonic — regression writes are refused.
func (o *Outbox) ObligationHighWater(ctx context.Context) (int64, error) {
	hw, err := o.meta(ctx, metaObligationHWM)
	if err != nil || hw == "" {
		return 0, err
	}
	return strconv.ParseInt(hw, 10, 64)
}

// AdvanceObligationHWM raises the obligation high-water mark to seq —
// or leaves it. The mark only moves forward.
func (o *Outbox) AdvanceObligationHWM(ctx context.Context, seq int64) error {
	cur, err := o.ObligationHighWater(ctx)
	if err != nil {
		return err
	}
	if seq <= cur {
		return nil
	}
	if err := o.setMeta(ctx, metaObligationHWM, strconv.FormatInt(seq, 10)); err != nil {
		return err
	}
	o.recordEvent(ctx, "obligation_hwm", fmt.Sprintf("advanced %d → %d", cur, seq))
	return nil
}

// MissingObligations returns the subset of executionIDs that hold no
// outbox row — the obligations the replay scanner must restore.
func (o *Outbox) MissingObligations(ctx context.Context, executionIDs []string) (map[string]bool, error) {
	missing := make(map[string]bool, len(executionIDs))
	if len(executionIDs) == 0 {
		return missing, nil
	}
	for _, id := range executionIDs {
		missing[id] = true
	}
	present, err := o.obligationsPresent(ctx, executionIDs)
	if err != nil {
		return nil, err
	}
	for _, id := range present {
		delete(missing, id)
	}
	return missing, nil
}

func (o *Outbox) obligationsPresent(ctx context.Context, executionIDs []string) ([]string, error) {
	var present []string
	// Chunked IN() lookups — bounded placeholder lists keep the driver
	// happy on large backlogs.
	const chunk = 500
	for i := 0; i < len(executionIDs); i += chunk {
		end := i + chunk
		if end > len(executionIDs) {
			end = len(executionIDs)
		}
		part := executionIDs[i:end]
		var sb strings.Builder
		sb.WriteString(`SELECT execution_id FROM custody_outbox WHERE execution_id IN (`)
		args := make([]any, len(part))
		for j, id := range part {
			if j > 0 {
				sb.WriteByte(',')
			}
			fmt.Fprintf(&sb, "$%d", j+1)
			args[j] = id
		}
		sb.WriteByte(')')
		rows, err := o.db.QueryContext(ctx, sb.String(), args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return nil, err
			}
			present = append(present, id)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		rows.Close()
	}
	return present, nil
}

// CustodyEvents returns the durable transition audit log, oldest
// first — the independently auditable record of every degraded,
// repair, and high-water transition.
func (o *Outbox) CustodyEvents(ctx context.Context, limit int) ([]string, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := o.db.QueryContext(ctx,
		`SELECT created_at, event, detail FROM custody_events ORDER BY seq DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var at, ev, d string
		if err := rows.Scan(&at, &ev, &d); err != nil {
			return nil, err
		}
		out = append(out, fmt.Sprintf("%s %-18s %s", at, ev, d))
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, rows.Err()
}
