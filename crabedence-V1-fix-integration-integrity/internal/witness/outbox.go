package witness

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
	} {
		if _, err := db.Exec(stmt); err != nil {
			db.Close()
			return nil, fmt.Errorf("custody outbox schema: %w", err)
		}
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
		return 0, fmt.Errorf("custody outbox enqueue: execution %s already queued with different receipt bytes — an evidence contradiction, never overwritten", executionID)
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

// PendingRow is one queued custody obligation.
type PendingRow struct {
	Seq          int64
	ExecutionID  string
	EnvelopeHash string
	Envelope     *custody.Envelope
	Ack          *Ack
}

func (o *Outbox) rowsFrom(ctx context.Context, fromSeq int64) ([]PendingRow, error) {
	rows, err := o.db.QueryContext(ctx,
		`SELECT seq, execution_id, envelope_hash, envelope_json, COALESCE(ack, '')
		 FROM custody_outbox WHERE seq >= $1 ORDER BY seq`, fromSeq)
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
