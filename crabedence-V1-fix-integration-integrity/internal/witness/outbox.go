package witness

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"
)

// Outbox is the kernel-side durable custody queue. Terminal receipts
// are enqueued before the dispatch or resolution response returns, so
// a crash cannot lose evidence the kernel already reported. Rows stay
// after delivery — if the witness restores from an older checkpoint
// the resend path can re-custody them.
type Outbox struct {
	db *sql.DB
}

// OpenOutbox opens the kernel custody outbox. The containing
// directory is created at 0700 when absent — the outbox holds the
// same evidence the custody boundary protects.
func OpenOutbox(path string) (*Outbox, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("custody outbox dir: %w", err)
	}
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)"+
		"&_pragma=synchronous(FULL)&_pragma=busy_timeout(5000)"+
		"&_pragma=temp_store(MEMORY)&_txlock=immediate", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS custody_outbox (
		seq INTEGER PRIMARY KEY AUTOINCREMENT,
		execution_id TEXT NOT NULL,
		receipt_digest TEXT NOT NULL,
		payload BLOB,
		ack TEXT,
		delivered_at TEXT
	)`); err != nil {
		db.Close()
		return nil, fmt.Errorf("custody outbox schema: %w", err)
	}
	return &Outbox{db: db}, nil
}

// Close releases the outbox.
func (o *Outbox) Close() error { return o.db.Close() }

// Enqueue appends one terminal receipt and returns its sequence. The
// sequence is the per-deployment custody order the witness enforces.
func (o *Outbox) Enqueue(ctx context.Context, executionID, receiptDigest string, payload []byte) (int64, error) {
	res, err := o.db.ExecContext(ctx,
		`INSERT INTO custody_outbox (execution_id, receipt_digest, payload) VALUES ($1, $2, $3)`,
		executionID, receiptDigest, payload)
	if err != nil {
		return 0, fmt.Errorf("custody outbox enqueue: %w", err)
	}
	return res.LastInsertId()
}

// Undelivered counts rows without an acknowledgement — the custody
// backlog the fail-closed gate inspects.
func (o *Outbox) Undelivered(ctx context.Context) (int64, error) {
	var n int64
	err := o.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM custody_outbox WHERE delivered_at IS NULL`).Scan(&n)
	return n, err
}

type pendingRow struct {
	seq           int64
	executionID   string
	receiptDigest string
	payload       []byte
}

func (o *Outbox) rowsFrom(ctx context.Context, fromSeq int64) ([]pendingRow, error) {
	rows, err := o.db.QueryContext(ctx,
		`SELECT seq, execution_id, receipt_digest, COALESCE(payload, x'')
		 FROM custody_outbox WHERE seq >= $1 ORDER BY seq`, fromSeq)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []pendingRow
	for rows.Next() {
		var r pendingRow
		if err := rows.Scan(&r.seq, &r.executionID, &r.receiptDigest, &r.payload); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (o *Outbox) markDelivered(ctx context.Context, seq int64, ack *Ack) error {
	ackJSON, err := json.Marshal(ack)
	if err != nil {
		return err
	}
	_, err = o.db.ExecContext(ctx,
		`UPDATE custody_outbox SET ack = $1, delivered_at = $2 WHERE seq = $3`,
		string(ackJSON), time.Now().UTC().Format(time.RFC3339Nano), seq)
	return err
}

// Sender drains the outbox to the witness with restart-safe realignment:
// each iteration checkpoints the witness head, then submits every
// outbox row from head+1 forward. A witness restored from an older
// checkpoint is re-custodied; a divergent custody row is refused by the
// witness and degrades the sender rather than overwriting history.
type Sender struct {
	client   *Client
	outbox   *Outbox
	deployFP string
	log      *slog.Logger

	lastErr atomic.Value // string — most recent transport/refusal error
	stopped chan struct{}
	once    sync.Once
}

// NewSender wires the kernel-side drain loop.
func NewSender(client *Client, outbox *Outbox, deploymentFP string, log *slog.Logger) *Sender {
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Sender{client: client, outbox: outbox, deployFP: deploymentFP, log: log, stopped: make(chan struct{})}
}

// CustodyHealthy reports whether the custody path is clean: no pending
// backlog and no recent transport failure. The fail-closed gate for
// CRITICAL admissions consults it.
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

// Run drains until ctx ends or Stop fires. One attempt pass runs every
// interval and after every successful submission burst.
func (s *Sender) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 2 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		s.drain(ctx)
		select {
		case <-ctx.Done():
			return
		case <-s.stopped:
			return
		case <-t.C:
		}
	}
}

func (s *Sender) drain(ctx context.Context) {
	head, _, _, err := s.client.Checkpoint(ctx, s.deployFP)
	if err != nil {
		s.lastErr.Store(fmt.Sprintf("witness checkpoint: %v", err))
		s.log.Warn("custody witness unreachable", "error", err)
		return
	}
	// Resume from the custody head: delivers pending rows and, after a
	// witness restore to an older checkpoint, re-delivers rows the
	// witness no longer holds. Identical resubmissions return the
	// stored ack — divergence is refused by the witness.
	rows, err := s.outbox.rowsFrom(ctx, head+1)
	if err != nil {
		s.lastErr.Store(fmt.Sprintf("custody outbox read: %v", err))
		return
	}
	for _, r := range rows {
		ack, err := s.client.Submit(ctx, Request{
			DeploymentFP:  s.deployFP,
			Seq:           r.seq,
			ExecutionID:   r.executionID,
			ReceiptDigest: r.receiptDigest,
			Payload:       r.payload,
		})
		if err != nil {
			s.lastErr.Store(fmt.Sprintf("witness submit seq %d: %v", r.seq, err))
			s.log.Warn("custody submission failed — sender degraded until next checkpoint",
				"seq", r.seq, "execution", r.executionID, "error", err)
			return
		}
		if err := s.outbox.markDelivered(ctx, r.seq, ack); err != nil {
			s.lastErr.Store(fmt.Sprintf("custody ack persist: %v", err))
			return
		}
	}
	s.lastErr.Store("")
}
