package witness

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"

	"github.com/openclaw/crabbox/internal/evidence"
)

// Ledger is the witness's append-only custody log. It exposes insert
// and read operations only — no update or delete path exists, so the
// custody record a kernel cannot reach stays intact. Sequence is the
// per-deployment custody head: submissions must extend it by exactly
// one, which is what makes rollback-disguise and replay rejection
// structural rather than procedural.
type Ledger struct {
	db *sql.DB
}

// ErrDeploymentMismatch is returned when a submission names a
// deployment other than the one this witness is bound to.
var ErrDeploymentMismatch = errors.New("witness: deployment fingerprint mismatch")

// ErrSequence is returned for gap, replay-with-different-content, or
// already-final sequence violations.
var ErrSequence = errors.New("witness: sequence violation")

// ErrReceiptVerify is returned when a signed payload does not verify
// under the deployment signer.
var ErrReceiptVerify = errors.New("witness: receipt signature invalid")

// CustodyRow is one stored submission.
type CustodyRow struct {
	DeploymentFP  string
	Seq           int64
	ExecutionID   string
	ReceiptDigest string
	Payload       json.RawMessage
	Ack           *Ack
	ReceivedAt    time.Time
}

// OpenLedger opens (creating if needed) the append-only custody log.
// The containing directory must be 0700 — same rule as the effect
// store, for the same reason.
func OpenLedger(path string) (*Ledger, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("witness ledger dir: %w", err)
	}
	if st, err := os.Stat(dir); err == nil && st.Mode().Perm() != 0o700 {
		return nil, fmt.Errorf("witness ledger directory %q is accessible by group/other (mode %04o): custody storage must live under 0700", dir, st.Mode().Perm())
	}
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)"+
		"&_pragma=synchronous(FULL)&_pragma=busy_timeout(5000)"+
		"&_pragma=temp_store(MEMORY)&_txlock=immediate", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	for _, stmt := range []string{
		`CREATE TABLE IF NOT EXISTS witness_meta (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS custody_log (
			deployment_fp TEXT NOT NULL,
			seq INTEGER NOT NULL,
			execution_id TEXT NOT NULL,
			receipt_digest TEXT NOT NULL,
			payload BLOB,
			ack TEXT NOT NULL,
			received_at TEXT NOT NULL,
			PRIMARY KEY (deployment_fp, seq),
			UNIQUE (deployment_fp, execution_id)
		)`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			db.Close()
			return nil, fmt.Errorf("witness ledger schema: %w", err)
		}
	}
	return &Ledger{db: db}, nil
}

// Close releases the ledger.
func (l *Ledger) Close() error { return l.db.Close() }

// BoundDeployment returns the deployment fingerprint this witness is
// bound to — the configured pin when provided, else the first-seen
// fingerprint persisted under TOFU.
func (l *Ledger) BoundDeployment(ctx context.Context) (string, error) {
	var fp string
	err := l.db.QueryRowContext(ctx, `SELECT value FROM witness_meta WHERE key = 'deployment_fp'`).Scan(&fp)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return fp, err
}

func (l *Ledger) bindDeployment(ctx context.Context, fp string) error {
	_, err := l.db.ExecContext(ctx, `INSERT INTO witness_meta (key, value) VALUES ('deployment_fp', $1)`, fp)
	return err
}

// Head returns the deployment's custody head — the highest contiguous
// sequence stored — and the identity of the head row.
func (l *Ledger) Head(ctx context.Context, deploymentFP string) (seq int64, executionID, digest string, err error) {
	err = l.db.QueryRowContext(ctx, `
		SELECT seq, execution_id, receipt_digest FROM custody_log
		WHERE deployment_fp = $1 ORDER BY seq DESC LIMIT 1`, deploymentFP).
		Scan(&seq, &executionID, &digest)
	if err == sql.ErrNoRows {
		return 0, "", "", nil
	}
	return seq, executionID, digest, err
}

// Records counts custody rows for a deployment.
func (l *Ledger) Records(ctx context.Context, deploymentFP string) (int64, error) {
	var n int64
	err := l.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM custody_log WHERE deployment_fp = $1`, deploymentFP).Scan(&n)
	return n, err
}

// Stored returns the custody row for (deployment, seq) or nil.
func (l *Ledger) Stored(ctx context.Context, deploymentFP string, seq int64) (*CustodyRow, error) {
	var row CustodyRow
	var ackJSON string
	var receivedAt string
	err := l.db.QueryRowContext(ctx, `
		SELECT deployment_fp, seq, execution_id, receipt_digest, COALESCE(payload, x''), ack, received_at
		FROM custody_log WHERE deployment_fp = $1 AND seq = $2`, deploymentFP, seq).
		Scan(&row.DeploymentFP, &row.Seq, &row.ExecutionID, &row.ReceiptDigest, &row.Payload, &ackJSON, &receivedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(ackJSON), &row.Ack); err != nil {
		return nil, err
	}
	row.ReceivedAt, _ = time.Parse(time.RFC3339Nano, receivedAt)
	return &row, nil
}

// Submit stores one submission and returns its acknowledgement. The
// binding rules, in order: the deployment fingerprint must equal the
// witness's bound fingerprint; the sequence must extend the custody
// head by exactly one; the execution ID must be unseen; and a signed
// payload must verify under the deployment signer. A resubmission of
// an already-stored identical row returns the stored ack — recovery
// resends are idempotent, divergent reuse is a sequence violation.
func (l *Ledger) Submit(ctx context.Context, signer *evidence.Signer, req Request, pinnedFP string) (*Ack, error) {
	// Deployment binding.
	bound, err := l.BoundDeployment(ctx)
	if err != nil {
		return nil, err
	}
	if pinnedFP != "" && bound == "" {
		if err := l.bindDeployment(ctx, pinnedFP); err != nil {
			return nil, err
		}
		bound = pinnedFP
	}
	if bound == "" {
		// TOFU: first deployment to submit becomes the binding.
		if err := l.bindDeployment(ctx, req.DeploymentFP); err != nil {
			return nil, err
		}
		bound = req.DeploymentFP
	}
	if req.DeploymentFP != bound {
		return nil, fmt.Errorf("%w: this witness custodies %s, not %s", ErrDeploymentMismatch, bound, req.DeploymentFP)
	}
	if pinnedFP != "" && req.DeploymentFP != pinnedFP {
		return nil, fmt.Errorf("%w: this witness is pinned to %s", ErrDeploymentMismatch, pinnedFP)
	}

	// Idempotent resend: identical row already stored → stored ack.
	if existing, err := l.Stored(ctx, bound, req.Seq); err != nil {
		return nil, err
	} else if existing != nil {
		if existing.ExecutionID == req.ExecutionID && existing.ReceiptDigest == req.ReceiptDigest &&
			bytes.Equal(existing.Payload, req.Payload) {
			return existing.Ack, nil
		}
		return nil, fmt.Errorf("%w: seq %d already custodies a different record", ErrSequence, req.Seq)
	}

	head, _, _, err := l.Head(ctx, bound)
	if err != nil {
		return nil, err
	}
	if req.Seq != head+1 {
		return nil, fmt.Errorf("%w: seq %d does not extend custody head %d (gap, replay, or rollback)", ErrSequence, req.Seq, head)
	}

	// A signed payload must verify under the deployment signer — a
	// receipt forged under a foreign key is refused before it can be
	// custodied as evidence.
	if len(req.Payload) > 0 {
		receipt, err := evidence.ParseReceipt(req.Payload)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrReceiptVerify, err)
		}
		if receipt.Signer != bound {
			return nil, fmt.Errorf("%w: receipt signer %s is not the bound deployment %s", ErrReceiptVerify, receipt.Signer, bound)
		}
		if err := evidence.VerifySignature(receipt); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrReceiptVerify, err)
		}
		if receipt.ExecutionID != req.ExecutionID {
			return nil, fmt.Errorf("%w: receipt names execution %s, submission names %s", ErrReceiptVerify, receipt.ExecutionID, req.ExecutionID)
		}
	}

	ack := SignAck(signer, bound, req.Seq, req.ExecutionID, req.ReceiptDigest)
	ackJSON, err := json.Marshal(ack)
	if err != nil {
		return nil, err
	}
	_, err = l.db.ExecContext(ctx, `
		INSERT INTO custody_log (deployment_fp, seq, execution_id, receipt_digest, payload, ack, received_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		bound, req.Seq, req.ExecutionID, req.ReceiptDigest, req.Payload, string(ackJSON),
		time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return nil, fmt.Errorf("witness custody insert: %w", err)
	}
	return ack, nil
}
