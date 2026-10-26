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
	"time"

	_ "modernc.org/sqlite"

	"github.com/openclaw/crabbox/internal/custody"
	"github.com/openclaw/crabbox/internal/evidence"
)

// Ledger is the witness's append-only custody log. It exposes insert
// and read operations only — no update or delete path exists, so the
// custody record a kernel cannot reach stays intact. Sequence is the
// per-deployment custody head: submissions must extend it by exactly
// one and chain to the stored head hash, which is what makes
// rollback-disguise, replay, and contradictory-checkpoint rejection
// structural rather than procedural.
type Ledger struct {
	db *sql.DB
}

// Typed submission refusals.
var (
	ErrDeploymentMismatch = errors.New("witness: deployment identity mismatch")
	ErrSequence           = errors.New("witness: sequence violation")
	ErrContradiction      = errors.New("witness: contradictory checkpoint — same index, different record")
	ErrDuplicate          = errors.New("witness: execution already custodied")
	ErrEnvelope           = errors.New("witness: envelope rejected")
)

// CustodyRow is one stored submission.
type CustodyRow struct {
	DeploymentID string
	Seq          int64
	ExecutionID  string
	EnvelopeHash string
	Envelope     *custody.Envelope
	Ack          *Ack
	ReceivedAt   time.Time
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
			deployment_id TEXT NOT NULL,
			seq INTEGER NOT NULL,
			execution_id TEXT NOT NULL,
			envelope_hash TEXT NOT NULL,
			envelope_json TEXT NOT NULL,
			ack TEXT NOT NULL,
			signer_epoch INTEGER NOT NULL,
			received_at TEXT NOT NULL,
			PRIMARY KEY (deployment_id, seq),
			UNIQUE (deployment_id, execution_id)
		)`,
		fenceDDL,
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

func (l *Ledger) meta(ctx context.Context, key string) (string, error) {
	var v string
	err := l.db.QueryRowContext(ctx, `SELECT value FROM witness_meta WHERE key = $1`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return v, err
}

func (l *Ledger) setMeta(ctx context.Context, key, value string) error {
	_, err := l.db.ExecContext(ctx, `INSERT INTO witness_meta (key, value) VALUES ($1, $2)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

// SignerEpoch is the witness's current signing-key epoch — it bumps
// exactly once per authorized key rotation, so acknowledgements record
// which key generation minted them.
func (l *Ledger) SignerEpoch(ctx context.Context) (int64, error) {
	return signerEpochFrom(ctx, l.db)
}

// signerEpochFrom reads the epoch on an explicit queryer so a
// submission can number its acknowledgement from inside the same
// transaction that admitted it, instead of opening a second connection
// while holding the write lock.
func signerEpochFrom(ctx context.Context, q fenceQueryer) (int64, error) {
	var v string
	err := q.QueryRowContext(ctx, `SELECT value FROM witness_meta WHERE key = $1`, "signer_epoch").Scan(&v)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	if err != nil || v == "" {
		return 0, err
	}
	return strconv.ParseInt(v, 10, 64)
}

// AdvanceSignerEpoch records a key rotation — the new signer epoch is
// the old +1, never asserted. The accompanying signer key change is the
// service's act; this ledger only numbers it.
func (l *Ledger) AdvanceSignerEpoch(ctx context.Context) (int64, error) {
	epoch, err := l.SignerEpoch(ctx)
	if err != nil {
		return 0, err
	}
	epoch++
	if err := l.setMeta(ctx, "signer_epoch", strconv.FormatInt(epoch, 10)); err != nil {
		return 0, err
	}
	return epoch, nil
}

// MaxEnvelopeEpoch is the highest subject-sequence epoch custodied —
// prior-epoch replays are refused below it.
func (l *Ledger) MaxEnvelopeEpoch(ctx context.Context, deploymentID string) (int64, error) {
	return maxEnvelopeEpochFrom(ctx, l.db, deploymentID)
}

func maxEnvelopeEpochFrom(ctx context.Context, q fenceQueryer, deploymentID string) (int64, error) {
	var v sql.NullInt64
	err := q.QueryRowContext(ctx, `
		SELECT MAX(CAST(json_extract(envelope_json, '$.sequence.epoch') AS INTEGER))
		FROM custody_log WHERE deployment_id = $1`, deploymentID).Scan(&v)
	if err != nil || !v.Valid {
		return 0, err
	}
	return v.Int64, nil
}

// Head returns the deployment's custody head — the highest contiguous
// sequence stored — and the identity of the head record.
func (l *Ledger) Head(ctx context.Context, deploymentID string) (seq int64, hash, executionID string, err error) {
	return headFrom(ctx, l.db, deploymentID)
}

func headFrom(ctx context.Context, q fenceQueryer, deploymentID string) (seq int64, hash, executionID string, err error) {
	err = q.QueryRowContext(ctx, `
		SELECT seq, envelope_hash, execution_id FROM custody_log
		WHERE deployment_id = $1 ORDER BY seq DESC LIMIT 1`, deploymentID).
		Scan(&seq, &hash, &executionID)
	if err == sql.ErrNoRows {
		return 0, "", "", nil
	}
	return seq, hash, executionID, err
}

// Records counts custody rows for a deployment.
func (l *Ledger) Records(ctx context.Context, deploymentID string) (int64, error) {
	var n int64
	err := l.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM custody_log WHERE deployment_id = $1`, deploymentID).Scan(&n)
	return n, err
}

// Stored returns the custody row for (deployment, seq) or nil.
func (l *Ledger) Stored(ctx context.Context, deploymentID string, seq int64) (*CustodyRow, error) {
	return storedFrom(ctx, l.db, deploymentID, seq)
}

func storedFrom(ctx context.Context, q fenceQueryer, deploymentID string, seq int64) (*CustodyRow, error) {
	var row CustodyRow
	var envJSON, ackJSON, receivedAt string
	err := q.QueryRowContext(ctx, `
		SELECT deployment_id, seq, execution_id, envelope_hash, envelope_json, ack, received_at
		FROM custody_log WHERE deployment_id = $1 AND seq = $2`, deploymentID, seq).
		Scan(&row.DeploymentID, &row.Seq, &row.ExecutionID, &row.EnvelopeHash, &envJSON, &ackJSON, &receivedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	row.Envelope = &custody.Envelope{}
	if err := json.Unmarshal([]byte(envJSON), row.Envelope); err != nil {
		return nil, err
	}
	if row.Ack, err = decodeAck(ackJSON); err != nil {
		return nil, err
	}
	row.ReceivedAt, _ = time.Parse(time.RFC3339Nano, receivedAt)
	return &row, nil
}

// Submit verifies, stores, and countersigns one custody submission.
// The binding rules, in order: no migration epoch may be open for the
// deployment; the deployment must equal the witness's pinned identity;
// the envelope must satisfy the full custody-envelope-v1 verification
// pipeline under the pinned kernel trust set (family allowlist,
// deployment, sequence expectation, content hash, signature under a
// pinned kernel-relay key); an identical re-submission returns the
// stored ack (recovery resends are idempotent); a divergent record at
// a custodied index is a contradictory checkpoint and fails closed; a
// new record must extend the head by exactly one and chain to its
// hash.
//
// The fence check, the head read, and the insert share one immediate
// transaction. That is what makes a migration epoch an actual barrier:
// a submission racing a fence-begin either commits before the fence
// (and is therefore inside the head the fence freezes) or observes the
// fence and is refused. There is no window in which a submission is
// admitted against a head a migration has already frozen.
func (l *Ledger) Submit(ctx context.Context, signer *evidence.Signer, env *custody.Envelope, deploymentID string, kernelTrust *custody.TrustSet) (*Ack, error) {
	if env == nil {
		return nil, fmt.Errorf("%w: submission carries no custody-envelope-v1 record — capability negotiation is explicit", ErrEnvelope)
	}
	if env.DeploymentID != deploymentID {
		return nil, fmt.Errorf("%w: this witness custodies %s, not %s", ErrDeploymentMismatch, deploymentID, env.DeploymentID)
	}

	envHash, err := env.Hash()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEnvelope, err)
	}

	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	if fence, open, err := activeFenceFrom(ctx, tx, deploymentID); err != nil {
		return nil, err
	} else if open {
		return nil, fmt.Errorf("%w: epoch %d (fence %s) is open at seq %d — submissions are suspended until the migration closes it",
			ErrFenced, fence.Epoch, fence.FenceID, fence.BaseSeq)
	}

	// Idempotent resend first: an identical record already custodied
	// returns its stored acknowledgement — recovery redelivery is never
	// a second custody.
	if existing, err := storedFrom(ctx, tx, deploymentID, env.Sequence.Index); err != nil {
		return nil, err
	} else if existing != nil {
		if existing.EnvelopeHash == envHash {
			return existing.Ack, tx.Commit()
		}
		return nil, fmt.Errorf("%w: index %d already custodies %s, submission presents %s",
			ErrContradiction, env.Sequence.Index, existing.EnvelopeHash, envHash)
	}

	// A new execution_id at a custodied-less index must extend the head
	// exactly and chain to it — gaps, replays, and rollback disguises
	// are refused before the signature is even checked.
	head, headHash, _, err := headFrom(ctx, tx, deploymentID)
	if err != nil {
		return nil, err
	}
	maxEpoch, err := maxEnvelopeEpochFrom(ctx, tx, deploymentID)
	if err != nil {
		return nil, err
	}
	expectedPrev := ""
	if head > 0 {
		expectedPrev = headHash
	}
	if env.Sequence.Index == 1 && head == 0 {
		expectedPrev = ""
	}
	if err := custody.Verify(env, custody.VerifyOptions{
		DeploymentID:  deploymentID,
		AllowFamilies: map[string]bool{custody.FamilyReceipt: true},
		Trust:         kernelTrust,
		Seq: &custody.SeqExpect{
			Index:    head + 1,
			PrevHash: expectedPrev,
			MinEpoch: maxEpoch,
		},
	}); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEnvelope, err)
	}

	// Execution-id uniqueness is durable state, not just the index
	// check: a new index reusing a custodied execution id is a replay
	// under a different sequence.
	var dup int64
	err = tx.QueryRowContext(ctx, `SELECT seq FROM custody_log WHERE deployment_id = $1 AND execution_id = $2`,
		deploymentID, env.Subject.ExecutionID).Scan(&dup)
	if err == nil {
		return nil, fmt.Errorf("%w: execution %s already custodied at seq %d", ErrDuplicate, env.Subject.ExecutionID, dup)
	}
	if err != sql.ErrNoRows {
		return nil, err
	}

	epoch, err := signerEpochFrom(ctx, tx)
	if err != nil {
		return nil, err
	}
	ack, err := SignAck(signer, epoch, env, envHash)
	if err != nil {
		return nil, err
	}
	envJSON, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}
	ackJSON, err := json.Marshal(ack)
	if err != nil {
		return nil, err
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO custody_log (deployment_id, seq, execution_id, envelope_hash, envelope_json, ack, signer_epoch, received_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		deploymentID, env.Sequence.Index, env.Subject.ExecutionID, envHash,
		string(envJSON), string(ackJSON), epoch,
		time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return nil, fmt.Errorf("witness custody insert: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("witness custody commit: %w", err)
	}
	return ack, nil
}
