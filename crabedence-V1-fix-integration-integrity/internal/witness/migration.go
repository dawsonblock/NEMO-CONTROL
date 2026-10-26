package witness

// RC8.3 integrity closure — lossless, authorized legacy custody
// migration.
//
// RC8.1-era outboxes hold rows whose envelope content is empty:
// non-CRITICAL executions enqueued a nil receipt, producing an envelope
// that can never verify under the canonical terminal-receipt preimage.
// Repairing one is a rewrite of durable evidence state, so it is
// classification-first, authorization-gated, and chain-aware:
//
//   - Preflight is read-only and examines the target, every successor,
//     existing acknowledgements, and any external checkpoint.
//   - A fully unacknowledged, never-checkpointed suffix may be rebuilt
//     atomically: the target receives canonical bytes and every
//     successor's previous_checkpoint_hash and signature are rewritten
//     in the same transaction, so the chain never forks.
//   - A suffix containing a witnessed (acknowledged) row is refused and
//     quarantined; rewriting it would alter history the witness holds.
//   - Every transition lands in an append-only journal carrying the
//     signed operator grant, before/after hashes, and a signed
//     before/after proof.
//
// Coverage is never inferred from "some journal entry exists". Reconcile
// independently re-verifies the journal identity, terminal receipt
// digest, envelope hash binding, row sequence, authorization signature,
// and disposition before treating a legacy row as covered.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/openclaw/crabbox/internal/custody"
	"github.com/openclaw/crabbox/internal/evidence"
)

// Legacy journal actions.
const (
	// JournalCompensated — an unacknowledged empty-payload suffix was
	// rebuilt from the authoritative terminal record: the target kept
	// its sequence position, the suffix was re-linked and re-signed,
	// and canonical receipt bytes now live inside. Nothing in the
	// suffix had been witnessed.
	JournalCompensated = "payload-compensated"
	// JournalLegacyWitnessed — an acknowledged empty-payload row was
	// recorded as a known legacy divergence. Its bytes are evidence the
	// witness already holds and stay byte-identical; the journal entry
	// is the operator-approved classification, and coverage requires a
	// cryptographically verified acknowledgement.
	JournalLegacyWitnessed = "legacy-witnessed"
	// JournalUnverifiable — an empty-payload row whose authoritative
	// terminal record cannot be established. Quarantined in place:
	// REPAIR_REQUIRED stays open and a forensic escalation is owed.
	// This disposition is never coverage.
	JournalUnverifiable = "unverifiable-legacy"
)

// MigrationProofDomain separates before/after migration proofs from
// every other signed record.
const MigrationProofDomain = "custody-migration-proof-v1\x00"

// LegacyRow is one outbox row whose envelope content is empty — the
// RC8.1 durable shape that predates canonical terminal payloads.
type LegacyRow struct {
	Seq          int64
	ExecutionID  string
	EnvelopeHash string
	Acked        bool
}

// MigrationJournalEntry is one append-only migration transition. The
// authorization fields make the entry independently verifiable: the
// embedded grant is signed by a pinned repair authority, and its nonce
// is durably consumed before the entry is written.
type MigrationJournalEntry struct {
	Seq                   int64  `json:"seq"`
	RowSeq                int64  `json:"row_seq"`
	ExecutionID           string `json:"execution_id"`
	Action                string `json:"action"`
	Detail                string `json:"detail"`
	CreatedAt             string `json:"created_at"`
	OriginalEnvelopeHash  string `json:"original_envelope_hash"`
	ResultEnvelopeHash    string `json:"result_envelope_hash"`
	TerminalReceiptDigest string `json:"terminal_receipt_digest"`
	TerminalSeq           int64  `json:"terminal_seq"`
	CheckpointSeq         int64  `json:"checkpoint_seq"`
	CheckpointHash        string `json:"checkpoint_hash"`
	CheckpointWitnessFP   string `json:"checkpoint_witness_fp"`
	AuthorizationJSON     string `json:"authorization_json"`
	AuthorizationDigest   string `json:"authorization_digest"`
	AuthorizedBy          string `json:"authorized_by"`
	Nonce                 string `json:"nonce"`
	BeforeDigest          string `json:"before_digest"`
	AfterDigest           string `json:"after_digest"`
	ProofJSON             string `json:"proof_json"`
	ProofSignature        string `json:"proof_signature"`
}

// legacyJournalDDL is appended to the outbox schema at open — an
// additive, non-destructive table for the migration journal.
const legacyJournalDDL = `CREATE TABLE IF NOT EXISTS custody_migration_journal (
	seq INTEGER PRIMARY KEY AUTOINCREMENT,
	row_seq INTEGER NOT NULL,
	execution_id TEXT NOT NULL,
	action TEXT NOT NULL,
	detail TEXT NOT NULL,
	created_at TEXT NOT NULL,
	original_envelope_hash TEXT NOT NULL DEFAULT '',
	result_envelope_hash TEXT NOT NULL DEFAULT '',
	terminal_receipt_digest TEXT NOT NULL DEFAULT '',
	terminal_seq INTEGER NOT NULL DEFAULT 0,
	checkpoint_seq INTEGER NOT NULL DEFAULT 0,
	checkpoint_hash TEXT NOT NULL DEFAULT '',
	checkpoint_witness_fp TEXT NOT NULL DEFAULT '',
	authorization_json TEXT NOT NULL DEFAULT '',
	authorization_digest TEXT NOT NULL DEFAULT '',
	authorized_by TEXT NOT NULL DEFAULT '',
	nonce TEXT NOT NULL DEFAULT '',
	before_digest TEXT NOT NULL DEFAULT '',
	after_digest TEXT NOT NULL DEFAULT '',
	proof_json TEXT NOT NULL DEFAULT '',
	proof_signature TEXT NOT NULL DEFAULT ''
)`

// nonceLedgerDDL is the durable single-use fence for operator grants.
const nonceLedgerDDL = `CREATE TABLE IF NOT EXISTS operator_nonce_ledger (
	nonce TEXT PRIMARY KEY,
	subject TEXT NOT NULL,
	operation TEXT NOT NULL,
	grant_digest TEXT NOT NULL,
	used_at TEXT NOT NULL
)`

// journalUpgradeColumns are the columns added after the RC8.3-dev
// journal shape. OpenOutbox adds any that a pre-existing database
// lacks; the migration is additive and never rewrites journal rows.
var journalUpgradeColumns = []struct{ name, decl string }{
	{"original_envelope_hash", "TEXT NOT NULL DEFAULT ''"},
	{"result_envelope_hash", "TEXT NOT NULL DEFAULT ''"},
	{"terminal_receipt_digest", "TEXT NOT NULL DEFAULT ''"},
	{"terminal_seq", "INTEGER NOT NULL DEFAULT 0"},
	{"checkpoint_seq", "INTEGER NOT NULL DEFAULT 0"},
	{"checkpoint_hash", "TEXT NOT NULL DEFAULT ''"},
	{"checkpoint_witness_fp", "TEXT NOT NULL DEFAULT ''"},
	{"authorization_json", "TEXT NOT NULL DEFAULT ''"},
	{"authorization_digest", "TEXT NOT NULL DEFAULT ''"},
	{"authorized_by", "TEXT NOT NULL DEFAULT ''"},
	{"nonce", "TEXT NOT NULL DEFAULT ''"},
	{"before_digest", "TEXT NOT NULL DEFAULT ''"},
	{"after_digest", "TEXT NOT NULL DEFAULT ''"},
	{"proof_json", "TEXT NOT NULL DEFAULT ''"},
	{"proof_signature", "TEXT NOT NULL DEFAULT ''"},
}

// ensureLegacyJournalSchema upgrades a pre-existing journal table
// additively. It refuses a table whose shape it cannot read rather than
// proceeding on an unknown schema.
func ensureLegacyJournalSchema(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, `PRAGMA table_info(custody_migration_journal)`)
	if err != nil {
		return fmt.Errorf("custody journal schema: %w", err)
	}
	defer rows.Close()
	have := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull, pk int
		var dflt any
		if err := rows.Scan(&cid, &name, &typ, &notNull, &dflt, &pk); err != nil {
			return fmt.Errorf("custody journal schema: %w", err)
		}
		have[name] = true
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("custody journal schema: %w", err)
	}
	for _, col := range journalUpgradeColumns {
		if have[col.name] {
			continue
		}
		if _, err := db.ExecContext(ctx,
			fmt.Sprintf(`ALTER TABLE custody_migration_journal ADD COLUMN %s %s`, col.name, col.decl)); err != nil {
			return fmt.Errorf("custody journal schema add %s: %w", col.name, err)
		}
	}
	return nil
}

// LegacyRows classifies every outbox row whose envelope content is
// empty. Bounded callers use LegacyRowsPage.
func (o *Outbox) LegacyRows(ctx context.Context) ([]LegacyRow, error) {
	return o.LegacyRowsPage(ctx, 0, 0)
}

// LegacyRowsPage classifies legacy rows strictly after afterSeq, capped
// at limit rows (0 = unbounded). The cursor is the SQL scan position —
// no row materialization beyond the page.
func (o *Outbox) LegacyRowsPage(ctx context.Context, afterSeq int64, limit int) ([]LegacyRow, error) {
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

type journalRecord struct {
	RowSeq                int64
	ExecutionID           string
	Action                string
	Detail                string
	OriginalEnvelopeHash  string
	ResultEnvelopeHash    string
	TerminalReceiptDigest string
	TerminalSeq           int64
	CheckpointSeq         int64
	CheckpointHash        string
	CheckpointWitnessFP   string
	AuthorizationJSON     string
	AuthorizationDigest   string
	AuthorizedBy          string
	Nonce                 string
	BeforeDigest          string
	AfterDigest           string
	ProofJSON             string
	ProofSignature        string
}

type execQueryer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// journal writes one append-only migration transition.
func (o *Outbox) journal(ctx context.Context, q execQueryer, rec journalRecord) (int64, error) {
	res, err := q.ExecContext(ctx,
		`INSERT INTO custody_migration_journal (
			row_seq, execution_id, action, detail, created_at,
			original_envelope_hash, result_envelope_hash,
			terminal_receipt_digest, terminal_seq,
			checkpoint_seq, checkpoint_hash, checkpoint_witness_fp,
			authorization_json, authorization_digest, authorized_by, nonce,
			before_digest, after_digest, proof_json, proof_signature)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)`,
		rec.RowSeq, rec.ExecutionID, rec.Action, rec.Detail,
		time.Now().UTC().Format(time.RFC3339Nano),
		rec.OriginalEnvelopeHash, rec.ResultEnvelopeHash,
		rec.TerminalReceiptDigest, rec.TerminalSeq,
		rec.CheckpointSeq, rec.CheckpointHash, rec.CheckpointWitnessFP,
		rec.AuthorizationJSON, rec.AuthorizationDigest, rec.AuthorizedBy, rec.Nonce,
		rec.BeforeDigest, rec.AfterDigest, rec.ProofJSON, rec.ProofSignature)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// MigrationJournal lists every recorded migration transition.
func (o *Outbox) MigrationJournal(ctx context.Context) ([]MigrationJournalEntry, error) {
	return o.MigrationJournalPage(ctx, 0, 0)
}

// MigrationJournalPage lists transitions strictly after afterSeq, capped
// at limit rows (0 = unbounded). Operator surfaces use the bounded form
// so a large forensic journal never materializes at once.
// journalFields is the full post-upgrade journal shape in scan order.
// The default literal is selected in place of a column a pre-upgrade
// database does not have yet.
var journalFields = []struct{ name, dflt string }{
	{"seq", "0"},
	{"row_seq", "0"},
	{"execution_id", "''"},
	{"action", "''"},
	{"detail", "''"},
	{"created_at", "''"},
	{"original_envelope_hash", "''"},
	{"result_envelope_hash", "''"},
	{"terminal_receipt_digest", "''"},
	{"terminal_seq", "0"},
	{"checkpoint_seq", "0"},
	{"checkpoint_hash", "''"},
	{"checkpoint_witness_fp", "''"},
	{"authorization_json", "''"},
	{"authorization_digest", "''"},
	{"authorized_by", "''"},
	{"nonce", "''"},
	{"before_digest", "''"},
	{"after_digest", "''"},
	{"proof_json", "''"},
	{"proof_signature", "''"},
}

// journalSelectList renders the scan list for the journal's actual
// shape. Only writable OpenOutbox runs the additive upgrade, so a
// read-only inspector can meet the six-column RC8.3-dev table. Selecting
// a literal default for an absent column keeps preflight working on
// exactly the databases this release exists to migrate; a present
// column is always read from the row.
func journalSelectList(ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}) (string, error) {
	rows, err := q.QueryContext(ctx, `PRAGMA table_info(custody_migration_journal)`)
	if err != nil {
		return "", fmt.Errorf("custody journal schema: %w", err)
	}
	defer rows.Close()
	have := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull, pk int
		var dflt any
		if err := rows.Scan(&cid, &name, &typ, &notNull, &dflt, &pk); err != nil {
			return "", fmt.Errorf("custody journal schema: %w", err)
		}
		have[name] = true
	}
	if err := rows.Err(); err != nil {
		return "", fmt.Errorf("custody journal schema: %w", err)
	}
	parts := make([]string, 0, len(journalFields))
	for _, f := range journalFields {
		if have[f.name] {
			parts = append(parts, f.name)
			continue
		}
		parts = append(parts, f.dflt+` AS `+f.name)
	}
	return strings.Join(parts, ", "), nil
}

func scanJournalEntry(rows *sql.Rows) (MigrationJournalEntry, error) {
	var e MigrationJournalEntry
	err := rows.Scan(&e.Seq, &e.RowSeq, &e.ExecutionID, &e.Action, &e.Detail, &e.CreatedAt,
		&e.OriginalEnvelopeHash, &e.ResultEnvelopeHash,
		&e.TerminalReceiptDigest, &e.TerminalSeq,
		&e.CheckpointSeq, &e.CheckpointHash, &e.CheckpointWitnessFP,
		&e.AuthorizationJSON, &e.AuthorizationDigest, &e.AuthorizedBy, &e.Nonce,
		&e.BeforeDigest, &e.AfterDigest, &e.ProofJSON, &e.ProofSignature)
	return e, err
}

func (o *Outbox) MigrationJournalPage(ctx context.Context, afterSeq int64, limit int) ([]MigrationJournalEntry, error) {
	sel, err := journalSelectList(ctx, o.db)
	if err != nil {
		return nil, err
	}
	q := `SELECT ` + sel + ` FROM custody_migration_journal WHERE seq > $1 ORDER BY seq`
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
	var out []MigrationJournalEntry
	for rows.Next() {
		e, err := scanJournalEntry(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// LegacyJournalAction returns the latest journal action recorded for an
// execution, or "". A database failure is an error — never silently
// reported as "no classification recorded", which would turn a broken
// journal read into an admission decision.
func (o *Outbox) LegacyJournalAction(ctx context.Context, executionID string) (string, error) {
	var action string
	err := o.db.QueryRowContext(ctx,
		`SELECT action FROM custody_migration_journal WHERE execution_id = $1
		 ORDER BY seq DESC LIMIT 1`, executionID).Scan(&action)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("legacy journal read %s: %w", executionID, err)
	}
	return action, nil
}

// latestJournalEntry returns the newest journal entry for an execution.
func latestJournalEntry(ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}, executionID string) (MigrationJournalEntry, bool, error) {
	sel, err := journalSelectList(ctx, q)
	if err != nil {
		return MigrationJournalEntry{}, false, err
	}
	rows, err := q.QueryContext(ctx,
		`SELECT `+sel+` FROM custody_migration_journal WHERE execution_id = $1
		 ORDER BY seq DESC LIMIT 1`, executionID)
	if err != nil {
		return MigrationJournalEntry{}, false, err
	}
	defer rows.Close()
	if !rows.Next() {
		return MigrationJournalEntry{}, false, rows.Err()
	}
	e, err := scanJournalEntry(rows)
	if err != nil {
		return MigrationJournalEntry{}, false, err
	}
	return e, true, rows.Err()
}

// LegacyDisposition is the typed outcome of re-verifying a legacy row's
// journal classification. Only LegacyCoverageVerified permits the
// obligation scanner to treat the row as covered.
type LegacyDisposition string

const (
	// LegacyCoverageVerified — every binding re-verified independently.
	LegacyCoverageVerified LegacyDisposition = "COVERED_VERIFIED"
	// LegacyCoverageUnresolved — classification is missing, stale,
	// quarantined, or cannot be proved. REPAIR_REQUIRED stays open.
	LegacyCoverageUnresolved LegacyDisposition = "UNRESOLVED"
	// LegacyCoverageContradiction — the journal binds different
	// evidence than the row or terminal record now holds.
	LegacyCoverageContradiction LegacyDisposition = "CONTRADICTION"
)

// LegacyCoverageRequest is the independently pinned context a coverage
// decision requires. Nothing here is learned from the journal row.
type LegacyCoverageRequest struct {
	ExecutionID           string
	TerminalReceiptDigest string
	DeploymentID          string
	RepairTrust           *custody.TrustSet
	CustodianTrust        *custody.TrustSet
	// ProofTrust pins the kernel-relay keys that sign migration
	// proofs. Without it a compensated entry cannot be distinguished
	// from a copied one, so compensated coverage fails closed.
	ProofTrust *custody.TrustSet
	Now        time.Time
}

// LegacyCoverage is the typed verdict.
type LegacyCoverage struct {
	Disposition LegacyDisposition
	Action      string
	JournalSeq  int64
	Reason      string
}

func unresolved(reason string) LegacyCoverage {
	return LegacyCoverage{Disposition: LegacyCoverageUnresolved, Reason: reason}
}

func contradiction(reason string) LegacyCoverage {
	return LegacyCoverage{Disposition: LegacyCoverageContradiction, Reason: reason}
}

// ResolveLegacyCoverage re-verifies a legacy row's journal
// classification. It requires, independently:
//
//   - journal identity: execution id and row sequence match the row;
//   - terminal receipt digest: equals the authoritative record's;
//   - original envelope hash: the hash the journal classified;
//   - disposition: only compensated / legacy-witnessed can cover, and a
//     compensated row must currently hold its journaled result hash;
//   - authorization: the embedded grant verifies under the pinned
//     repair-authority set for this deployment, was valid at the time
//     the entry was written, authorizes custody-migrate, and its nonce
//     was durably consumed;
//   - for legacy-witnessed rows, a cryptographically verified witness
//     acknowledgement over the unchanged envelope.
//
// Any read failure is returned as an error: a journal that cannot be
// read cannot prove coverage.
func (o *Outbox) ResolveLegacyCoverage(ctx context.Context, req LegacyCoverageRequest) (LegacyCoverage, error) {
	var rowSeq int64
	var envJSON, ackJSON string
	err := o.db.QueryRowContext(ctx,
		`SELECT seq, envelope_json, COALESCE(ack, '') FROM custody_outbox WHERE execution_id = $1`,
		req.ExecutionID).Scan(&rowSeq, &envJSON, &ackJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return unresolved("no outbox row for execution"), nil
	}
	if err != nil {
		return LegacyCoverage{}, fmt.Errorf("legacy coverage row read %s: %w", req.ExecutionID, err)
	}
	var env custody.Envelope
	if err := json.Unmarshal([]byte(envJSON), &env); err != nil {
		return contradiction("outbox envelope does not parse"), nil
	}
	envHash, err := env.Hash()
	if err != nil {
		return contradiction("outbox envelope cannot be hashed"), nil
	}
	entry, found, err := latestJournalEntry(ctx, o.db, req.ExecutionID)
	if err != nil {
		return LegacyCoverage{}, fmt.Errorf("legacy coverage journal read %s: %w", req.ExecutionID, err)
	}
	if !found {
		return unresolved("no classification recorded"), nil
	}
	base := LegacyCoverage{Action: entry.Action, JournalSeq: entry.Seq}
	switch entry.Action {
	case JournalUnverifiable:
		base.Disposition = LegacyCoverageUnresolved
		base.Reason = "row is quarantined as unverifiable-legacy — a terminal record arriving later requires re-migration, never automatic coverage"
		return base, nil
	case JournalCompensated, JournalLegacyWitnessed:
	default:
		base.Disposition = LegacyCoverageUnresolved
		base.Reason = fmt.Sprintf("unknown journal disposition %q", entry.Action)
		return base, nil
	}
	if entry.ExecutionID != req.ExecutionID {
		base.Disposition = LegacyCoverageContradiction
		base.Reason = "journal execution identity does not match the row"
		return base, nil
	}
	if entry.RowSeq != rowSeq {
		base.Disposition = LegacyCoverageContradiction
		base.Reason = fmt.Sprintf("journal row sequence %d does not match the outbox row %d", entry.RowSeq, rowSeq)
		return base, nil
	}
	if entry.TerminalReceiptDigest == "" || entry.TerminalReceiptDigest != req.TerminalReceiptDigest {
		base.Disposition = LegacyCoverageUnresolved
		base.Reason = "journal terminal receipt digest does not bind the authoritative terminal record"
		return base, nil
	}
	if entry.AuthorizationJSON == "" || entry.AuthorizationDigest == "" || entry.AuthorizedBy == "" || entry.Nonce == "" {
		base.Disposition = LegacyCoverageUnresolved
		base.Reason = "journal entry carries no verifiable operator authorization"
		return base, nil
	}
	var grant OperatorGrant
	if err := json.Unmarshal([]byte(entry.AuthorizationJSON), &grant); err != nil {
		base.Disposition = LegacyCoverageUnresolved
		base.Reason = "journal authorization does not parse"
		return base, nil
	}
	digest, err := GrantDigest(&grant)
	if err != nil || digest != entry.AuthorizationDigest {
		base.Disposition = LegacyCoverageUnresolved
		base.Reason = "journal authorization digest does not match the embedded grant"
		return base, nil
	}
	if grant.Subject != entry.AuthorizedBy || grant.Nonce != entry.Nonce {
		base.Disposition = LegacyCoverageUnresolved
		base.Reason = "journal authorization subject or nonce does not match the entry"
		return base, nil
	}
	classifiedAt, err := time.Parse(time.RFC3339Nano, entry.CreatedAt)
	if err != nil {
		classifiedAt, err = time.Parse(time.RFC3339, entry.CreatedAt)
	}
	if err != nil {
		base.Disposition = LegacyCoverageUnresolved
		base.Reason = "journal timestamp is not parseable"
		return base, nil
	}
	if err := VerifyOperatorGrant(&grant, req.RepairTrust, req.DeploymentID, OperationMigrate, classifiedAt); err != nil {
		base.Disposition = LegacyCoverageUnresolved
		base.Reason = fmt.Sprintf("journal authorization does not verify at classification time: %v", err)
		return base, nil
	}
	used, err := o.OperatorNonceUsed(ctx, grant.Nonce, entry.AuthorizationDigest)
	if err != nil {
		base.Disposition = LegacyCoverageContradiction
		base.Reason = fmt.Sprintf("journal authorization nonce state: %v", err)
		return base, nil
	}
	if !used {
		base.Disposition = LegacyCoverageUnresolved
		base.Reason = "journal authorization nonce was never durably consumed"
		return base, nil
	}
	switch entry.Action {
	case JournalCompensated:
		if entry.OriginalEnvelopeHash == "" || entry.ResultEnvelopeHash == "" {
			base.Disposition = LegacyCoverageUnresolved
			base.Reason = "compensation journal omits before/after envelope hashes"
			return base, nil
		}
		if entry.ResultEnvelopeHash != envHash {
			base.Disposition = LegacyCoverageContradiction
			base.Reason = "compensated row no longer holds the journaled result envelope"
			return base, nil
		}
		// The rewrite itself must be the one the kernel-relay key
		// signed. Without this, a journal row carrying a copied grant
		// would be indistinguishable from an authorized rewrite.
		if perr := VerifyMigrationProof(entry, req.DeploymentID, req.ProofTrust); perr != nil {
			base.Disposition = LegacyCoverageUnresolved
			base.Reason = fmt.Sprintf("compensated journal entry carries no verifiable signed rewrite proof: %v", perr)
			return base, nil
		}
		content, cerr := env.ContentBytes()
		if cerr != nil || len(content) == 0 {
			base.Disposition = LegacyCoverageUnresolved
			base.Reason = "compensated row holds no canonical content"
			return base, nil
		}
		base.Disposition = LegacyCoverageVerified
		base.Reason = "compensated suffix verified: authorization, terminal digest, and result envelope bind"
		return base, nil
	case JournalLegacyWitnessed:
		if entry.OriginalEnvelopeHash == "" || entry.OriginalEnvelopeHash != envHash {
			base.Disposition = LegacyCoverageContradiction
			base.Reason = "witnessed-legacy row bytes changed after classification"
			return base, nil
		}
		if entry.ResultEnvelopeHash != "" && entry.ResultEnvelopeHash != envHash {
			base.Disposition = LegacyCoverageContradiction
			base.Reason = "witnessed-legacy journal result hash does not match the unchanged row"
			return base, nil
		}
		if ackJSON == "" {
			base.Disposition = LegacyCoverageUnresolved
			base.Reason = "witnessed-legacy classification has no acknowledgement — presence of a journal entry is not witnessed coverage"
			return base, nil
		}
		ack, err := decodeAck(ackJSON)
		if err != nil {
			base.Disposition = LegacyCoverageUnresolved
			base.Reason = "recorded acknowledgement does not parse"
			return base, nil
		}
		if err := VerifyAck(ack, &env, req.CustodianTrust); err != nil {
			base.Disposition = LegacyCoverageUnresolved
			base.Reason = fmt.Sprintf("recorded acknowledgement does not verify: %v", err)
			return base, nil
		}
		if ack.Seq != rowSeq {
			base.Disposition = LegacyCoverageContradiction
			base.Reason = "acknowledgement sequence does not bind the outbox row"
			return base, nil
		}
		base.Disposition = LegacyCoverageVerified
		base.Reason = "witnessed-legacy divergence verified: unchanged bytes, verified acknowledgement, authorized classification"
		return base, nil
	}
	return unresolved("unreachable disposition"), nil
}

// ─── Chain integrity ─────────────────────────────────────────────────

// ChainState is the structural verdict over the durable outbox chain.
type ChainState struct {
	Rows     int64
	HeadSeq  int64
	HeadHash string
	Digest   string
}

// VerifyChain walks every outbox row and proves the chain is intact:
// contiguous sequence, envelope hash equals the recomputed hash, content
// hash equals the stored bytes, and every row links to its predecessor.
// It is the structural check migration and repair rely on; signature
// verification is a separate trust-scoped act.
func (o *Outbox) VerifyChain(ctx context.Context) (ChainState, error) {
	return verifyChainState(ctx, o.db)
}

// verifyChainState runs the structural check on an explicit queryer so
// a caller inside a write transaction proves the chain it is about to
// read, not a second connection's view of it.
func verifyChainState(ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}) (ChainState, error) {
	rows, err := q.QueryContext(ctx,
		`SELECT seq, execution_id, envelope_hash, envelope_json
		 FROM custody_outbox ORDER BY seq`)
	if err != nil {
		return ChainState{}, err
	}
	defer rows.Close()
	var st ChainState
	var prevSeq int64
	var prevHash string
	first := true
	h := sha256.New()
	for rows.Next() {
		var seq int64
		var execID, storedHash, envJSON string
		if err := rows.Scan(&seq, &execID, &storedHash, &envJSON); err != nil {
			return ChainState{}, err
		}
		if !first && seq != prevSeq+1 {
			return ChainState{}, fmt.Errorf("custody chain gap: row %d follows %d", seq, prevSeq)
		}
		var env custody.Envelope
		if err := json.Unmarshal([]byte(envJSON), &env); err != nil {
			return ChainState{}, fmt.Errorf("custody chain row %d does not parse: %w", seq, err)
		}
		recomputed, err := env.Hash()
		if err != nil {
			return ChainState{}, fmt.Errorf("custody chain row %d cannot hash: %w", seq, err)
		}
		if recomputed != storedHash {
			return ChainState{}, fmt.Errorf("custody chain row %d: stored envelope hash %s != recomputed %s", seq, storedHash, recomputed)
		}
		if env.Sequence.Index != seq {
			return ChainState{}, fmt.Errorf("custody chain row %d: envelope index %d", seq, env.Sequence.Index)
		}
		if env.Sequence.PreviousCheckpointHash != prevHash {
			return ChainState{}, fmt.Errorf("custody chain row %d: previous hash %q != predecessor %q", seq, env.Sequence.PreviousCheckpointHash, prevHash)
		}
		content, err := env.ContentBytes()
		if err != nil {
			return ChainState{}, fmt.Errorf("custody chain row %d content: %w", seq, err)
		}
		sum := sha256.Sum256(content)
		if hex.EncodeToString(sum[:]) != env.Content.Hash {
			return ChainState{}, fmt.Errorf("custody chain row %d: content hash does not match bytes", seq)
		}
		if env.Family != custody.FamilyReceipt {
			return ChainState{}, fmt.Errorf("custody chain row %d: family %q is not receipt", seq, env.Family)
		}
		fmt.Fprintf(h, "%d\x00%s\x00%s\x00%s\x00", seq, execID, storedHash, env.Sequence.PreviousCheckpointHash)
		prevSeq, prevHash = seq, storedHash
		first = false
		st.Rows++
	}
	if err := rows.Err(); err != nil {
		return ChainState{}, err
	}
	st.HeadSeq = prevSeq
	st.HeadHash = prevHash
	if st.Rows > 0 {
		st.Digest = hex.EncodeToString(h.Sum(nil))
	}
	return st, nil
}

// ─── Migration preflight and atomic suffix rewrite ───────────────────

// MigrationRow is one row in a migration suffix.
type MigrationRow struct {
	Seq          int64  `json:"seq"`
	ExecutionID  string `json:"execution_id"`
	EnvelopeHash string `json:"envelope_hash"`
	PreviousHash string `json:"previous_hash"`
	Acked        bool   `json:"acked"`
	ContentLen   int    `json:"content_len"`
}

// CheckpointRef is the verified witness checkpoint a migration is
// allowed to proceed under. It is fetched live over the authenticated
// witness transport, verified under the pinned custodian set, and bound
// into the signed migration proof and journal. A zero value means no
// checkpoint was verified — callers must treat that as a refusal.
type CheckpointRef struct {
	Seq       int64  `json:"seq"`
	Hash      string `json:"hash"`
	WitnessFP string `json:"witness_fp"`
}

// MigrationPreflight is the read-only safety verdict for rewriting a
// legacy row and its suffix.
type MigrationPreflight struct {
	TargetSeq    int64          `json:"target_seq"`
	ExecutionID  string         `json:"execution_id"`
	EnvelopeHash string         `json:"envelope_hash"`
	Rows         []MigrationRow `json:"rows"`
	Blocked      bool           `json:"blocked"`
	Reason       string         `json:"reason,omitempty"`
}

// MigrationAuthorization is a verified operator grant plus the pinned
// repair-authority set and deployment it is verified against.
type MigrationAuthorization struct {
	Grant        *OperatorGrant
	Trust        *custody.TrustSet
	DeploymentID string
}

func (a MigrationAuthorization) verify(deploymentID, operation string, now time.Time) error {
	if deploymentID == "" {
		deploymentID = a.DeploymentID
	}
	return VerifyOperatorGrant(a.Grant, a.Trust, deploymentID, operation, now)
}

// MigrationPreflight examines the target row, every successor, existing
// acknowledgements, and an externally observed checkpoint. It never
// mutates. A blocked preflight is a refusal: the chain is quarantined
// pending an explicitly authorized witness-coordinated recovery.
func (o *Outbox) MigrationPreflight(ctx context.Context, rowSeq int64, checkpoint CheckpointRef) (MigrationPreflight, error) {
	return migrationPreflight(ctx, o.db, rowSeq, checkpoint)
}

func migrationPreflight(ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}, rowSeq int64, checkpoint CheckpointRef) (MigrationPreflight, error) {
	checkpointSeq, checkpointHash := checkpoint.Seq, checkpoint.Hash
	var pf MigrationPreflight
	pf.TargetSeq = rowSeq
	var envJSON string
	rows, err := q.QueryContext(ctx,
		`SELECT seq, execution_id, envelope_hash, envelope_json, COALESCE(ack, '')
		 FROM custody_outbox WHERE seq >= $1 ORDER BY seq`, rowSeq)
	if err != nil {
		return pf, err
	}
	defer rows.Close()
	first := true
	for rows.Next() {
		var seq int64
		var execID, hash, ack string
		if err := rows.Scan(&seq, &execID, &hash, &envJSON, &ack); err != nil {
			return pf, err
		}
		var env custody.Envelope
		if err := json.Unmarshal([]byte(envJSON), &env); err != nil {
			return pf, fmt.Errorf("migration preflight seq %d: %w", seq, err)
		}
		content, cerr := env.ContentBytes()
		if cerr != nil {
			return pf, fmt.Errorf("migration preflight seq %d content: %w", seq, cerr)
		}
		mr := MigrationRow{
			Seq: seq, ExecutionID: execID, EnvelopeHash: hash,
			PreviousHash: env.Sequence.PreviousCheckpointHash,
			Acked:        ack != "", ContentLen: len(content),
		}
		if first {
			pf.ExecutionID = execID
			pf.EnvelopeHash = hash
			first = false
			if mr.Acked {
				pf.Blocked, pf.Reason = true, "target row is already witnessed — its bytes are evidence and are never rewritten"
			}
			if mr.ContentLen != 0 {
				pf.Blocked, pf.Reason = true, "target row already holds content — not a legacy empty-payload row"
			}
		} else if mr.Acked {
			pf.Blocked, pf.Reason = true, fmt.Sprintf("successor seq %d is witnessed — rewriting the suffix would alter history the witness holds", seq)
		}
		pf.Rows = append(pf.Rows, mr)
	}
	if err := rows.Err(); err != nil {
		return pf, err
	}
	if len(pf.Rows) == 0 {
		return pf, fmt.Errorf("migration preflight: no row at seq %d", rowSeq)
	}
	if checkpointSeq >= rowSeq {
		pf.Blocked, pf.Reason = true, fmt.Sprintf("external checkpoint covers seq %d (target %d) — the suffix is checkpointed history", checkpointSeq, rowSeq)
		return pf, nil
	}
	if checkpointSeq > 0 {
		var stored string
		rows2, qerr := q.QueryContext(ctx, `SELECT envelope_hash FROM custody_outbox WHERE seq = $1`, checkpointSeq)
		if qerr != nil {
			return pf, qerr
		}
		if rows2.Next() {
			_ = rows2.Scan(&stored)
		}
		cerr := rows2.Err()
		rows2.Close()
		if cerr != nil {
			return pf, cerr
		}
		if stored == "" {
			pf.Blocked, pf.Reason = true, fmt.Sprintf("checkpoint names seq %d, which this outbox does not hold", checkpointSeq)
		} else if checkpointHash != "" && stored != checkpointHash {
			pf.Blocked, pf.Reason = true, fmt.Sprintf("checkpoint head at seq %d is %s but this outbox holds %s — the stores have forked", checkpointSeq, checkpointHash, stored)
		}
	}
	return pf, nil
}

// migrationProof is the signed before/after evidence for one suffix
// rewrite. It is stored in the journal and independently verifiable
// under the deployment's kernel-relay key.
type migrationProof struct {
	Schema       string              `json:"schema"`
	TargetSeq    int64               `json:"target_seq"`
	Checkpoint   CheckpointRef       `json:"checkpoint"`
	Rows         []migrationProofRow `json:"rows"`
	BeforeDigest string              `json:"before_digest"`
	AfterDigest  string              `json:"after_digest"`
}

type migrationProofRow struct {
	Seq        int64  `json:"seq"`
	BeforeHash string `json:"before_hash"`
	AfterHash  string `json:"after_hash"`
	BeforePrev string `json:"before_prev"`
	AfterPrev  string `json:"after_prev"`
}

// MigrationResult reports one suffix rewrite.
type MigrationResult struct {
	TargetSeq       int64
	Rehashed        int
	AlreadyMigrated bool
	BeforeDigest    string
	AfterDigest     string
	JournalSeq      int64
}

type migrationCandidate struct {
	seq          int64
	execID       string
	envelopeHash string
	envelope     custody.Envelope
	raw          string
}

// MigrateLegacySuffix atomically rewrites an unacknowledged,
// never-checkpointed legacy suffix. It verifies the operator grant,
// re-runs preflight inside the write transaction, rewrites the target
// and every successor's linkage and signature, records signed
// before/after evidence, and commits. Any witness or checkpoint in the
// suffix refuses the whole operation.
func (o *Outbox) MigrateLegacySuffix(ctx context.Context, p Producer, rowSeq int64, receiptDigest string, native []byte, checkpoint CheckpointRef, auth MigrationAuthorization) (MigrationResult, error) {
	var res MigrationResult
	res.TargetSeq = rowSeq
	// WitnessFP is the proof that a live checkpoint was verified: an
	// initial witness head is seq 0 with an empty hash, but it still
	// carries the custodian key identity. A zero-value CheckpointRef is
	// an offline attempt and is refused.
	if checkpoint.WitnessFP == "" {
		return res, fmt.Errorf("%w: migration requires a live, verified witness checkpoint — offline suffix rewriting is not authorized", ErrEvidenceContradiction)
	}
	if len(native) == 0 {
		return res, fmt.Errorf("%w: migration requires a non-empty canonical payload", ErrEvidenceContradiction)
	}
	if p.Signer == nil || p.DeploymentID == "" {
		return res, fmt.Errorf("%w: migration requires a deployment-bound kernel-relay signer", ErrEvidenceContradiction)
	}
	if err := auth.verify(p.DeploymentID, OperationMigrate, time.Now()); err != nil {
		return res, err
	}
	digest, err := GrantDigest(auth.Grant)
	if err != nil {
		return res, err
	}
	if used, err := o.OperatorNonceUsed(ctx, auth.Grant.Nonce, digest); err != nil {
		return res, err
	} else if !used {
		return res, fmt.Errorf("%w: migration grant nonce was not consumed — authorization is not live", ErrOperatorAuthorization)
	}
	// A chain that is already structurally broken cannot be repaired by
	// rewriting a suffix — refuse before any mutation.
	if _, err := o.VerifyChain(ctx); err != nil {
		return res, fmt.Errorf("%w: pre-migration chain is not intact: %v", ErrEvidenceContradiction, err)
	}

	tx, err := o.db.BeginTx(ctx, nil)
	if err != nil {
		return res, err
	}
	defer tx.Rollback()

	// Idempotent replay: a completed migration of the same target with
	// the same terminal digest and result hash is a no-op.
	var curExec, curHash, curJSON, curAck string
	err = tx.QueryRowContext(ctx,
		`SELECT execution_id, envelope_hash, envelope_json, COALESCE(ack, '')
		 FROM custody_outbox WHERE seq = $1`, rowSeq).
		Scan(&curExec, &curHash, &curJSON, &curAck)
	if err != nil {
		return res, fmt.Errorf("migration seq %d: %w", rowSeq, err)
	}
	var curEnv custody.Envelope
	if err := json.Unmarshal([]byte(curJSON), &curEnv); err != nil {
		return res, fmt.Errorf("migration seq %d: %w", rowSeq, err)
	}
	curContent, cerr := curEnv.ContentBytes()
	if cerr != nil {
		return res, fmt.Errorf("migration seq %d content: %w", rowSeq, cerr)
	}
	if len(curContent) != 0 {
		entry, found, jerr := latestJournalEntry(ctx, tx, curExec)
		if jerr != nil {
			return res, jerr
		}
		if found && entry.Action == JournalCompensated &&
			entry.TerminalReceiptDigest == receiptDigest &&
			entry.ResultEnvelopeHash == curHash {
			if _, err := verifyChainState(ctx, tx); err != nil {
				return res, fmt.Errorf("migration replay: chain is not intact: %w", err)
			}
			res.AlreadyMigrated = true
			res.Rehashed = 0
			res.BeforeDigest = entry.BeforeDigest
			res.AfterDigest = entry.AfterDigest
			res.JournalSeq = entry.Seq
			return res, nil
		}
		return res, fmt.Errorf("%w: seq %d already holds content and is not the recorded migration of this receipt", ErrEvidenceContradiction, rowSeq)
	}

	pf, err := migrationPreflight(ctx, tx, rowSeq, checkpoint)
	if err != nil {
		return res, err
	}
	if pf.Blocked {
		return res, fmt.Errorf("%w: migration refused: %s", ErrEvidenceContradiction, pf.Reason)
	}
	if pf.ExecutionID != curExec {
		return res, fmt.Errorf("%w: preflight execution identity changed under the transaction", ErrEvidenceContradiction)
	}

	cands := make([]migrationCandidate, 0, len(pf.Rows))
	rows, err := tx.QueryContext(ctx,
		`SELECT seq, execution_id, envelope_hash, envelope_json
		 FROM custody_outbox WHERE seq >= $1 ORDER BY seq`, rowSeq)
	if err != nil {
		return res, err
	}
	for rows.Next() {
		var c migrationCandidate
		if err := rows.Scan(&c.seq, &c.execID, &c.envelopeHash, &c.raw); err != nil {
			rows.Close()
			return res, err
		}
		if err := json.Unmarshal([]byte(c.raw), &c.envelope); err != nil {
			rows.Close()
			return res, fmt.Errorf("migration seq %d: %w", c.seq, err)
		}
		if c.envelope.Sequence.Index != c.seq {
			rows.Close()
			return res, fmt.Errorf("%w: seq %d carries envelope index %d", ErrEvidenceContradiction, c.seq, c.envelope.Sequence.Index)
		}
		cands = append(cands, c)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return res, err
	}
	rows.Close()
	if len(cands) == 0 || cands[0].seq != rowSeq {
		return res, fmt.Errorf("%w: suffix changed under the transaction", ErrEvidenceContradiction)
	}
	before := suffixDigest(cands)
	proof := migrationProof{
		Schema:       "custody-migration-proof-v1",
		TargetSeq:    rowSeq,
		Checkpoint:   checkpoint,
		BeforeDigest: before,
		Rows:         make([]migrationProofRow, 0, len(cands)),
	}
	prev := cands[0].envelope.Sequence.PreviousCheckpointHash
	for i, c := range cands {
		pr := migrationProofRow{
			Seq: c.seq, BeforeHash: c.envelopeHash,
			BeforePrev: c.envelope.Sequence.PreviousCheckpointHash,
		}
		// Every rewritten row is re-signed with this deployment's
		// current kernel-relay key. A row that was signed by a
		// different key means the suffix spans a rotation: re-signing
		// it would place the row at an index outside the signer's
		// pinned window, so the result would not verify. Refuse
		// instead of minting unverifiable history.
		if c.envelope.Signer.KeyID != p.Signer.Fingerprint() {
			return res, fmt.Errorf("%w: seq %d was signed by kernel-relay key %s, not this deployment's %s — the suffix spans a key rotation and cannot be re-signed inside the pinned window; witness-coordinated recovery is required", ErrEvidenceContradiction, c.seq, c.envelope.Signer.KeyID, p.Signer.Fingerprint())
		}
		env := c.envelope
		env.Signature = ""
		env.Sequence.PreviousCheckpointHash = prev
		if i == 0 {
			env.Content = custody.Content{}
			rebuilt := custody.New(env.Family, env.DeploymentID, env.ReleaseIdentity, env.PolicyDigest,
				env.Subject, env.Sequence, c.envelope.Content.Encoding, native)
			env = *rebuilt
		}
		if err := custody.Sign(&env, custody.RoleKernelRelay, p.Signer); err != nil {
			return res, fmt.Errorf("migration sign seq %d: %w", c.seq, err)
		}
		newHash, err := env.Hash()
		if err != nil {
			return res, fmt.Errorf("migration hash seq %d: %w", c.seq, err)
		}
		raw, err := json.Marshal(&env)
		if err != nil {
			return res, err
		}
		if i == 0 {
			if _, err := tx.ExecContext(ctx,
				`UPDATE custody_outbox SET envelope_hash = $1, envelope_json = $2, receipt_digest = $3 WHERE seq = $4`,
				newHash, string(raw), receiptDigest, c.seq); err != nil {
				return res, fmt.Errorf("migration update seq %d: %w", c.seq, err)
			}
		} else {
			if _, err := tx.ExecContext(ctx,
				`UPDATE custody_outbox SET envelope_hash = $1, envelope_json = $2 WHERE seq = $3`,
				newHash, string(raw), c.seq); err != nil {
				return res, fmt.Errorf("migration update seq %d: %w", c.seq, err)
			}
		}
		pr.AfterHash = newHash
		pr.AfterPrev = env.Sequence.PreviousCheckpointHash
		proof.Rows = append(proof.Rows, pr)
		prev = newHash
		cands[i].envelopeHash = newHash
		cands[i].envelope = env
	}
	after := suffixDigest(cands)
	proof.AfterDigest = after
	proofJSON, err := canonicalJSON(proof)
	if err != nil {
		return res, err
	}
	proofSig, err := p.Signer.SignRecord(MigrationProofDomain, string(proofJSON))
	if err != nil {
		return res, fmt.Errorf("migration proof sign: %w", err)
	}
	authJSON, err := json.Marshal(auth.Grant)
	if err != nil {
		return res, err
	}
	jseq, err := o.journal(ctx, tx, journalRecord{
		RowSeq: rowSeq, ExecutionID: curExec, Action: JournalCompensated,
		Detail:                fmt.Sprintf("unacknowledged legacy suffix rebuilt from authoritative terminal record (digest %s); %d rows re-linked and re-signed", receiptDigest, len(cands)),
		OriginalEnvelopeHash:  pf.EnvelopeHash,
		ResultEnvelopeHash:    cands[0].envelopeHash,
		TerminalReceiptDigest: receiptDigest,
		CheckpointSeq:         checkpoint.Seq,
		CheckpointHash:        checkpoint.Hash,
		CheckpointWitnessFP:   checkpoint.WitnessFP,
		AuthorizationJSON:     string(authJSON),
		AuthorizationDigest:   digest,
		AuthorizedBy:          auth.Grant.Subject,
		Nonce:                 auth.Grant.Nonce,
		BeforeDigest:          before,
		AfterDigest:           after,
		ProofJSON:             string(proofJSON),
		ProofSignature:        proofSig,
	})
	if err != nil {
		return res, fmt.Errorf("migration journal: %w", err)
	}
	if o.migrationHook != nil {
		if err := o.migrationHook("before_commit"); err != nil {
			return res, err
		}
	}
	if err := tx.Commit(); err != nil {
		return res, fmt.Errorf("migration commit: %w", err)
	}
	if o.migrationHook != nil {
		if err := o.migrationHook("after_commit"); err != nil {
			res.Rehashed = len(cands)
			res.BeforeDigest, res.AfterDigest, res.JournalSeq = before, after, jseq
			return res, err
		}
	}
	res.Rehashed = len(cands)
	res.BeforeDigest, res.AfterDigest, res.JournalSeq = before, after, jseq
	return res, nil
}

func suffixDigest(cands []migrationCandidate) string {
	h := sha256.New()
	for _, c := range cands {
		fmt.Fprintf(h, "%d\x00%s\x00%s\x00", c.seq, c.envelopeHash, c.envelope.Sequence.PreviousCheckpointHash)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func canonicalJSON(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(m); err != nil {
		return nil, err
	}
	return []byte(strings.TrimRight(buf.String(), "\n")), nil
}

// VerifyMigrationProof verifies a journal entry's signed before/after
// proof under a pinned kernel-relay trust set.
func VerifyMigrationProof(entry MigrationJournalEntry, deploymentID string, trust *custody.TrustSet) error {
	if entry.ProofJSON == "" || entry.ProofSignature == "" {
		return fmt.Errorf("migration journal entry %d carries no signed proof", entry.Seq)
	}
	var proof migrationProof
	if err := json.Unmarshal([]byte(entry.ProofJSON), &proof); err != nil {
		return fmt.Errorf("migration proof %d does not parse: %w", entry.Seq, err)
	}
	if proof.BeforeDigest != entry.BeforeDigest || proof.AfterDigest != entry.AfterDigest {
		return fmt.Errorf("migration proof %d digests do not bind the journal entry", entry.Seq)
	}
	if proof.TargetSeq != entry.RowSeq {
		return fmt.Errorf("migration proof %d targets seq %d, journal entry records seq %d", entry.Seq, proof.TargetSeq, entry.RowSeq)
	}
	canon, err := canonicalJSON(proof)
	if err != nil {
		return err
	}
	if trust.Empty() {
		return fmt.Errorf("migration proof %d: no pinned kernel-relay trust set", entry.Seq)
	}
	for _, k := range trust.Keys() {
		if k.Role != custody.RoleKernelRelay {
			continue
		}
		if k.DeploymentID != "" && k.DeploymentID != deploymentID {
			continue
		}
		if err := evidence.VerifyRecordSignature(k.PublicKey, MigrationProofDomain, entry.ProofSignature, string(canon)); err == nil {
			return nil
		}
	}
	return fmt.Errorf("migration proof %d does not verify under any pinned kernel-relay key", entry.Seq)
}

// CompensateLegacyRow is the single-row compatibility entry point. It
// is only safe when the row has no successors; MigrateLegacySuffix is
// the general path and the one custodyctl uses.
func (o *Outbox) CompensateLegacyRow(ctx context.Context, p Producer, rowSeq int64, receiptDigest string, native []byte, checkpoint CheckpointRef, auth MigrationAuthorization) (MigrationResult, error) {
	return o.MigrateLegacySuffix(ctx, p, rowSeq, receiptDigest, native, checkpoint, auth)
}

// JournalLegacyWitnessed records the operator-approved classification
// of an acknowledged empty-payload row: bytes untouched, divergence
// recorded, and coverage later requires the acknowledgement to verify.
func (o *Outbox) JournalLegacyWitnessed(ctx context.Context, rowSeq int64, terminalReceiptDigest, detail string, auth MigrationAuthorization) error {
	if auth.Grant == nil {
		return fmt.Errorf("%w: witnessed-legacy classification requires an operator grant", ErrOperatorAuthorization)
	}
	if err := auth.verify(auth.DeploymentID, OperationMigrate, time.Now()); err != nil {
		return err
	}
	if terminalReceiptDigest == "" {
		return fmt.Errorf("%w: witnessed-legacy classification requires the authoritative terminal receipt digest", ErrEvidenceContradiction)
	}
	digest, err := GrantDigest(auth.Grant)
	if err != nil {
		return err
	}
	if used, err := o.OperatorNonceUsed(ctx, auth.Grant.Nonce, digest); err != nil {
		return err
	} else if !used {
		return fmt.Errorf("%w: classification grant nonce was not consumed", ErrOperatorAuthorization)
	}
	tx, err := o.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var execID, ackJSON, envHash string
	if err := tx.QueryRowContext(ctx,
		`SELECT execution_id, COALESCE(ack, ''), envelope_hash FROM custody_outbox WHERE seq = $1`, rowSeq).
		Scan(&execID, &ackJSON, &envHash); err != nil {
		return fmt.Errorf("journal seq %d: %w", rowSeq, err)
	}
	if ackJSON == "" {
		return fmt.Errorf("seq %d is unacknowledged — compensate it, never journal-over a pending obligation", rowSeq)
	}
	authJSON, err := json.Marshal(auth.Grant)
	if err != nil {
		return err
	}
	if _, err := o.journal(ctx, tx, journalRecord{
		RowSeq: rowSeq, ExecutionID: execID, Action: JournalLegacyWitnessed, Detail: detail,
		OriginalEnvelopeHash: envHash, ResultEnvelopeHash: envHash,
		TerminalReceiptDigest: terminalReceiptDigest,
		AuthorizationJSON:     string(authJSON), AuthorizationDigest: digest,
		AuthorizedBy: auth.Grant.Subject, Nonce: auth.Grant.Nonce,
	}); err != nil {
		return err
	}
	return tx.Commit()
}

// JournalUnverifiable quarantines an empty-payload row whose
// authoritative terminal record cannot be established: the row stays,
// REPAIR_REQUIRED stays open, and the journal records the forensic
// escalation owed. This disposition is never coverage.
func (o *Outbox) JournalUnverifiable(ctx context.Context, rowSeq int64, executionID, detail string, auth MigrationAuthorization) error {
	if auth.Grant == nil {
		return fmt.Errorf("%w: quarantine requires an operator grant", ErrOperatorAuthorization)
	}
	if err := auth.verify(auth.DeploymentID, OperationMigrate, time.Now()); err != nil {
		return err
	}
	digest, err := GrantDigest(auth.Grant)
	if err != nil {
		return err
	}
	if used, err := o.OperatorNonceUsed(ctx, auth.Grant.Nonce, digest); err != nil {
		return err
	} else if !used {
		return fmt.Errorf("%w: quarantine grant nonce was not consumed", ErrOperatorAuthorization)
	}
	tx, err := o.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var execID, envHash string
	if err := tx.QueryRowContext(ctx,
		`SELECT execution_id, envelope_hash FROM custody_outbox WHERE seq = $1`, rowSeq).
		Scan(&execID, &envHash); err != nil {
		return fmt.Errorf("journal seq %d: %w", rowSeq, err)
	}
	if executionID != "" && executionID != execID {
		return fmt.Errorf("%w: seq %d belongs to %s, not %s", ErrEvidenceContradiction, rowSeq, execID, executionID)
	}
	authJSON, err := json.Marshal(auth.Grant)
	if err != nil {
		return err
	}
	if _, err := o.journal(ctx, tx, journalRecord{
		RowSeq: rowSeq, ExecutionID: execID, Action: JournalUnverifiable, Detail: detail,
		OriginalEnvelopeHash: envHash,
		AuthorizationJSON:    string(authJSON), AuthorizationDigest: digest,
		AuthorizedBy: auth.Grant.Subject, Nonce: auth.Grant.Nonce,
	}); err != nil {
		return err
	}
	return tx.Commit()
}

// SortMigrationRows orders rows by sequence — exported for tooling that
// renders preflight output deterministically.
func SortMigrationRows(rows []MigrationRow) {
	sort.Slice(rows, func(i, j int) bool { return rows[i].Seq < rows[j].Seq })
}
