package cli

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/openclaw/crabbox/internal/idempotency"
)

// The durable-effect operator surface. When a provider outcome cannot be
// established the record stays UNKNOWN by design — never silently failed
// or retried — and the only correct endings are a registered resolver
// proving the outcome or an approved manual intervention. These commands
// are that intervention path: every mutation goes through the store's own
// CAS, epoch fencing, and terminal-proof policy, so a stale operator view
// or an unsigned CRITICAL claim fails rather than rewriting history.

type recoveryKongCmd struct {
	List         recoveryListCmd         `cmd:"" name:"list" help:"List UNKNOWN effect records awaiting reconciliation or manual review."`
	Show         recoveryShowCmd         `cmd:"" name:"show" help:"Show one effect record's durable state and recovery locator."`
	Resolve      recoveryResolveCmd      `cmd:"" name:"resolve" help:"Resolve an UNKNOWN record to a terminal state with operator evidence."`
	AdvanceEpoch recoveryAdvanceEpochCmd `cmd:"" name:"advance-epoch" help:"Advance the cluster epoch after a store restore — fences every store admitted under the old epoch."`
	Complete     recoveryCompleteCmd     `cmd:"" name:"complete" help:"Clear post-restore cluster recovery mode so new-effect admission reopens."`
}

type recoveryListCmd struct{}

type recoveryShowCmd struct {
	ExecutionID string `arg:"" help:"Execution ID to inspect."`
	Events      bool   `help:"Also print the forensic effect-event history."`
}

type recoveryResolveCmd struct {
	ExecutionID     string `arg:"" help:"Execution ID to resolve."`
	ExpectedVersion int    `help:"Record version the operator reviewed (recovery show) — the CAS fails if the record moved since." name:"expected-version" required:""`
	Decision        string `help:"Terminal decision: committed or failed." required:""`
	Evidence        string `help:"Operator attestation file — stored verbatim as the recovery evidence and sha256-bound to it." required:""`
	ProviderID      string `help:"Provider identity the operator observed; must agree with any stored provider observation."`
	ProviderRunID   string `help:"Provider-side run or operation ID the operator confirmed."`
	Result          string `help:"Canonical JSON result to record as the terminal result."`
	ReceiptVersion  int    `help:"Evidence receipt schema version." default:"3"`
}

type recoveryAdvanceEpochCmd struct {
	Expected int64  `help:"Cluster epoch being restored from — the advance is refused if the store already moved past it." required:""`
	Reason   string `help:"Audit text recorded on the meta row (what was restored and why)." required:""`
}

type recoveryCompleteCmd struct {
	Expected   int64  `help:"Cluster epoch to clear — the clear is refused if the epoch moved past it." required:""`
	Resolution string `help:"Audit text recorded on the meta row (how the recovery backlog was accounted for)." required:""`
}

func (c *recoveryListCmd) Run(ctx context.Context, app App) error {
	store, closeStore, err := openRecoveryStore()
	if err != nil {
		return err
	}
	defer closeStore()

	if required, err := store.ClusterRecoveryRequired(ctx); err == nil && required {
		fmt.Fprintln(app.Stderr, "cluster is in post-restore recovery mode: new-effect admission is closed until 'recovery complete'")
	}
	unknown, err := store.ListUnknown(ctx)
	if err != nil {
		return fmt.Errorf("list UNKNOWN records: %w", err)
	}
	if len(unknown) == 0 {
		fmt.Fprintln(app.Stdout, "no UNKNOWN effect records")
		return nil
	}
	w := tabwriter.NewWriter(app.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "EXECUTION_ID\tCAPABILITY\tPRINCIPAL\tCLASS\tVERSION\tATTEMPTS\tENTERED_UNKNOWN\tCAUSE\tLAST_ERROR")
	for _, rec := range unknown {
		entered := "-"
		if rec.EnteredUnknownAt != nil {
			entered = rec.EnteredUnknownAt.UTC().Format(time.RFC3339)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%d\t%s\t%s\t%s\n",
			rec.ExecutionID, rec.CapabilityID, rec.PrincipalID, rec.ExecutionClass,
			rec.Version, rec.ReconcileAttempt, entered,
			truncateCell(rec.AmbiguityCause, 24), truncateCell(rec.LastReconcileError, 40))
	}
	return w.Flush()
}

func (c *recoveryShowCmd) Run(ctx context.Context, app App) error {
	store, closeStore, err := openRecoveryStore()
	if err != nil {
		return err
	}
	defer closeStore()

	rec, err := store.Lookup(ctx, c.ExecutionID)
	if err != nil {
		return fmt.Errorf("lookup %s: %w", c.ExecutionID, err)
	}
	out, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal record: %w", err)
	}
	fmt.Fprintln(app.Stdout, string(out))
	if rec.State != idempotency.StateUnknown {
		fmt.Fprintf(app.Stderr, "note: record is %s, not UNKNOWN — it is not awaiting reconciliation\n", rec.State)
	}
	if !c.Events {
		return nil
	}
	events, err := store.ListEffectEvents(ctx, c.ExecutionID)
	if err != nil {
		return fmt.Errorf("list effect events: %w", err)
	}
	out, err = json.MarshalIndent(events, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal events: %w", err)
	}
	fmt.Fprintln(app.Stdout, string(out))
	return nil
}

func (c *recoveryResolveCmd) Run(ctx context.Context, app App) error {
	var decision idempotency.RecoveryDecision
	switch strings.ToLower(c.Decision) {
	case "committed":
		decision = idempotency.RecoveryCommitted
	case "failed":
		decision = idempotency.RecoveryFailed
	default:
		return exit(2, "--decision must be committed or failed")
	}
	evidenceBytes, err := os.ReadFile(c.Evidence)
	if err != nil {
		return fmt.Errorf("read evidence: %w", err)
	}
	if len(evidenceBytes) == 0 {
		return exit(2, "--evidence file is empty: a manual resolution must name what the operator verified")
	}
	if len(evidenceBytes) > idempotency.MaxEvidenceReceiptBytes {
		return exit(2, "--evidence exceeds %d bytes", idempotency.MaxEvidenceReceiptBytes)
	}
	var result json.RawMessage
	if c.Result != "" {
		if !json.Valid([]byte(c.Result)) {
			return exit(2, "--result is not valid JSON")
		}
		result = json.RawMessage(c.Result)
	}
	evidenceSHA := sha256.Sum256(evidenceBytes)

	store, closeStore, err := openRecoveryStore()
	if err != nil {
		return err
	}
	defer closeStore()

	if err := store.ResolveRecovery(ctx, c.ExecutionID, c.ExpectedVersion, idempotency.RecoveryResult{
		Decision:        decision,
		Result:          result,
		EvidenceDigest:  hex.EncodeToString(evidenceSHA[:]),
		ReceiptVersion:  c.ReceiptVersion,
		ProviderID:      c.ProviderID,
		ProviderRunID:   c.ProviderRunID,
		EvidenceReceipt: evidenceBytes,
	}); err != nil {
		return fmt.Errorf("resolve %s: %w", c.ExecutionID, err)
	}
	fmt.Fprintf(app.Stdout, "execution %s resolved %s (version %d, evidence sha256 %s)\n",
		c.ExecutionID, decision, c.ExpectedVersion, hex.EncodeToString(evidenceSHA[:]))
	return nil
}

func (c *recoveryAdvanceEpochCmd) Run(ctx context.Context, app App) error {
	store, closeStore, err := openRecoveryStore()
	if err != nil {
		return err
	}
	defer closeStore()

	epoch, err := store.AdvanceClusterEpoch(ctx, c.Expected, c.Reason)
	if err != nil {
		return fmt.Errorf("advance cluster epoch: %w", err)
	}
	fmt.Fprintf(app.Stdout, "cluster epoch advanced to %d — stores admitted under %d are fenced; reconciliation may proceed, new-effect admission is closed until 'recovery complete'\n",
		epoch, c.Expected)
	return nil
}

func (c *recoveryCompleteCmd) Run(ctx context.Context, app App) error {
	store, closeStore, err := openRecoveryStore()
	if err != nil {
		return err
	}
	defer closeStore()

	required, err := store.ClusterRecoveryRequired(ctx)
	if err != nil {
		return fmt.Errorf("check cluster recovery mode: %w", err)
	}
	if !required {
		fmt.Fprintln(app.Stderr, "cluster is not in recovery mode — nothing to clear")
		return nil
	}
	if err := store.CompleteClusterRecovery(ctx, c.Expected, c.Resolution); err != nil {
		return fmt.Errorf("complete cluster recovery: %w", err)
	}
	fmt.Fprintf(app.Stdout, "cluster recovery mode cleared at epoch %d — new-effect admission reopened\n", c.Expected)
	return nil
}

// openRecoveryStore resolves the same store backends serve-exec uses —
// CRABEDENCE_STORE_BACKEND (auto: postgres when a DSN is set, sqlite
// otherwise), CRABEDENCE_DATABASE_URL, and CRABEDENCE_STORE_PATH — but
// only the effect store; an operator resolving a record needs no
// authority store. Mirrors the backend switch in internal/execution/serve.go.
func openRecoveryStore() (idempotency.EffectStore, func(), error) {
	backend := strings.ToLower(strings.TrimSpace(os.Getenv("CRABEDENCE_STORE_BACKEND")))
	dsn := os.Getenv("CRABEDENCE_DATABASE_URL")
	switch backend {
	case "", "auto":
		if dsn != "" {
			backend = "postgres"
		} else {
			backend = "sqlite"
		}
	case "sqlite", "postgres":
	case "none":
		return nil, nil, fmt.Errorf("CRABEDENCE_STORE_BACKEND=none — recovery commands require a durable effect store")
	default:
		return nil, nil, fmt.Errorf("unknown CRABEDENCE_STORE_BACKEND %q (want sqlite, postgres, none, or auto)", backend)
	}

	var store idempotency.EffectStore
	var db *sql.DB
	if backend == "postgres" {
		if dsn == "" {
			return nil, nil, fmt.Errorf("CRABEDENCE_STORE_BACKEND=postgres requires CRABEDENCE_DATABASE_URL")
		}
		var err error
		db, err = sql.Open("pgx", dsn)
		if err != nil {
			return nil, nil, fmt.Errorf("open postgres store: %w", err)
		}
		if err := db.PingContext(context.Background()); err != nil {
			db.Close()
			return nil, nil, fmt.Errorf("connect postgres store: %w", err)
		}
		store, err = idempotency.NewStore(db)
		if err != nil {
			db.Close()
			return nil, nil, fmt.Errorf("create idempotency store: %w", err)
		}
	} else {
		path := os.Getenv("CRABEDENCE_STORE_PATH")
		if path == "" {
			base, err := os.UserConfigDir()
			if err != nil {
				return nil, nil, fmt.Errorf("resolve config dir for embedded store: %w", err)
			}
			path = filepath.Join(base, "crabbox", "crabedence.db")
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, nil, fmt.Errorf("create store directory: %w", err)
		}
		var err error
		db, err = idempotency.OpenSQLiteDB(path)
		if err != nil {
			return nil, nil, fmt.Errorf("open embedded store %s: %w", path, err)
		}
		if err := db.PingContext(context.Background()); err != nil {
			db.Close()
			return nil, nil, fmt.Errorf("connect embedded store %s: %w", path, err)
		}
		store, err = idempotency.NewSQLiteStore(db)
		if err != nil {
			db.Close()
			return nil, nil, fmt.Errorf("create idempotency store: %w", err)
		}
	}

	// The same trusted-signer set the service was configured with: a
	// CRITICAL resolution's signed receipt must verify under it.
	if fps := os.Getenv("CRABBOX_EVIDENCE_TRUSTED_SIGNERS"); fps != "" {
		var trusted []string
		for _, fp := range strings.Split(fps, ",") {
			fp = strings.TrimSpace(fp)
			if fp == "" {
				continue
			}
			if len(fp) != 64 {
				return nil, nil, fmt.Errorf("CRABBOX_EVIDENCE_TRUSTED_SIGNERS entry %q is not a SHA-256 fingerprint (64 hex chars)", fp)
			}
			trusted = append(trusted, fp)
		}
		store.SetTrustedEvidenceSigners(trusted...)
	}
	return store, func() { db.Close() }, nil
}

func truncateCell(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}
