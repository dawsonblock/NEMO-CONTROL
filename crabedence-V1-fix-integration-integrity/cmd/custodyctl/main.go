// Command custodyctl is the shipped custody operator surface.
//
// Syntax is subcommand-first, matching the documentation:
//
//	custodyctl status   -outbox <path> [-json]
//	custodyctl inspect  -outbox <path> [-limit N] [-cursor N] [-page-size N] [-json]
//	custodyctl preflight -outbox <path> [-page-size N] [-json]
//	custodyctl migrate  -outbox <path> -effect-store <path> -deployment <id> ...
//	custodyctl rescan   -outbox <path> -effect-store <path> -deployment <id> ...
//	custodyctl repair   -outbox <path> -effect-store <path> -deployment <id> -actor <subject> -reason <text> ...
//
// Authorization: read-only operations (status, inspect, preflight) need
// only owner-level access to the outbox file. Mutating operations
// require a detached operator grant signed by a pinned repair-authority
// key (-operator-token, -repair-trust-roots), the deployment's custody
// evidence signer (-signer-key, used to re-sign envelopes), and the
// authoritative effect store. The grant's subject is the operator
// identity; -actor is accepted only when it matches the signed subject,
// so a self-supplied name never establishes authority. The grant nonce
// is consumed durably before any mutation, making replay impossible.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash"
	"os"
	"time"

	"github.com/openclaw/crabbox/internal/custody"
	"github.com/openclaw/crabbox/internal/evidence"
	"github.com/openclaw/crabbox/internal/execution"
	"github.com/openclaw/crabbox/internal/idempotency"
	"github.com/openclaw/crabbox/internal/witness"
)

const maxPageSize = 1000

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "custodyctl: "+format+"\n", args...)
	os.Exit(1)
}

func usage() {
	fmt.Fprint(os.Stderr, `usage:
  custodyctl status    -outbox <path> [-json]
  custodyctl inspect   -outbox <path> [-limit N] [-cursor N] [-page-size N] [-json]
  custodyctl preflight -outbox <path> [-page-size N] [-json]
  custodyctl fence     status -outbox <path> [-json]
  custodyctl fence     abort  (same authority flags as migrate)
  custodyctl migrate   -outbox <path> -effect-store <path> -deployment <id>
                       -signer-key <pem> -operator-token <json>
                       -custodian-trust-roots <file> -kernel-trust-roots <file>
                       -repair-trust-roots <file>
                       [-witness-socket <path> | -witness-tls <addr> -witness-tls-key <fp>]
                       [-actor <subject>] [-dry-run] [-json]
  custodyctl rescan    (same authority flags as migrate) [-dry-run] [-json]
  custodyctl repair    (same authority flags as migrate) -reason <text> [-actor <subject>] [-dry-run] [-json]

Read-only commands need no authority. Mutating commands require a
repair-authority-signed grant; -actor must match the grant subject.
Custodian, kernel-relay, and repair authorities resolve from three
separate role-pinned trust files — one file may only pin its own role.
`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	op := os.Args[1]
	switch op {
	case "help", "-h", "--help":
		usage()
		return
	case "status", "inspect", "preflight":
		runReadOnly(op, os.Args[2:])
	case "migrate", "rescan", "repair":
		runMutating(op, os.Args[2:])
	case "fence":
		runFence(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

// runFence is the migration-epoch operator surface. status is
// read-only; abort releases an epoch whose migration will never
// complete, and requires the same grant that opened it.
func runFence(args []string) {
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}
	switch args[0] {
	case "status":
		f := parseReadFlags("fence status", args[1:])
		outbox, err := witness.OpenOutboxReadOnly(f.outbox)
		if err != nil {
			fatalf("outbox (read-only): %v", err)
		}
		defer outbox.Close()
		intents, err := outbox.FenceIntents(context.Background(), f.limit)
		if err != nil {
			fatalf("fence status: %v", err)
		}
		if f.json {
			writeJSON(map[string]any{"fences": intents})
			return
		}
		if len(intents) == 0 {
			fmt.Println("no migration epochs recorded")
			return
		}
		for _, in := range intents {
			fmt.Printf("fence=%s state=%s epoch_base=%d base_hash=%s grant=%s opened=%s closed=%s\n",
				in.FenceID, in.State, in.BaseSeq, in.BaseHash, in.GrantDigest, in.OpenedAt, in.ClosedAt)
		}
	case "abort":
		runMutating("fence-abort", args[1:])
	default:
		usage()
		os.Exit(2)
	}
}

// ─── Read-only surface ───────────────────────────────────────────────

type readFlags struct {
	outbox     string
	deployment string
	json       bool
	cursor     int64
	pageSize   int
	limit      int
}

func parseReadFlags(op string, args []string) readFlags {
	fs := flag.NewFlagSet(op, flag.ContinueOnError)
	var f readFlags
	fs.StringVar(&f.outbox, "outbox", os.Getenv("CRABEDENCE_WITNESS_OUTBOX"), "custody outbox sqlite path (or CRABEDENCE_WITNESS_OUTBOX)")
	fs.StringVar(&f.deployment, "deployment", os.Getenv("CRABEDENCE_WITNESS_DEPLOYMENT"), "custody deployment id (informational for read-only commands)")
	fs.BoolVar(&f.json, "json", false, "machine-readable JSON output")
	fs.Int64Var(&f.cursor, "cursor", 0, "start after this outbox sequence")
	fs.IntVar(&f.pageSize, "page-size", 200, "rows per SQL page (1-1000)")
	fs.IntVar(&f.limit, "limit", 0, "maximum rows/events to render (0 = all pages)")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if fs.NArg() != 0 {
		fatalf("%s: unexpected arguments %v", op, fs.Args())
	}
	if f.outbox == "" {
		fatalf("%s requires -outbox (or CRABEDENCE_WITNESS_OUTBOX)", op)
	}
	normalizePage(&f.pageSize)
	return f
}

func normalizePage(pageSize *int) {
	if *pageSize <= 0 {
		*pageSize = 200
	}
	if *pageSize > maxPageSize {
		*pageSize = maxPageSize
	}
}

type statusOutput struct {
	DegradedReason string `json:"degraded_reason"`
	RepairReason   string `json:"repair_reason"`
	ObligationHWM  int64  `json:"obligation_hwm"`
	Undelivered    int64  `json:"undelivered"`
}

type inspectRow struct {
	Seq          int64  `json:"seq"`
	ExecutionID  string `json:"execution_id"`
	State        string `json:"state"`
	EnvelopeHash string `json:"envelope_hash"`
	PayloadBytes int    `json:"payload_bytes"`
}

type inspectOutput struct {
	Rows       []inspectRow `json:"rows"`
	NextCursor int64        `json:"next_cursor"`
	HasMore    bool         `json:"has_more"`
	Events     []string     `json:"events,omitempty"`
}

type preflightRow struct {
	Seq            int64  `json:"seq"`
	ExecutionID    string `json:"execution_id"`
	Classification string `json:"classification"`
	EnvelopeHash   string `json:"envelope_hash"`
}

type preflightOutput struct {
	Rows              []preflightRow                  `json:"rows"`
	NextCursor        int64                           `json:"next_cursor"`
	HasMore           bool                            `json:"has_more"`
	LegacyCount       int                             `json:"legacy_count"`
	UnackedCount      int                             `json:"unacked_count"`
	AckedCount        int                             `json:"acked_count"`
	Journal           []witness.MigrationJournalEntry `json:"journal"`
	JournalNextCursor int64                           `json:"journal_next_cursor"`
	JournalHasMore    bool                            `json:"journal_has_more"`
	MigrationPending  bool                            `json:"migration_pending"`
}

func runReadOnly(op string, args []string) {
	f := parseReadFlags(op, args)
	ctx := context.Background()
	outbox, err := witness.OpenOutboxReadOnly(f.outbox)
	if err != nil {
		fatalf("outbox (read-only): %v", err)
	}
	defer outbox.Close()

	st, err := outbox.CustodyStatus(ctx)
	if err != nil {
		fatalf("status: %v", err)
	}
	n, err := outbox.Undelivered(ctx)
	if err != nil {
		fatalf("status: %v", err)
	}
	if f.json && op == "status" {
		writeJSON(statusOutput{st.DegradedReason, st.RepairReason, st.ObligationHWM, n})
		return
	}
	if !f.json {
		fmt.Printf("degraded_reason=%q repair_reason=%q obligation_hwm=%d undelivered=%d\n",
			st.DegradedReason, st.RepairReason, st.ObligationHWM, n)
	}
	if op == "status" {
		return
	}
	switch op {
	case "inspect":
		runInspect(ctx, outbox, f)
	case "preflight":
		runPreflight(ctx, outbox, f)
	}
}

func runInspect(ctx context.Context, outbox *witness.Outbox, f readFlags) {
	var out inspectOutput
	cursor := f.cursor
	rendered := 0
	jsonCap := f.pageSize
	if f.limit > 0 {
		jsonCap = f.limit
	}
	for {
		page, err := outbox.PendingPage(ctx, cursor, f.pageSize+1)
		if err != nil {
			fatalf("inspect: %v", err)
		}
		hasMore := len(page) > f.pageSize
		if hasMore {
			page = page[:f.pageSize]
		}
		lastRendered := cursor
		for _, r := range page {
			if f.limit > 0 && rendered >= f.limit {
				break
			}
			state := "pending"
			if r.Ack != nil {
				state = "acked"
			}
			content, _ := r.Envelope.ContentBytes()
			if f.json {
				if len(out.Rows) < jsonCap {
					out.Rows = append(out.Rows, inspectRow{r.Seq, r.ExecutionID, state, r.EnvelopeHash, len(content)})
				}
			} else {
				fmt.Printf("seq=%d exec=%s %s payload=%dB hash=%s\n", r.Seq, r.ExecutionID, state, len(content), r.EnvelopeHash)
			}
			rendered++
			lastRendered = r.Seq
		}
		if f.limit > 0 && rendered >= f.limit {
			out.NextCursor = lastRendered
			if len(page) > 0 {
				out.HasMore = hasMore || lastRendered < page[len(page)-1].Seq
			}
			break
		}
		if len(page) > 0 {
			cursor = page[len(page)-1].Seq
		}
		out.NextCursor, out.HasMore = cursor, hasMore
		if !hasMore || len(page) == 0 {
			break
		}
	}
	events, err := outbox.CustodyEvents(ctx, f.limit)
	if err == nil {
		out.Events = events
		if !f.json {
			for _, e := range events {
				fmt.Println("event:", e)
			}
		}
	}
	if f.json {
		writeJSON(out)
	}
}

func runPreflight(ctx context.Context, outbox *witness.Outbox, f readFlags) {
	var out preflightOutput
	cursor := f.cursor
	jsonCap := f.pageSize
	if f.limit > 0 {
		jsonCap = f.limit
	}
	for {
		page, err := outbox.LegacyRowsPage(ctx, cursor, f.pageSize+1)
		if err != nil {
			fatalf("preflight: %v", err)
		}
		hasMore := len(page) > f.pageSize
		if hasMore {
			page = page[:f.pageSize]
		}
		for _, r := range page {
			class := "LEGACY-EMPTY-UNACKED"
			if r.Acked {
				class = "WITNESSED-LEGACY"
				out.AckedCount++
			} else {
				out.UnackedCount++
			}
			out.LegacyCount++
			if f.json {
				if len(out.Rows) < jsonCap {
					out.Rows = append(out.Rows, preflightRow{r.Seq, r.ExecutionID, class, r.EnvelopeHash})
				}
			} else {
				if r.Acked {
					fmt.Printf("seq=%d exec=%s WITNESSED-LEGACY (acknowledged — bytes are evidence; operator classification required)\n", r.Seq, r.ExecutionID)
				} else {
					fmt.Printf("seq=%d exec=%s LEGACY-EMPTY-UNACKED (compensation candidate)\n", r.Seq, r.ExecutionID)
				}
			}
		}
		if len(page) > 0 {
			cursor = page[len(page)-1].Seq
		}
		out.NextCursor, out.HasMore = cursor, hasMore
		if !hasMore || len(page) == 0 {
			break
		}
	}
	// Journal scan is paged too; only the first page is retained for
	// JSON, while text mode streams every page.
	jcursor := int64(0)
	first := true
	for {
		page, err := outbox.MigrationJournalPage(ctx, jcursor, f.pageSize+1)
		if err != nil {
			fatalf("preflight journal: %v", err)
		}
		hasMore := len(page) > f.pageSize
		if hasMore {
			page = page[:f.pageSize]
		}
		for _, e := range page {
			if f.json && first && len(out.Journal) < f.pageSize {
				out.Journal = append(out.Journal, e)
			}
			if !f.json {
				fmt.Printf("journal seq=%d row=%d exec=%s action=%s %s\n", e.Seq, e.RowSeq, e.ExecutionID, e.Action, e.Detail)
			}
		}
		if len(page) > 0 {
			jcursor = page[len(page)-1].Seq
		}
		out.JournalNextCursor, out.JournalHasMore = jcursor, hasMore
		first = false
		if !hasMore || len(page) == 0 {
			break
		}
	}
	out.MigrationPending = out.LegacyCount > 0
	if f.json {
		writeJSON(out)
	} else {
		fmt.Printf("preflight: %d legacy empty-payload rows (%d unacked compensatable, %d witnessed-legacy)\n",
			out.LegacyCount, out.UnackedCount, out.AckedCount)
	}
	if out.MigrationPending {
		os.Exit(3)
	}
}

// ─── Mutating surface ────────────────────────────────────────────────

type mutateFlags struct {
	outbox        string
	deployment    string
	trustRoots    string
	kernelTrust   string
	repairTrust   string
	socket        string
	tlsAddr       string
	tlsKeyFP      string
	policyDigest  string
	signerKey     string
	storePath     string
	release       string
	operatorToken string
	actor         string
	reason        string
	jsonOut       bool
	dryRun        bool
	cursor        int64
	pageSize      int
	limit         int
}

func parseMutateFlags(op string, args []string) mutateFlags {
	fs := flag.NewFlagSet(op, flag.ContinueOnError)
	var f mutateFlags
	fs.StringVar(&f.outbox, "outbox", os.Getenv("CRABEDENCE_WITNESS_OUTBOX"), "custody outbox sqlite path")
	fs.StringVar(&f.deployment, "deployment", os.Getenv("CRABEDENCE_WITNESS_DEPLOYMENT"), "custody deployment id")
	fs.StringVar(&f.trustRoots, "custodian-trust-roots", os.Getenv("CRABEDENCE_WITNESS_TRUST_ROOTS"), "custodian trust set JSON (custodian keys only)")
	fs.StringVar(&f.trustRoots, "trust-roots", os.Getenv("CRABEDENCE_WITNESS_TRUST_ROOTS"), "alias for -custodian-trust-roots")
	fs.StringVar(&f.kernelTrust, "kernel-trust-roots", os.Getenv("CRABEDENCE_WITNESS_KERNEL_TRUST_ROOTS"), "kernel-relay trust set JSON (kernel-relay keys only)")
	fs.StringVar(&f.repairTrust, "repair-trust-roots", os.Getenv("CRABEDENCE_REPAIR_TRUST_ROOTS"), "pinned repair-authority trust set JSON")
	fs.StringVar(&f.socket, "witness-socket", os.Getenv("CRABEDENCE_WITNESS_SOCKET"), "witness unix socket")
	fs.StringVar(&f.tlsAddr, "witness-tls", os.Getenv("CRABEDENCE_WITNESS_TLS"), "witness TLS addr:port")
	fs.StringVar(&f.tlsKeyFP, "witness-tls-key", os.Getenv("CRABEDENCE_WITNESS_TLS_KEY"), "pinned witness TLS key fingerprint")
	fs.StringVar(&f.policyDigest, "policy-digest", os.Getenv("CRABEDENCE_POLICY_DIGEST"), "custody policy digest")
	fs.StringVar(&f.signerKey, "signer-key", os.Getenv("CRABBOX_EVIDENCE_KEY"), "custody evidence signer PKCS8 PEM")
	fs.StringVar(&f.storePath, "effect-store", os.Getenv("CRABEDENCE_EFFECT_STORE"), "authoritative effect store sqlite path")
	fs.StringVar(&f.release, "release-version", "", "release identity version bound into envelopes")
	fs.StringVar(&f.operatorToken, "operator-token", "", "signed operator grant JSON — REQUIRED for mutation")
	fs.StringVar(&f.actor, "actor", os.Getenv("USER"), "operator identity — must match the signed grant subject")
	fs.StringVar(&f.reason, "reason", "", "operator reason — REQUIRED for repair")
	fs.BoolVar(&f.jsonOut, "json", false, "machine-readable JSON output")
	fs.BoolVar(&f.dryRun, "dry-run", false, "verify authorization and preflight without mutating")
	fs.Int64Var(&f.cursor, "cursor", 0, "start after this outbox sequence")
	fs.IntVar(&f.pageSize, "page-size", 200, "rows per SQL page (1-1000)")
	fs.IntVar(&f.limit, "limit", 0, "maximum rows to process (0 = all)")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if fs.NArg() != 0 {
		fatalf("%s: unexpected arguments %v", op, fs.Args())
	}
	normalizePage(&f.pageSize)
	return f
}

type repairOutput struct {
	Operation string `json:"operation"`
	DryRun    bool   `json:"dry_run"`
	Subject   string `json:"subject"`
	Grant     string `json:"grant_digest"`
	State     string `json:"state"`
	Result    string `json:"result"`
}

type migrateOutput struct {
	Operation   string   `json:"operation"`
	DryRun      bool     `json:"dry_run"`
	Subject     string   `json:"subject"`
	Grant       string   `json:"grant_digest"`
	Compensated int      `json:"compensated"`
	Witnessed   int      `json:"witnessed"`
	Quarantined int      `json:"quarantined"`
	Blocked     int      `json:"blocked"`
	AlreadyDone int      `json:"already_done"`
	Checkpoint  bool     `json:"checkpoint_verified"`
	FenceID     string   `json:"fence_id,omitempty"`
	FenceEpoch  int64    `json:"fence_epoch,omitempty"`
	FenceResult string   `json:"fence_result_digest,omitempty"`
	Resumed     bool     `json:"resumed_epoch,omitempty"`
	Errors      []string `json:"errors,omitempty"`
}

func writeJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		fatalf("json output: %v", err)
	}
}

func loadGrant(path string) (*witness.OperatorGrant, error) {
	if path == "" {
		return nil, fmt.Errorf("operator grant required (-operator-token)")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("operator token: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("operator token %s must be a regular file, not a symlink", path)
	}
	if info.Size() == 0 || info.Size() > 1<<20 {
		return nil, fmt.Errorf("operator token %s has invalid size %d", path, info.Size())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var g witness.OperatorGrant
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&g); err != nil {
		return nil, fmt.Errorf("operator token %s: %w", path, err)
	}
	return &g, nil
}

func runMutating(op string, args []string) {
	f := parseMutateFlags(op, args)
	if f.outbox == "" || f.deployment == "" || f.storePath == "" || f.signerKey == "" {
		fatalf("%s requires -outbox, -deployment, -effect-store and -signer-key", op)
	}
	if f.repairTrust == "" {
		fatalf("%s requires -repair-trust-roots — repair authority is never inferred from the evidence signer", op)
	}
	if f.trustRoots == "" {
		fatalf("%s requires -custodian-trust-roots — witness acknowledgements, checkpoints and migration epochs are unverifiable without a pinned custodian set", op)
	}
	if f.kernelTrust == "" {
		fatalf("%s requires -kernel-trust-roots — migration proofs are signed by the kernel relay and verified against a set pinned separately from the custodian set", op)
	}
	if op == "repair" && f.reason == "" {
		fatalf("repair requires -reason — an auditable operator justification")
	}
	ctx := context.Background()

	grant, err := loadGrant(f.operatorToken)
	if err != nil {
		fatalf("%s: %v", op, err)
	}
	// Each authority resolves from its own role-pinned file. A set that
	// pins another role's key is a configuration fault, not a broader
	// trust decision, so the loader refuses it rather than filtering.
	repairTrust, err := custody.LoadTrustSetForRole(f.repairTrust, custody.RoleRepairAuthority)
	if err != nil {
		fatalf("%s repair trust: %v", op, err)
	}
	trust, err := custody.LoadTrustSetForRole(f.trustRoots, custody.RoleCustodian)
	if err != nil {
		fatalf("%s custodian trust: %v", op, err)
	}
	kernelTrust, err := custody.LoadTrustSetForRole(f.kernelTrust, custody.RoleKernelRelay)
	if err != nil {
		fatalf("%s kernel-relay trust: %v", op, err)
	}
	if err := custody.CheckDisjointRoles(map[string]*custody.TrustSet{
		"custodian": trust, "kernel-relay": kernelTrust, "repair-authority": repairTrust,
	}); err != nil {
		fatalf("%s trust configuration: %v", op, err)
	}
	operation := witness.OperationMigrate
	switch op {
	case "repair":
		operation = witness.OperationRepair
	case "rescan":
		operation = witness.OperationRescan
	}
	if err := witness.VerifyOperatorGrant(grant, repairTrust, f.deployment, operation, time.Now()); err != nil {
		fatalf("%s: %v", op, err)
	}
	if f.actor != "" && f.actor != grant.Subject {
		fatalf("%s: -actor %q does not match the signed grant subject %q — a caller-supplied name never establishes identity", op, f.actor, grant.Subject)
	}
	grantDigest, err := witness.GrantDigest(grant)
	if err != nil {
		fatalf("%s: %v", op, err)
	}
	if op == "fence-abort" {
		runFenceAbort(ctx, f, grant, grantDigest, trust, kernelTrust)
		return
	}

	rawKey, err := os.ReadFile(f.signerKey)
	if err != nil {
		fatalf("signer key: %v", err)
	}
	signer, err := evidence.ParseSignerPEM(rawKey)
	if err != nil {
		fatalf("signer key: %v", err)
	}
	outbox, err := witness.OpenOutbox(f.outbox)
	if err != nil {
		fatalf("outbox: %v", err)
	}
	defer outbox.Close()
	db, err := idempotency.OpenSQLiteDB(f.storePath)
	if err != nil {
		fatalf("effect store: %v", err)
	}
	defer db.Close()
	store, err := idempotency.NewSQLiteStore(db)
	if err != nil {
		fatalf("effect store: %v", err)
	}
	version := f.release
	if version == "" {
		version = "custodyctl"
	}
	producer := witness.Producer{
		DeploymentID: f.deployment,
		Release:      custody.ReleaseIdentity{Version: version},
		PolicyDigest: f.policyDigest,
		Signer:       signer,
	}
	policy := execution.CustodyCoveragePolicy{
		DeploymentID:   f.deployment,
		RepairTrust:    repairTrust,
		CustodianTrust: trust,
		ProofTrust:     kernelTrust,
	}
	var client *witness.Client
	if f.tlsAddr != "" {
		tlsCfg, err := witness.ClientTLSConfig(signer, f.tlsKeyFP)
		if err != nil {
			fatalf("witness tls: %v", err)
		}
		client = witness.NewTLSClient(f.tlsAddr, tlsCfg)
	} else if f.socket != "" {
		client = witness.NewClient(f.socket)
	}
	auth := witness.OperatorAuthorization{Grant: grant, Trust: repairTrust, DeploymentID: f.deployment}

	if f.dryRun && op != "migrate" {
		state := "unknown"
		if st, serr := outbox.CustodyStatus(ctx); serr == nil {
			switch {
			case st.RepairReason != "":
				state = "REPAIR_REQUIRED"
			case st.DegradedReason != "":
				state = "DEGRADED"
			default:
				state = "HEALTHY_MARKERS_CLEAR"
			}
		}
		if f.jsonOut {
			writeJSON(repairOutput{Operation: op, DryRun: true, Subject: grant.Subject, Grant: grantDigest, State: state, Result: "authorization verified; no mutation performed"})
		} else {
			fmt.Printf("%s dry-run: authorization verified for %q (%s), custody state %s; no mutation performed\n", op, grant.Subject, grantDigest, state)
		}
		return
	}

	if !f.dryRun {
		// A migration that crashed after opening its epoch still holds
		// the consumed nonce. Resuming that epoch is the same
		// authorization act, not a replay: the durable fence intent is
		// the evidence, and the witness will only accept the same
		// fence identity.
		pending, perr := outbox.PendingFenceIntent(ctx, f.deployment, grantDigest)
		if perr != nil {
			fatalf("%s: %v", op, perr)
		}
		if pending != nil && op == "migrate" {
			fmt.Fprintf(os.Stderr, "custodyctl: resuming migration epoch %s (base seq %d)\n", pending.FenceID, pending.BaseSeq)
		} else if err := outbox.ConsumeOperatorNonce(ctx, grant, operation); err != nil {
			fatalf("%s: %v", op, err)
		}
	}

	switch op {
	case "repair":
		if client == nil {
			fatalf("repair requires -witness-socket or -witness-tls — a repair without the witness cannot verify custody")
		}
		sender := witness.NewSender(client, outbox, f.deployment, trust, nil)
		sender.SetObligationScanner(func(ctx context.Context) error {
			hwm, err := outbox.ObligationHighWater(ctx)
			if err != nil {
				return err
			}
			return execution.ReconcileCustodyObligationsFrom(ctx, store, outbox, producer, hwm, policy)
		})
		sender.SetFullRescanScanner(func(ctx context.Context) error {
			return execution.CustodyObligationRescan(ctx, store, outbox, producer, policy)
		})
		if err := sender.OperatorRepair(ctx, auth, f.reason); err != nil {
			fatalf("repair: %v", err)
		}
		if f.jsonOut {
			writeJSON(repairOutput{Operation: op, Subject: grant.Subject, Grant: grantDigest, State: sender.CustodyState(ctx), Result: "REPAIR_REQUIRED cleared after verified full rescan"})
		} else {
			fmt.Println("repair: REPAIR_REQUIRED cleared after verified full rescan")
		}
	case "rescan":
		if err := execution.CustodyObligationRescan(ctx, store, outbox, producer, policy); err != nil {
			fatalf("rescan: %v", err)
		}
		if f.jsonOut {
			writeJSON(repairOutput{Operation: op, Subject: grant.Subject, Grant: grantDigest, State: "RESCANNED", Result: "full-history obligation stream verified clean"})
		} else {
			fmt.Println("rescan: full-history obligation stream verified clean")
		}
	case "migrate":
		runMigrate(ctx, outbox, store, producer, policy, f, auth, grant, grantDigest, client)
	}
}

// runFenceAbort releases a migration epoch whose rewrite will never
// complete. It requires the same grant that opened the epoch, so an
// unrelated operator cannot unfreeze custody, and the witness refuses
// the abort if custody moved while the epoch was open.
func runFenceAbort(ctx context.Context, f mutateFlags, grant *witness.OperatorGrant, grantDigest string, trust, kernelTrust *custody.TrustSet) {
	if f.socket == "" && f.tlsAddr == "" {
		fatalf("fence abort requires -witness-socket or -witness-tls — an epoch is released at the custodian, never locally")
	}
	rawKey, err := os.ReadFile(f.signerKey)
	if err != nil {
		fatalf("signer key: %v", err)
	}
	signer, err := evidence.ParseSignerPEM(rawKey)
	if err != nil {
		fatalf("signer key: %v", err)
	}
	outbox, err := witness.OpenOutbox(f.outbox)
	if err != nil {
		fatalf("outbox: %v", err)
	}
	defer outbox.Close()
	pending, err := outbox.PendingFenceIntent(ctx, f.deployment, grantDigest)
	if err != nil {
		fatalf("fence abort: %v", err)
	}
	if pending == nil {
		fatalf("fence abort: no open migration epoch was opened by this grant")
	}
	// Releasing an epoch that already rewrote rows would resume
	// submissions against a suffix the sender may still hold in its old
	// form — the exact in-flight corruption the epoch exists to
	// prevent. An epoch that committed anything is closed, never
	// aborted.
	committed, err := outbox.JournalSince(ctx, pending.OpenedAt)
	if err != nil {
		fatalf("fence abort: %v", err)
	}
	if committed > 0 {
		fatalf("fence abort: epoch %s already committed %d migration(s) — finish the run to close it; aborting would resume submissions against a rewritten suffix", pending.FenceID, committed)
	}
	client, err := witnessClient(f, signer)
	if err != nil {
		fatalf("fence abort: %v", err)
	}
	fc := &witness.FenceClient{
		Client: client, Signer: signer, DeploymentID: f.deployment,
		GrantDigest: grantDigest, KernelTrust: kernelTrust, CustodianTrust: trust,
	}
	receipt, err := fc.Abort(ctx, witness.FenceReceipt{
		FenceID: pending.FenceID, GrantDigest: grantDigest,
		BaseSeq: pending.BaseSeq, BaseHash: pending.BaseHash,
	})
	if err != nil {
		fatalf("fence abort: %v", err)
	}
	if err := outbox.CompleteFenceIntent(ctx, receipt.FenceID, receipt.State, ""); err != nil {
		fatalf("fence abort: %v", err)
	}
	if f.jsonOut {
		writeJSON(map[string]any{"operation": "fence-abort", "fence_id": receipt.FenceID, "state": receipt.State, "subject": grant.Subject})
		return
	}
	fmt.Printf("fence abort: epoch %s released (%s); submissions resume on the next drain\n", receipt.FenceID, receipt.State)
}

// witnessClient builds the kernel's transport handle from the
// configured posture.
func witnessClient(f mutateFlags, signer *evidence.Signer) (*witness.Client, error) {
	if f.tlsAddr != "" {
		tlsCfg, err := witness.ClientTLSConfig(signer, f.tlsKeyFP)
		if err != nil {
			return nil, fmt.Errorf("witness tls: %w", err)
		}
		return witness.NewTLSClient(f.tlsAddr, tlsCfg), nil
	}
	if f.socket != "" {
		return witness.NewClient(f.socket), nil
	}
	return nil, fmt.Errorf("no witness transport configured")
}

func runMigrate(ctx context.Context, outbox *witness.Outbox, store idempotency.EffectStore, producer witness.Producer, policy execution.CustodyCoveragePolicy, f mutateFlags, auth witness.OperatorAuthorization, grant *witness.OperatorGrant, grantDigest string, client *witness.Client) {
	out := migrateOutput{Operation: "migrate", Subject: grant.Subject, Grant: grantDigest}
	// Offline suffix rewriting is not authorized. A checkpoint proves
	// the custodian's state at one instant; only an open migration
	// epoch proves nothing can still land while the rewrite commits.
	// The epoch is opened first and closed last, and every rewrite
	// binds its signed receipt.
	if client == nil {
		fatalf("migrate requires -witness-socket or -witness-tls — offline suffix rewriting is not authorized without a verified custodian epoch")
	}
	fenceClient := &witness.FenceClient{
		Client: client, Signer: producer.Signer, DeploymentID: f.deployment,
		GrantDigest: grantDigest, KernelTrust: policy.ProofTrust, CustodianTrust: policy.CustodianTrust,
	}
	fence, resumed, err := openMigrationEpoch(ctx, outbox, fenceClient, f.deployment, grantDigest)
	if err != nil {
		fatalf("migrate: %v", err)
	}
	out.FenceID, out.FenceEpoch, out.Resumed = fence.FenceID, fence.Epoch, resumed
	out.Checkpoint = true

	// The epoch is closed exactly once, on the success path: a failed
	// rewrite leaves the custodian frozen on purpose, so a second
	// migration cannot start against a half-rewritten suffix.
	result := newMigrationDigest()

	cursor := f.cursor
	processed := 0
	for {
		page, err := outbox.LegacyRowsPage(ctx, cursor, f.pageSize)
		if err != nil {
			fatalf("migrate: %v", err)
		}
		for _, r := range page {
			if f.limit > 0 && processed >= f.limit {
				break
			}
			processed++
			rec, lerr := store.Lookup(ctx, r.ExecutionID)
			if lerr != nil && !errors.Is(lerr, sql.ErrNoRows) {
				// A read failure is not "no authoritative record": it
				// must never become a durable forensic quarantine.
				fatalf("migrate seq %d: authoritative record read: %v", r.Seq, lerr)
			}
			if rec == nil || rec.TerminalReceiptDigest == "" {
				if !f.dryRun {
					if err := outbox.JournalUnverifiable(ctx, r.Seq, r.ExecutionID,
						fmt.Sprintf("operator %s: no authoritative terminal record — quarantined pending forensic escalation", grant.Subject), auth); err != nil {
						fatalf("migrate seq %d quarantine: %v", r.Seq, err)
					}
				}
				out.Quarantined++
				continue
			}
			if r.Acked {
				if !f.dryRun {
					if err := outbox.JournalLegacyWitnessed(ctx, r.Seq, rec.TerminalReceiptDigest,
						fmt.Sprintf("operator %s classified witnessed legacy divergence (grant %s)", grant.Subject, grantDigest), auth); err != nil {
						fatalf("migrate seq %d journal: %v", r.Seq, err)
					}
				}
				out.Witnessed++
				continue
			}
			payload, perr := idempotency.TerminalReceiptFromRecord(rec).CustodyPayload()
			if perr != nil || len(payload) == 0 {
				if !f.dryRun {
					if err := outbox.JournalUnverifiable(ctx, r.Seq, r.ExecutionID,
						fmt.Sprintf("operator %s: terminal record cannot produce a canonical payload — quarantined", grant.Subject), auth); err != nil {
						fatalf("migrate seq %d quarantine: %v", r.Seq, err)
					}
				}
				out.Quarantined++
				continue
			}
			pf, err := outbox.MigrationPreflight(ctx, r.Seq, witness.CheckpointRef{
				Seq: fence.BaseSeq, Hash: fence.BaseHash, WitnessFP: fence.WitnessFP,
			})
			if err != nil {
				fatalf("migrate seq %d preflight: %v", r.Seq, err)
			}
			if pf.Blocked {
				out.Blocked++
				out.Errors = append(out.Errors, fmt.Sprintf("seq %d: %s", r.Seq, pf.Reason))
				continue
			}
			if f.dryRun {
				out.Compensated++
				continue
			}
			// Admit exactly one transaction for this target, bound to the
			// bytes it holds right now, then record the admission
			// locally before any mutation runs.
			// Bind the admission to the bytes preflight just inspected.
			// A successor's hash changes when its predecessor is
			// rewritten, so the page-level hash is stale by the time a
			// later row in the same suffix is admitted.
			permit, perr := fenceClient.Prepare(ctx, fence, r.Seq, pf.EnvelopeHash)
			if perr != nil {
				fatalf("migrate seq %d: %v (epoch %s stays open)", r.Seq, perr, fence.FenceID)
			}
			if _, aerr := outbox.AdmitMigration(ctx, &permit); aerr != nil {
				fatalf("migrate seq %d: %v", r.Seq, aerr)
			}
			res, err := outbox.MigrateLegacySuffix(ctx, producer, witness.MigrationRequest{
				RowSeq:                r.Seq,
				TerminalReceiptDigest: rec.TerminalReceiptDigest,
				Native:                payload,
				Permit:                permit,
				Authorization:         auth,
				CustodianTrust:        policy.CustodianTrust,
			})
			if err != nil {
				// The epoch stays open deliberately: a failed rewrite
				// must not silently release custody, and the operator
				// re-runs migrate with the same grant to resume it.
				fatalf("migrate seq %d: %v (epoch %s stays open; re-run with the same grant to resume)", r.Seq, err, fence.FenceID)
			}
			terminal, ferr := fenceClient.Finalize(ctx, permit, witness.FinalizeReport{
				ProofDigest:  res.ProofDigest,
				JournalSeq:   res.JournalSeq,
				BeforeDigest: res.BeforeDigest,
				AfterDigest:  res.AfterDigest,
				ResultDigest: result.sum(),
			})
			if ferr != nil {
				fatalf("migrate seq %d: local rewrite committed but the witness did not record it: %v — the epoch stays open and must be finalized, never aborted", r.Seq, ferr)
			}
			if cerr := outbox.CompleteMigrationTx(ctx, &terminal); cerr != nil {
				fatalf("migrate seq %d: local transaction: %v", r.Seq, cerr)
			}
			if res.AlreadyMigrated {
				out.AlreadyDone++
			} else {
				out.Compensated++
			}
			result.add(r.Seq, res.AfterDigest)
		}
		if len(page) > 0 {
			cursor = page[len(page)-1].Seq
		}
		if len(page) < f.pageSize || (f.limit > 0 && processed >= f.limit) {
			break
		}
	}
	if !f.dryRun {
		receipt, cerr := fenceClient.End(ctx, fence, result.sum())
		if cerr != nil {
			fatalf("migrate: migration epoch %s could not be closed: %v — custody stays fenced until an operator resolves it", fence.FenceID, cerr)
		}
		if cerr := outbox.CompleteFenceIntent(ctx, fence.FenceID, receipt.State, receipt.ResultDigest); cerr != nil {
			fatalf("migrate: fence intent: %v", cerr)
		}
		out.FenceResult = receipt.ResultDigest
	}
	out.DryRun = f.dryRun
	if f.jsonOut {
		writeJSON(out)
	} else {
		fmt.Printf("migrate: %d compensated, %d journaled legacy-witnessed, %d quarantined unverifiable, %d blocked, %d already migrated (epoch %s at seq %d)\n",
			out.Compensated, out.Witnessed, out.Quarantined, out.Blocked, out.AlreadyDone, fence.FenceID, fence.BaseSeq)
		for _, e := range out.Errors {
			fmt.Fprintln(os.Stderr, "custodyctl: blocked:", e)
		}
	}
	if out.Blocked > 0 || out.Quarantined > 0 {
		os.Exit(3)
	}
}

// openMigrationEpoch resumes the epoch this grant already planned, or
// plans and opens a new one. The local intent is durable before the
// witness is asked to freeze, so a crash in between is recoverable
// rather than an orphaned epoch nobody can name.
func openMigrationEpoch(ctx context.Context, outbox *witness.Outbox, fenceClient *witness.FenceClient, deploymentID, grantDigest string) (witness.FenceReceipt, bool, error) {
	pending, err := outbox.PendingFenceIntent(ctx, deploymentID, grantDigest)
	if err != nil {
		return witness.FenceReceipt{}, false, err
	}
	if pending != nil {
		receipt, rerr := fenceClient.Reenter(ctx, pending.FenceID, pending.BaseSeq, pending.BaseHash)
		if rerr == nil {
			return receipt, true, nil
		}
		// A witness that never saw the planned epoch has no fence to
		// re-enter; fall through and plan a fresh one.
		if !errors.Is(rerr, witness.ErrFenceState) {
			return witness.FenceReceipt{}, false, rerr
		}
	}
	const attempts = 8
	var last error
	for attempt := 0; attempt < attempts; attempt++ {
		req, perr := fenceClient.Plan(ctx)
		if perr != nil {
			return witness.FenceReceipt{}, false, perr
		}
		if err := outbox.RecordFenceIntent(ctx, witness.FenceIntent{
			FenceID: req.FenceID, DeploymentID: deploymentID, GrantDigest: grantDigest,
			BaseSeq: req.BaseSeq, BaseHash: req.BaseHash, State: witness.FenceOpen,
			OpenedAt: time.Now().UTC().Format(time.RFC3339Nano),
		}); err != nil {
			return witness.FenceReceipt{}, false, err
		}
		receipt, oerr := fenceClient.Open(ctx, req)
		if oerr == nil {
			return receipt, false, nil
		}
		if !errors.Is(oerr, witness.ErrStaleFenceBase) {
			return witness.FenceReceipt{}, false, oerr
		}
		last = oerr
	}
	return witness.FenceReceipt{}, false, fmt.Errorf("custody head kept moving across %d attempts — submissions must quiesce before a migration epoch can open: %w", attempts, last)
}

// migrationDigest is the ordered digest of the rewrites one epoch
// performed. It is what the fence closes over, so the custodian records
// which migrations ran inside the frozen window.
type migrationDigest struct{ h hash.Hash }

func newMigrationDigest() *migrationDigest { return &migrationDigest{h: sha256.New()} }

func (m *migrationDigest) add(seq int64, afterDigest string) {
	fmt.Fprintf(m.h, "%d\x00%s\x00", seq, afterDigest)
}

func (m *migrationDigest) sum() string { return hex.EncodeToString(m.h.Sum(nil)) }
