// Command custodyctl is the shipped custody operator surface
// (RC8.3 PR-02/PR-03): status, inspect, preflight, migrate, rescan and
// repair over the kernel custody outbox — the lifecycle that was
// previously unreachable outside package internals.
//
// Authorization: read-only operations (status, inspect, preflight)
// need only owner-level access to the outbox file. Mutating
// operations (migrate, rescan, repair) require -signer-key — the
// deployment's custody evidence signer — plus -actor naming the
// authenticated operator; repair additionally requires -reason.
// Possession of the signer is the authorization proof: only its
// holder can produce envelopes the witness trusts, and the audit
// record binds actor + fingerprint + reason durably.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/openclaw/crabbox/internal/custody"
	"github.com/openclaw/crabbox/internal/evidence"
	"github.com/openclaw/crabbox/internal/execution"
	"github.com/openclaw/crabbox/internal/idempotency"
	"github.com/openclaw/crabbox/internal/witness"
)

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "custodyctl: "+format+"\n", args...)
	os.Exit(1)
}

func main() {
	outboxPath := flag.String("outbox", os.Getenv("CRABEDENCE_WITNESS_OUTBOX"), "custody outbox sqlite path (or CRABEDENCE_WITNESS_OUTBOX)")
	deployment := flag.String("deployment", os.Getenv("CRABEDENCE_WITNESS_DEPLOYMENT"), "custody deployment id (or CRABEDENCE_WITNESS_DEPLOYMENT)")
	trustRoots := flag.String("trust-roots", os.Getenv("CRABEDENCE_WITNESS_TRUST_ROOTS"), "custodian trust set JSON (or CRABEDENCE_WITNESS_TRUST_ROOTS)")
	socket := flag.String("witness-socket", os.Getenv("CRABEDENCE_WITNESS_SOCKET"), "witness unix socket (or CRABEDENCE_WITNESS_SOCKET)")
	tlsAddr := flag.String("witness-tls", os.Getenv("CRABEDENCE_WITNESS_TLS"), "witness TLS addr:port (or CRABEDENCE_WITNESS_TLS)")
	tlsKeyFP := flag.String("witness-tls-key", os.Getenv("CRABEDENCE_WITNESS_TLS_KEY"), "pinned witness TLS key fingerprint (or CRABEDENCE_WITNESS_TLS_KEY)")
	policyDigest := flag.String("policy-digest", os.Getenv("CRABEDENCE_POLICY_DIGEST"), "custody policy digest (or CRABEDENCE_POLICY_DIGEST)")
	signerKey := flag.String("signer-key", os.Getenv("CRABBOX_EVIDENCE_KEY"), "custody evidence signer PKCS8 PEM — required for mutating operations (or CRABBOX_EVIDENCE_KEY)")
	storePath := flag.String("effect-store", os.Getenv("CRABEDENCE_EFFECT_STORE"), "authoritative effect store sqlite path — required for migrate/rescan/repair (or CRABEDENCE_EFFECT_STORE)")
	releaseVersion := flag.String("release-version", "", "release identity version bound into compensated envelopes (default: custodyctl)")
	actor := flag.String("actor", os.Getenv("USER"), "authenticated operator identity recorded in the audit journal")
	reason := flag.String("reason", "", "operator reason — REQUIRED for repair, recorded durably")
	limit := flag.Int("limit", 50, "max rows for inspect")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: custodyctl <status|inspect|preflight|migrate|rescan|repair> [flags]\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	op := flag.Arg(0)
	ctx := context.Background()

	outbox, err := witness.OpenOutbox(*outboxPath)
	if err != nil {
		fatalf("outbox: %v", err)
	}
	defer outbox.Close()

	switch op {
	case "status", "inspect", "preflight":
		// Read-only surface — no signer required.
		st, err := outbox.CustodyStatus(ctx)
		if err != nil {
			fatalf("status: %v", err)
		}
		n, _ := outbox.Undelivered(ctx)
		fmt.Printf("degraded_reason=%q repair_reason=%q obligation_hwm=%d undelivered=%d\n",
			st.DegradedReason, st.RepairReason, st.ObligationHWM, n)
		if op == "status" {
			return
		}
		if op == "inspect" {
			rows, err := outbox.Pending(ctx)
			if err != nil {
				fatalf("inspect: %v", err)
			}
			for i, r := range rows {
				if i >= *limit {
					break
				}
				acked := "pending"
				if r.Ack != nil {
					acked = "acked"
				}
				content, _ := r.Envelope.ContentBytes()
				fmt.Printf("seq=%d exec=%s %s payload=%dB hash=%s\n", r.Seq, r.ExecutionID, acked, len(content), r.EnvelopeHash)
			}
			events, err := outbox.CustodyEvents(ctx, *limit)
			if err == nil {
				for _, e := range events {
					fmt.Println("event:", e)
				}
			}
			return
		}
		// preflight — read-only legacy classification.
		legacy, err := outbox.LegacyRows(ctx)
		if err != nil {
			fatalf("preflight: %v", err)
		}
		var unacked, acked int
		for _, r := range legacy {
			if r.Acked {
				acked++
				fmt.Printf("seq=%d exec=%s WITNESSED-LEGACY (acknowledged — bytes are evidence; operator classification required)\n", r.Seq, r.ExecutionID)
			} else {
				unacked++
				fmt.Printf("seq=%d exec=%s LEGACY-EMPTY-UNACKED (compensation candidate)\n", r.Seq, r.ExecutionID)
			}
		}
		fmt.Printf("preflight: %d legacy empty-payload rows (%d unacked compensatable, %d witnessed-legacy)\n", len(legacy), unacked, acked)
		journal, _ := outbox.MigrationJournal(ctx)
		for _, e := range journal {
			fmt.Printf("journal seq=%d row=%d exec=%s action=%s %s\n", e.Seq, e.RowSeq, e.ExecutionID, e.Action, e.Detail)
		}
		if len(legacy) > 0 {
			os.Exit(3) // migration pending — callers gate admission on this
		}
		return
	}

	// Mutating operations: signer + store + witness client required.
	if *signerKey == "" {
		fatalf("%s requires -signer-key — mutating custody operations carry authenticated-authority proof", op)
	}
	if *actor == "" {
		fatalf("%s requires -actor — operator actions bind an authenticated identity", op)
	}
	raw, err := os.ReadFile(*signerKey)
	if err != nil {
		fatalf("signer key: %v", err)
	}
	signer, err := evidence.ParseSignerPEM(raw)
	if err != nil {
		fatalf("signer key: %v", err)
	}
	trust, err := custody.LoadTrustSet(*trustRoots)
	if err != nil {
		fatalf("trust roots: %v", err)
	}
	db, err := idempotency.OpenSQLiteDB(*storePath)
	if err != nil {
		fatalf("effect store: %v", err)
	}
	defer db.Close()
	store, err := idempotency.NewSQLiteStore(db)
	if err != nil {
		fatalf("effect store: %v", err)
	}
	var client *witness.Client
	if *tlsAddr != "" {
		tlsCfg, err := witness.ClientTLSConfig(signer, *tlsKeyFP)
		if err != nil {
			fatalf("witness tls: %v", err)
		}
		client = witness.NewTLSClient(*tlsAddr, tlsCfg)
	} else {
		if *socket == "" {
			fatalf("%s requires -witness-socket or -witness-tls", op)
		}
		client = witness.NewClient(*socket)
	}
	version := *releaseVersion
	if version == "" {
		version = "custodyctl"
	}
	producer := witness.Producer{
		DeploymentID: *deployment,
		Release:      custody.ReleaseIdentity{Version: version},
		PolicyDigest: *policyDigest,
		Signer:       signer,
	}
	sender := witness.NewSender(client, outbox, *deployment, trust, nil)
	sender.SetObligationScanner(func(ctx context.Context) error {
		hwm, err := outbox.ObligationHighWater(ctx)
		if err != nil {
			return err
		}
		return reconcileShim(ctx, store, outbox, producer, hwm)
	})
	sender.SetFullRescanScanner(func(ctx context.Context) error {
		return execution.CustodyObligationRescan(ctx, store, outbox, producer)
	})

	switch op {
	case "migrate":
		// Operator-approved classification: unacked legacy rows are
		// compensated from the authoritative terminal record;
		// witnessed rows are journaled legacy-witnessed; rows with no
		// terminal record are quarantined as unverifiable.
		legacy, err := outbox.LegacyRows(ctx)
		if err != nil {
			fatalf("migrate: %v", err)
		}
		var compensated, journaled, blocked int
		for _, r := range legacy {
			if r.Acked {
				if err := outbox.JournalLegacyWitnessed(ctx, r.Seq,
					fmt.Sprintf("operator %s classified witnessed legacy divergence (signer %s)", *actor, signer.Fingerprint())); err != nil {
					fatalf("journal seq %d: %v", r.Seq, err)
				}
				journaled++
				continue
			}
			rec, lerr := store.Lookup(ctx, r.ExecutionID)
			if lerr != nil || rec == nil || rec.TerminalReceiptDigest == "" {
				_ = outbox.JournalUnverifiable(ctx, r.Seq, r.ExecutionID,
					fmt.Sprintf("operator %s: no authoritative terminal record — quarantined pending forensic escalation", *actor))
				blocked++
				continue
			}
			payload, perr := idempotency.TerminalReceiptFromRecord(rec).CustodyPayload()
			if perr != nil || len(payload) == 0 {
				_ = outbox.JournalUnverifiable(ctx, r.Seq, r.ExecutionID,
					fmt.Sprintf("operator %s: terminal record cannot produce a canonical payload — quarantined", *actor))
				blocked++
				continue
			}
			if err := outbox.CompensateLegacyRow(ctx, producer, r.Seq, rec.TerminalReceiptDigest, payload); err != nil {
				fatalf("compensate seq %d: %v", r.Seq, err)
			}
			compensated++
		}
		fmt.Printf("migrate: %d compensated, %d journaled legacy-witnessed, %d quarantined unverifiable\n", compensated, journaled, blocked)
		if blocked > 0 {
			os.Exit(3)
		}
	case "rescan":
		if err := execution.CustodyObligationRescan(ctx, store, outbox, producer); err != nil {
			fatalf("rescan: %v", err)
		}
		fmt.Println("rescan: full-history obligation stream verified clean")
	case "repair":
		if *reason == "" {
			fatalf("repair requires -reason — an auditable operator justification, recorded durably")
		}
		if err := sender.OperatorRepair(ctx, *actor, *reason); err != nil {
			fatalf("repair: %v", err)
		}
		fmt.Println("repair: REPAIR_REQUIRED cleared after verified full rescan")
	default:
		fatalf("unknown operation %q", op)
	}
}

// reconcileShim runs the incremental scanner for a custodyctl-built
// sender — identical semantics to the service's wiring.
func reconcileShim(ctx context.Context, store idempotency.EffectStore, outbox *witness.Outbox, producer witness.Producer, hwm int64) error {
	return execution.ReconcileCustodyObligationsFrom(ctx, store, outbox, producer, hwm)
}
