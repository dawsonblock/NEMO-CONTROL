// witnessd is the independent evidence-custody service for the receipt
// family (ADR-0003, custody-envelope-v1). It is separately administered
// from the execution kernel: it holds its own Ed25519 signing key, an
// append-only per-deployment custody log, and refuses replays,
// sequence gaps, contradictory checkpoints, foreign deployments, and
// envelopes that do not verify under the pinned kernel-relay keys.
//
// Transports — exactly one:
//
//	-socket <path>      local unix socket (same-host custody only; the
//	                    peer authenticates by filesystem ownership)
//	-listen <addr>      mutually authenticated TLS (separate-host
//	                    custody; -client-fp pins the kernel's key)
//
// Flags:
//
//	-store <path>       custody ledger (sqlite), append-only
//	-key <path>         witness signer PKCS8 PEM, created if absent
//	-deployment <id>    the only deployment identity this witness
//	                    custodies (required — no trust-on-first-use)
//	-kernel-trust <f>   kernel-relay trust set file (custody trust
//	                    format) — submissions must be signed under it
//	-client-fp <fp>     with -listen: the kernel-relay key fingerprint
//	                    the TLS client must present
//	-status             print custody status and exit (no daemon)
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/openclaw/crabbox/internal/custody"
	"github.com/openclaw/crabbox/internal/evidence"
	"github.com/openclaw/crabbox/internal/witness"
)

func main() {
	socket := flag.String("socket", os.Getenv("WITNESS_SOCKET"), "unix socket path for local custody (or WITNESS_SOCKET)")
	listen := flag.String("listen", os.Getenv("WITNESS_LISTEN"), "TCP addr for mTLS separate-host custody (or WITNESS_LISTEN)")
	clientFP := flag.String("client-fp", os.Getenv("WITNESS_CLIENT_FP"), "pinned kernel key fingerprint for -listen (or WITNESS_CLIENT_FP)")
	store := flag.String("store", os.Getenv("WITNESS_STORE"), "custody ledger path (or WITNESS_STORE)")
	keyPath := flag.String("key", os.Getenv("WITNESS_KEY"), "witness signer PKCS8 PEM path (or WITNESS_KEY)")
	deployment := flag.String("deployment", os.Getenv("WITNESS_DEPLOYMENT"), "the only deployment identity this witness custodies (or WITNESS_DEPLOYMENT)")
	kernelTrust := flag.String("kernel-trust", os.Getenv("WITNESS_KERNEL_TRUST"), "kernel-relay trust set file (or WITNESS_KERNEL_TRUST)")
	status := flag.Bool("status", false, "print custody status and exit instead of running the daemon")
	flag.Parse()

	if *store == "" {
		log.Fatalf("witnessd: -store is required")
	}
	if *deployment == "" {
		log.Fatalf("witnessd: -deployment is required — a witness with no deployment pin custodies nothing")
	}
	if *socket != "" && *listen != "" {
		log.Fatalf("witnessd: configure exactly one transport: -socket (local) xor -listen (separate-host mTLS)")
	}
	if *socket == "" && *listen == "" && !*status {
		log.Fatalf("witnessd: a transport is required (-socket or -listen)")
	}

	ledger, err := witness.OpenLedger(*store)
	if err != nil {
		log.Fatalf("witnessd: %v", err)
	}
	defer ledger.Close()

	if *status {
		ctx := context.Background()
		head, hash, execID, err := ledger.Head(ctx, *deployment)
		if err != nil {
			log.Fatalf("witnessd: %v", err)
		}
		n, err := ledger.Records(ctx, *deployment)
		if err != nil {
			log.Fatalf("witnessd: %v", err)
		}
		epoch, _ := ledger.SignerEpoch(ctx)
		fmt.Printf("deployment=%s records=%d head=%d head_hash=%s last_execution=%s signer_epoch=%d\n",
			*deployment, n, head, hash, execID, epoch)
		return
	}

	signer, err := evidence.LoadOrCreateSigner(*keyPath)
	if err != nil {
		log.Fatalf("witnessd: witness signing key: %v", err)
	}
	trust, err := custody.LoadTrustSet(*kernelTrust)
	if err != nil {
		log.Fatalf("witnessd: kernel trust set: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	svc := witness.NewService(ledger, signer, *deployment, trust, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sig := make(chan os.Signal, 2)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-sig; cancel() }()

	fmt.Fprintf(os.Stderr, "witnessd identity %s; deployment %s\n", signer.Fingerprint(), *deployment)
	switch {
	case *listen != "":
		if *clientFP == "" {
			log.Fatalf("witnessd: -listen requires -client-fp — an unauthenticated separate-host custody peer is not custody")
		}
		tlsCfg, err := witness.ServerTLSConfig(signer, *clientFP)
		if err != nil {
			log.Fatalf("witnessd: %v", err)
		}
		fmt.Fprintf(os.Stderr, "witnessd listening on tls://%s (client pinned to %s)\n", *listen, *clientFP)
		if err := svc.ServeTLS(ctx, *listen, tlsCfg); err != nil {
			log.Fatalf("witnessd: %v", err)
		}
	default:
		sock := *socket
		if dir := filepath.Dir(sock); dir != "." {
			if st, err := os.Stat(dir); err == nil && st.Mode().Perm()&0o077 != 0 {
				log.Fatalf("witnessd: socket directory %s is group/world accessible — local custody transport must be owner-only", dir)
			}
		}
		fmt.Fprintf(os.Stderr, "witnessd listening on unix://%s (local transport — same-host custody only)\n", sock)
		if err := svc.Serve(ctx, sock); err != nil {
			log.Fatalf("witnessd: %v", err)
		}
	}
}
