package execution

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/openclaw/crabbox/internal/releasectl"
)

// newControlGate builds the operator release-control admission check
// for the dispatch boundary. The trust root is loaded once at startup
// from the externally provisioned allowlist — never from event data.
// The returned closure re-opens the ledger on every consultation:
// control state is authoritative only as the folded chain on disk, so
// an operator's halt takes effect without a service restart and a
// kernel-compromised process cannot cache a stale "active" verdict.
//
// Fail-closed contract: any open/verify error denies admission.
//
// In production the ledger must already exist: it is provisioned by the
// operator through `crabbox control`, never minted here. Auto-creating
// an empty store would convert "ledger deleted" into "no restrictions
// recorded" at restart — the one path that could silently clear a halt.
// Development keeps the create-on-boot convenience.
func newControlGate(cfg ControlLedgerConfig, production bool) (func() error, error) {
	var roots releasectl.TrustRoots
	if cfg.TrustRootsPath != "" {
		r, err := releasectl.LoadTrustRoots(cfg.TrustRootsPath)
		if err != nil {
			return nil, fmt.Errorf("operator trust roots unavailable: %w", err)
		}
		roots = r
	} else {
		roots = releasectl.TrustRoots{}
	}
	verifier := releasectl.NewVerifier(roots, cfg.AllowUntrustedSigners)

	// The ledger must be usable at startup — an unreadable store is a
	// failed-closed condition for the deployment, not a boot-time
	// surprise after the first dispatch.
	if _, err := os.Stat(cfg.LedgerPath); err != nil {
		if os.IsNotExist(err) {
			if production {
				return nil, fmt.Errorf("control ledger %s missing — provision it with `crabbox control` before production startup", cfg.LedgerPath)
			}
			dir := filepath.Dir(cfg.LedgerPath)
			if mkErr := os.MkdirAll(dir, 0o700); mkErr != nil {
				return nil, fmt.Errorf("control ledger directory: %w", mkErr)
			}
			if f, cErr := os.OpenFile(cfg.LedgerPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600); cErr != nil {
				return nil, fmt.Errorf("control ledger create: %w", cErr)
			} else {
				f.Close()
			}
		} else {
			return nil, fmt.Errorf("control ledger unavailable: %w", err)
		}
	}
	if _, err := releasectl.Open(cfg.LedgerPath, cfg.CheckpointPath, verifier); err != nil {
		return nil, fmt.Errorf("control ledger fails integrity verification at startup: %w", err)
	}
	deployment := cfg.Deployment
	return func() error {
		l, err := releasectl.Open(cfg.LedgerPath, cfg.CheckpointPath, verifier)
		if err != nil {
			return err
		}
		return l.AdmitError(deployment)
	}, nil
}

// controlGateProbe wraps the admission check with a soft timeout so a
// wedged filesystem read degrades to denial rather than hanging the
// dispatch path forever.
//
// A blocking syscall cannot be cancelled, so a timed-out probe keeps
// running until the filesystem answers. Spawning one probe per
// admission would leak a goroutine for every dispatch while the store
// is wedged; instead concurrent admissions share a single in-flight
// probe — they would observe the same on-disk state anyway — each
// waiter enforces its own timeout, and the next admission after the
// probe completes gets a fresh read.
func controlGateProbe(check func() error, budget time.Duration) func() error {
	var mu sync.Mutex
	var done chan error
	return func() error {
		mu.Lock()
		if done == nil {
			done = make(chan error, 1)
			d := done
			go func() {
				err := check()
				// Release the slot before delivering the result: a
				// caller arriving in between must start a fresh probe,
				// never attach to a channel that receives nothing more.
				mu.Lock()
				done = nil
				mu.Unlock()
				d <- err
			}()
		}
		d := done
		mu.Unlock()
		select {
		case err := <-d:
			return err
		case <-time.After(budget):
			return fmt.Errorf("control ledger check exceeded %s — denied", budget)
		}
	}
}
