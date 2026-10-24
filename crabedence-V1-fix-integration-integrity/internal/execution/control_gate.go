package execution

import (
	"fmt"
	"os"
	"path/filepath"
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
func newControlGate(cfg ControlLedgerConfig) (func() error, error) {
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
	verifier := releasectl.NewVerifier(roots, cfg.AllowUnverified)

	// The ledger must be usable at startup — an unreadable store is a
	// failed-closed condition for the deployment, not a boot-time
	// surprise after the first dispatch.
	if _, err := os.Stat(cfg.LedgerPath); err != nil {
		if os.IsNotExist(err) {
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
func controlGateProbe(check func() error, budget time.Duration) func() error {
	return func() error {
		done := make(chan error, 1)
		go func() { done <- check() }()
		select {
		case err := <-done:
			return err
		case <-time.After(budget):
			return fmt.Errorf("control ledger check exceeded %s — denied", budget)
		}
	}
}
