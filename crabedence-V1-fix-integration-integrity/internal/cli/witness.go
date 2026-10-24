package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/openclaw/crabbox/internal/evidence"
	"github.com/openclaw/crabbox/internal/witness"
)

// witnessCommand implements `crabbox witness`: the separately
// administered evidence-custody service. It holds its own Ed25519
// signing key (CRABBOX_WITNESS_KEY or --key) and an append-only
// custody ledger, countersigns kernel terminal receipts with witness
// acknowledgements, and refuses replays, sequence gaps, foreign
// deployments, and forged receipts. The deployment binding is the
// kernel's evidence-signer fingerprint — pinned by --deployment-fp
// (recommended) or bound to the first deployment seen.
func (a App) witnessCommand(ctx context.Context, socket, storePath, keyPath, deploymentFP string) error {
	ledger, err := witness.OpenLedger(storePath)
	if err != nil {
		return fmt.Errorf("custody ledger: %w", err)
	}
	defer ledger.Close()
	signer, err := evidence.LoadOrCreateSigner(keyPath)
	if err != nil {
		return fmt.Errorf("witness signing key: %w", err)
	}
	if deploymentFP == "" {
		if bound, err := ledger.BoundDeployment(ctx); err != nil {
			return err
		} else if bound != "" {
			deploymentFP = bound
		}
	}
	fmt.Fprintf(os.Stderr, "Custody witness identity %s; deployment binding %s\n", signer.Fingerprint(), orElse(deploymentFP, "(first-seen)"))
	return witness.NewService(ledger, signer, deploymentFP, slog.New(slog.NewTextHandler(os.Stderr, nil))).Serve(ctx, socket)
}

func orElse(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
