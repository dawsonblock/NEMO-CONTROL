package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/openclaw/crabbox/internal/evidence"
	"github.com/openclaw/crabbox/internal/releasectl"
)

// controlFlags are the shared operator-control flags. The trust-roots
// file is the externally provisioned signer allowlist — the CLI never
// treats an event's embedded key as a trust source.
type controlFlags struct {
	Ledger      string `name:"ledger" required:"" help:"Append-only control ledger path."`
	Checkpoint  string `name:"checkpoint" help:"Monotonic checkpoint path (default <ledger>.checkpoint)."`
	TrustRoots  string `name:"trust-roots" required:"" help:"Operator signer allowlist file (fingerprints, one per line)."`
	Deployment  string `name:"deployment" required:"" help:"Deployment identity the event binds."`
	Reason      string `name:"reason" required:"" help:"Operator-attested reason for the transition."`
	Release     string `name:"release" help:"Release/artifact digest (64 hex)."`
	Policy      string `name:"policy" help:"Policy digest (64 hex)."`
	Epoch       uint64 `name:"epoch" help:"Trust-root epoch (default: ledger maximum)."`
	Key         string `name:"key" help:"Operator private key PEM (required for resume/unrevoke/stage/stage-clear; optional for halt/revoke)."`
	BreakGlass  bool   `name:"break-glass" help:"Sign with the breakglass signer role."`
	DevUnsigned bool   `name:"dev-unsigned" help:"Development only: permit unsigned relaxations."`
}

func (f controlFlags) checkpoint() string {
	if f.Checkpoint != "" {
		return f.Checkpoint
	}
	return f.Ledger + ".checkpoint"
}

func (f controlFlags) verifier() (*releasectl.Verifier, error) {
	roots, err := releasectl.LoadTrustRoots(f.TrustRoots)
	if err != nil {
		return nil, fmt.Errorf("trust roots: %w", err)
	}
	return releasectl.NewVerifier(roots, f.DevUnsigned), nil
}

// controlTransition appends one control event. kind is fixed by the
// subcommand — the CLI cannot be tricked into recording a different
// transition than the operator asked for.
func (a App) controlTransition(ctx context.Context, kind string, f controlFlags, stage int, evidenceRefs []string) error {
	_ = ctx
	v, err := f.verifier()
	if err != nil {
		return err
	}
	l, err := releasectl.Create(f.Ledger, f.checkpoint(), v)
	if err != nil {
		return fmt.Errorf("control ledger: %w", err)
	}
	e := l.NewEvent(kind, f.Deployment, f.Reason)
	e.ReleaseDigest = f.Release
	e.PolicyDigest = f.Policy
	if f.Epoch > 0 {
		e.Epoch = f.Epoch
	}
	e.Stage = stage
	e.EvidenceRefs = evidenceRefs
	if f.BreakGlass {
		e.SignerRole = releasectl.RoleBreakGlass
	}
	if f.Key != "" {
		keyData, err := os.ReadFile(f.Key)
		if err != nil {
			return fmt.Errorf("operator key: %w", err)
		}
		signer, err := evidence.ParseSignerPEM(keyData)
		if err != nil {
			return fmt.Errorf("operator key: %w", err)
		}
		if err := releasectl.SignEvent(signer, &e); err != nil {
			return err
		}
	}
	if err := l.Append(e); err != nil {
		return err
	}
	st := l.State(f.Deployment)
	fmt.Fprintf(a.Stdout, "recorded %s event %s (seq %d)\n", kind, e.EventID, e.Sequence)
	fmt.Fprintf(a.Stdout, "deployment %s: halted=%v revoked=%v stage=%d pending-relaxations=%d\n",
		f.Deployment, st.Halted, st.Revoked, st.StageLevel, st.PendingRelaxations)
	return nil
}

// controlStatus folds the ledger and reports the effective state.
func (a App) controlStatus(_ context.Context, f controlStatusFlags) error {
	v, err := f.verifier()
	if err != nil {
		return err
	}
	l, err := releasectl.Open(f.Ledger, f.checkpoint(), v)
	if err != nil {
		return fmt.Errorf("control ledger fails verification: %w", err)
	}
	fmt.Fprintf(a.Stdout, "ledger: %d records, max epoch %d, %d trusted operator roots\n",
		l.Len(), l.MaxEpoch(), v.RootCount())
	deps := []string{f.Deployment}
	if f.Deployment == "" {
		deps = l.Deployments()
	}
	if len(deps) == 0 {
		fmt.Fprintln(a.Stdout, "no control state recorded")
		return nil
	}
	for _, dep := range deps {
		st := l.State(dep)
		fmt.Fprintf(a.Stdout, "deployment %s: halted=%v revoked=%v stage=%d staged-release=%s pending-relaxations=%d admit=%v\n",
			dep, st.Halted, st.Revoked, st.StageLevel, st.StagedRelease,
			st.PendingRelaxations, l.AdmitError(dep) == nil)
	}
	return nil
}

type controlStatusFlags struct {
	Ledger     string `name:"ledger" required:"" help:"Append-only control ledger path."`
	Checkpoint string `name:"checkpoint" help:"Monotonic checkpoint path (default <ledger>.checkpoint)."`
	TrustRoots string `name:"trust-roots" required:"" help:"Operator signer allowlist file."`
	Deployment string `name:"deployment" help:"Report one deployment (default: all recorded)."`
}

func (f controlStatusFlags) checkpoint() string {
	if f.Checkpoint != "" {
		return f.Checkpoint
	}
	return f.Ledger + ".checkpoint"
}

func (f controlStatusFlags) verifier() (*releasectl.Verifier, error) {
	roots, err := releasectl.LoadTrustRoots(f.TrustRoots)
	if err != nil {
		return nil, fmt.Errorf("trust roots: %w", err)
	}
	return releasectl.NewVerifier(roots, false), nil
}
