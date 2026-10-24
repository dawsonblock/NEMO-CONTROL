package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"

	"github.com/openclaw/crabbox/internal/evidence"
	"github.com/openclaw/crabbox/internal/releasectl"
)

// The operator control surface: emergency halt, resume, per-release
// revocation, and status for a running execution service. Records are
// signed by the operator key — the kernel cannot mint its own halt
// waiver — and the service enforces them at every admission, failing
// closed on anything malformed or untrusted.

type controlKongCmd struct {
	Halt     controlHaltCmd     `cmd:"" name:"halt" help:"Halt a running deployment — every new admission is denied until resume."`
	Resume   controlResumeCmd   `cmd:"" name:"resume" help:"Clear a deployment halt."`
	Revoke   controlRevokeCmd   `cmd:"" name:"revoke" help:"Revoke a release — deployments bound to that identity deny all new work."`
	Unrevoke controlUnrevokeCmd `cmd:"" name:"unrevoke" help:"Clear a release revocation."`
	Stage    controlStageCmd    `cmd:"" name:"stage" help:"Record a signed rollout stage (canary|majority|full) for a release."`
	Unstage  controlUnstageCmd  `cmd:"" name:"unstage" help:"Clear a release's rollout-stage record."`
	Status   controlStatusCmd   `cmd:"" name:"status" help:"Show the control state of a running deployment."`
}

type controlHaltCmd struct {
	Socket  string `help:"Execution service socket — locates the control directory." required:""`
	Reason  string `help:"Why the deployment is being halted (recorded, signed)." required:""`
	Revoker string `help:"Operator identity recorded on the record." required:""`
	Key     string `help:"Operator Ed25519 key (PEM); default $CRABEDENCE_OPERATOR_KEY or ~/.config/crabbox/operator."`
}

type controlResumeCmd struct {
	Socket string `help:"Execution service socket." required:""`
}

type controlRevokeCmd struct {
	Socket  string `help:"Execution service socket." required:""`
	Release string `help:"Release identity to revoke (must match the service's declared release)." required:""`
	Reason  string `help:"Why the release is revoked." required:""`
	Revoker string `help:"Operator identity recorded on the record." required:""`
	Key     string `help:"Operator Ed25519 key (PEM); default $CRABEDENCE_OPERATOR_KEY or ~/.config/crabbox/operator."`
}

type controlUnrevokeCmd struct {
	Socket  string `help:"Execution service socket." required:""`
	Release string `help:"Release identity to unrevoke." required:""`
}

type controlStageCmd struct {
	Socket  string `help:"Execution service socket." required:""`
	Release string `help:"Release identity being promoted." required:""`
	Stage   string `help:"Rollout stage: canary, majority, or full." required:""`
	Reason  string `help:"Why the promotion is being recorded." required:""`
	Revoker string `help:"Operator identity recorded on the record." required:""`
	Key     string `help:"Operator Ed25519 key (PEM); default $CRABEDENCE_OPERATOR_KEY or ~/.config/crabbox/operator."`
}

type controlUnstageCmd struct {
	Socket  string `help:"Execution service socket." required:""`
	Release string `help:"Release identity to unstage." required:""`
}

type controlStatusCmd struct {
	Socket string `help:"Execution service socket." required:""`
}

func operatorSigner(path string) (*evidence.Signer, error) {
	if path == "" {
		path = os.Getenv("CRABEDENCE_OPERATOR_KEY")
	}
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		path = filepath.Join(home, ".config", "crabbox", "operator", "key.pem")
	}
	return evidence.LoadOrCreateSigner(path)
}

func (c *controlHaltCmd) Run(ctx context.Context, app App) error {
	signer, err := operatorSigner(c.Key)
	if err != nil {
		return err
	}
	rec, err := releasectl.Issue(signer, releasectl.ActionHalt, "", "", c.Reason, c.Revoker)
	if err != nil {
		return err
	}
	if err := releasectl.Halt(releasectl.Dir(c.Socket), rec); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "deployment halted: %s (signer %s)\n", c.Reason, rec.Signer)
	return nil
}

func (c *controlResumeCmd) Run(ctx context.Context, app App) error {
	if err := releasectl.Resume(releasectl.Dir(c.Socket)); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "halt cleared")
	return nil
}

func (c *controlRevokeCmd) Run(ctx context.Context, app App) error {
	signer, err := operatorSigner(c.Key)
	if err != nil {
		return err
	}
	rec, err := releasectl.Issue(signer, releasectl.ActionRevoke, c.Release, "", c.Reason, c.Revoker)
	if err != nil {
		return err
	}
	if err := releasectl.Revoke(releasectl.Dir(c.Socket), c.Release, rec); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "release %s revoked: %s (signer %s)\n", c.Release, c.Reason, rec.Signer)
	return nil
}

func (c *controlUnrevokeCmd) Run(ctx context.Context, app App) error {
	if err := releasectl.Unrevoke(releasectl.Dir(c.Socket), c.Release); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "revocation cleared for %s\n", c.Release)
	return nil
}

func (c *controlStageCmd) Run(ctx context.Context, app App) error {
	signer, err := operatorSigner(c.Key)
	if err != nil {
		return err
	}
	rec, err := releasectl.Issue(signer, releasectl.ActionStage, c.Release, c.Stage, c.Reason, c.Revoker)
	if err != nil {
		return err
	}
	if err := releasectl.SetStage(releasectl.Dir(c.Socket), c.Release, rec); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "release %s staged at %s: %s (signer %s)\n", c.Release, c.Stage, c.Reason, rec.Signer)
	return nil
}

func (c *controlUnstageCmd) Run(ctx context.Context, app App) error {
	if err := releasectl.ClearStage(releasectl.Dir(c.Socket), c.Release); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "rollout stage cleared for %s\n", c.Release)
	return nil
}

func (c *controlStatusCmd) Run(ctx context.Context, app App) error {
	dir := releasectl.Dir(c.Socket)
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	if r, err := releasectl.Load(releasectl.HaltPath(dir)); err != nil {
		return err
	} else if r != nil {
		fmt.Fprintf(w, "halt\t%s\t%s\t%s\n", r.Revoker, r.At, r.Reason)
	} else {
		fmt.Fprintln(w, "halt\t(none)")
	}
	revokedDir := filepath.Join(dir, "revoked")
	entries, err := os.ReadDir(revokedDir)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	count := 0
	for _, e := range entries {
		r, err := releasectl.Load(filepath.Join(revokedDir, e.Name()))
		if err != nil || r == nil {
			continue
		}
		count++
		fmt.Fprintf(w, "revoked\t%s\t%s\t%s\t%s\n", r.Release, r.Revoker, r.At, r.Reason)
	}
	if count == 0 {
		fmt.Fprintln(w, "revoked\t(none)")
	}
	stagedDir := filepath.Join(dir, "staged")
	entries, err = os.ReadDir(stagedDir)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	count = 0
	for _, e := range entries {
		r, err := releasectl.Load(filepath.Join(stagedDir, e.Name()))
		if err != nil || r == nil {
			continue
		}
		count++
		fmt.Fprintf(w, "staged\t%s\t%s\t%s\t%s\t%s\n", r.Release, r.Stage, r.Revoker, r.At, r.Reason)
	}
	if count == 0 {
		fmt.Fprintln(w, "staged\t(none)")
	}
	return w.Flush()
}
