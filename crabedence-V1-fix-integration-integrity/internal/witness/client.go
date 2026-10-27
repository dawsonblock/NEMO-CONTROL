package witness

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/openclaw/crabbox/internal/custody"
)

// Client is the kernel-side handle to the custody witness. Exactly one
// of Socket (local transport) or TLSAddr (mutually authenticated
// separate-host transport) is set.
type Client struct {
	Socket    string
	TLSAddr   string
	TLSConfig *tls.Config
	Timeout   time.Duration
}

// NewClient targets the witness on a local unix socket.
func NewClient(socketPath string) *Client {
	return &Client{Socket: socketPath, Timeout: 5 * time.Second}
}

// NewTLSClient targets the witness over mutually authenticated TLS;
// tlsCfg comes from ClientTLSConfig.
func NewTLSClient(addr string, tlsCfg *tls.Config) *Client {
	return &Client{TLSAddr: addr, TLSConfig: tlsCfg, Timeout: 5 * time.Second}
}

func (c *Client) timeout() time.Duration {
	if c.Timeout <= 0 {
		return 5 * time.Second
	}
	return c.Timeout
}

func (c *Client) call(ctx context.Context, req Request) (Response, error) {
	var conn net.Conn
	var err error
	d := net.Dialer{Timeout: c.timeout()}
	switch {
	case c.TLSAddr != "":
		conn, err = tls.DialWithDialer(&d, "tcp", c.TLSAddr, c.TLSConfig)
	case c.Socket != "":
		conn, err = d.DialContext(ctx, "unix", c.Socket)
	default:
		return Response{}, fmt.Errorf("witness client has no transport configured")
	}
	if err != nil {
		return Response{}, fmt.Errorf("witness dial: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(c.timeout()))
	payload, err := json.Marshal(req)
	if err != nil {
		return Response{}, err
	}
	if err := writeFrame(conn, payload); err != nil {
		return Response{}, fmt.Errorf("witness write: %w", err)
	}
	buf, err := readFrame(conn)
	if err != nil {
		return Response{}, fmt.Errorf("witness read: %w", err)
	}
	var resp Response
	if err := json.Unmarshal(buf, &resp); err != nil {
		return Response{}, fmt.Errorf("witness response: %w", err)
	}
	return resp, nil
}

// Submit delivers one custody submission — the signed
// custody-envelope-v1 record carrying the native receipt bytes.
func (c *Client) Submit(ctx context.Context, deploymentID string, env *custody.Envelope) (*Ack, error) {
	resp, err := c.call(ctx, Request{Op: OpSubmit, DeploymentID: deploymentID, Envelope: env})
	if err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, refusal(fmt.Errorf("witness submit refused: %s", resp.Error), resp.Code)
	}
	return resp.Ack, nil
}

// refusal attaches the witness's typed refusal to the transport error,
// so a caller can tell a fence (wait) from a contradiction (escalate).
func refusal(err error, code string) error {
	switch code {
	case CodeFenced:
		return fmt.Errorf("%w: %v", ErrFenced, err)
	case CodeFenceActive:
		return fmt.Errorf("%w: %v", ErrFenceActive, err)
	case CodeStaleFence:
		return fmt.Errorf("%w: %v", ErrStaleFenceBase, err)
	case CodeFenceState:
		return fmt.Errorf("%w: %v", ErrFenceState, err)
	case CodeContradiction:
		return fmt.Errorf("%w: %v", ErrContradiction, err)
	case CodePermitMissing:
		return fmt.Errorf("%w: %v", ErrPermitMissing, err)
	case CodePermitUsed:
		return fmt.Errorf("%w: %v", ErrPermitConsumed, err)
	case CodeOutcomeUnknown:
		return fmt.Errorf("%w: %v", ErrMigrationOutcomeUnknown, err)
	case CodeRecoveryNeeded:
		return fmt.Errorf("%w: %v", ErrFenceRecoveryRequired, err)
	case CodeWrongTerminal:
		return fmt.Errorf("%w: %v", ErrWrongTerminalReceipt, err)
	default:
		return err
	}
}

// Checkpoint returns the witness's signed custody head. The signature
// is NOT verified here — VerifyCheckpoint is the caller's obligation at
// the recording boundary.
func (c *Client) Checkpoint(ctx context.Context, deploymentID string) (*CheckpointHead, error) {
	resp, err := c.call(ctx, Request{Op: OpCheckpoint, DeploymentID: deploymentID})
	if err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, fmt.Errorf("witness checkpoint refused: %s", resp.Error)
	}
	return &CheckpointHead{
		Seq:             resp.Head,
		Hash:            resp.HeadHash,
		LastExecutionID: resp.LastExecutionID,
		SignerEpoch:     resp.SignerEpoch,
		WitnessFP:       resp.WitnessFP,
		Signature:       resp.CheckpointSig,
	}, nil
}

// BeginFence asks the witness to freeze the deployment at the head
// named in the (already signed) request. The returned receipt is NOT
// verified here — VerifyFenceReceipt is the boundary's obligation.
func (c *Client) BeginFence(ctx context.Context, req *FenceRequest) (*FenceReceipt, error) {
	return c.fenceCall(ctx, OpFenceBegin, req)
}

// EndFence closes a migration epoch with its result digest.
func (c *Client) EndFence(ctx context.Context, req *FenceRequest) (*FenceReceipt, error) {
	return c.fenceCall(ctx, req.Op, req)
}

// PrepareFence asks the witness to admit one migration transaction.
// The returned permit is NOT verified here — VerifyFencePermit is the
// boundary's obligation.
func (c *Client) PrepareFence(ctx context.Context, req *PrepareRequest) (*FencePermit, error) {
	resp, err := c.call(ctx, Request{Op: OpFencePrepare, DeploymentID: req.DeploymentID, Prepare: req})
	if err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, refusal(fmt.Errorf("witness %s refused: %s", OpFencePrepare, resp.Error), resp.Code)
	}
	if resp.Permit == nil {
		return nil, fmt.Errorf("witness %s returned no signed permit", OpFencePrepare)
	}
	return resp.Permit, nil
}

// FinalizeFence reports one transaction's committed local outcome.
func (c *Client) FinalizeFence(ctx context.Context, req *FinalizeRequest) (*FenceResult, error) {
	resp, err := c.call(ctx, Request{Op: OpFenceFinalize, DeploymentID: req.DeploymentID, Finalize: req})
	if err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, refusal(fmt.Errorf("witness %s refused: %s", OpFenceFinalize, resp.Error), resp.Code)
	}
	if resp.Result == nil {
		return nil, fmt.Errorf("witness %s returned no signed result", OpFenceFinalize)
	}
	return resp.Result, nil
}

// AbortMigrationFence asks the witness to release one admitted
// transaction that never committed locally.
func (c *Client) AbortMigrationFence(ctx context.Context, req *FinalizeRequest) (*FenceReceipt, error) {
	resp, err := c.call(ctx, Request{Op: OpFenceAbortTx, DeploymentID: req.DeploymentID, Finalize: req})
	if err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, refusal(fmt.Errorf("witness %s refused: %s", OpFenceAbortTx, resp.Error), resp.Code)
	}
	if resp.Fence == nil {
		return nil, fmt.Errorf("witness %s returned no signed receipt", OpFenceAbortTx)
	}
	return resp.Fence, nil
}

func (c *Client) fenceCall(ctx context.Context, op string, req *FenceRequest) (*FenceReceipt, error) {
	if req == nil {
		return nil, fmt.Errorf("witness %s: no fence request", op)
	}
	req.Op = op
	resp, err := c.call(ctx, Request{Op: op, DeploymentID: req.DeploymentID, Fence: req})
	if err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, refusal(fmt.Errorf("witness %s refused: %s", op, resp.Error), resp.Code)
	}
	if resp.Fence == nil {
		return nil, fmt.Errorf("witness %s returned no signed fence receipt", op)
	}
	return resp.Fence, nil
}
