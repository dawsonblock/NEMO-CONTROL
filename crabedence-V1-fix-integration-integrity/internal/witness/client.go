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
		return nil, fmt.Errorf("witness submit refused: %s", resp.Error)
	}
	return resp.Ack, nil
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
