package witness

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"time"
)

// Client is the kernel-side handle to the custody witness.
type Client struct {
	socketPath string
	timeout    time.Duration
}

// NewClient targets the witness at socketPath.
func NewClient(socketPath string) *Client {
	return &Client{socketPath: socketPath, timeout: 5 * time.Second}
}

func (c *Client) call(ctx context.Context, req Request) (Response, error) {
	d := net.Dialer{Timeout: c.timeout}
	conn, err := d.DialContext(ctx, "unix", c.socketPath)
	if err != nil {
		return Response{}, fmt.Errorf("witness dial: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(c.timeout))
	payload, err := json.Marshal(req)
	if err != nil {
		return Response{}, err
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	if _, err := conn.Write(hdr[:]); err != nil {
		return Response{}, fmt.Errorf("witness write: %w", err)
	}
	if _, err := conn.Write(payload); err != nil {
		return Response{}, fmt.Errorf("witness write: %w", err)
	}
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return Response{}, fmt.Errorf("witness read: %w", err)
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > maxRequestBytes {
		return Response{}, fmt.Errorf("witness response length %d out of bounds", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return Response{}, fmt.Errorf("witness read: %w", err)
	}
	var resp Response
	if err := json.Unmarshal(buf, &resp); err != nil {
		return Response{}, fmt.Errorf("witness response: %w", err)
	}
	return resp, nil
}

// Submit delivers one custody submission.
func (c *Client) Submit(ctx context.Context, req Request) (*Ack, error) {
	req.Op = OpSubmit
	resp, err := c.call(ctx, req)
	if err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, fmt.Errorf("witness submit refused: %s", resp.Error)
	}
	return resp.Ack, nil
}

// Checkpoint returns the witness's custody head for a deployment.
func (c *Client) Checkpoint(ctx context.Context, deploymentFP string) (seq int64, executionID, digest string, err error) {
	resp, err := c.call(ctx, Request{Op: OpCheckpoint, DeploymentFP: deploymentFP})
	if err != nil {
		return 0, "", "", err
	}
	if !resp.OK {
		return 0, "", "", fmt.Errorf("witness checkpoint refused: %s", resp.Error)
	}
	return resp.Head, resp.LastExecutionID, resp.LastReceiptDigest, nil
}
