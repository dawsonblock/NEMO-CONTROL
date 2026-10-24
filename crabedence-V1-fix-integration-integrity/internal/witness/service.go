package witness

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/openclaw/crabbox/internal/evidence"
)

// maxRequestBytes bounds one framed request — submissions carry at most
// a signed receipt (~64KiB); a generous cap with headroom.
const maxRequestBytes = 4 * 1024 * 1024

// Service is the custody witness: a separately administered process
// holding its own signing key and append-only ledger. It answers on a
// unix socket with framed JSON (4-byte BE length + payload).
type Service struct {
	ledger   *Ledger
	signer   *evidence.Signer
	pinnedFP string // CRABEDENCE_WITNESS_DEPLOYMENT_FP pin ("" = TOFU)
	log      *slog.Logger
}

// NewService wires the custody service over an existing ledger and the
// witness's own signer. pinnedFP is the optional deployment binding:
// when set, only that deployment's submissions are accepted; when
// empty the first deployment to submit is bound (TOFU) and persisted.
func NewService(ledger *Ledger, signer *evidence.Signer, pinnedFP string, log *slog.Logger) *Service {
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Service{ledger: ledger, signer: signer, pinnedFP: pinnedFP, log: log}
}

// Handle implements one request — shared by the socket loop and tests.
func (s *Service) Handle(ctx context.Context, req Request) Response {
	switch req.Op {
	case OpCheckpoint:
		head, execID, digest, err := s.ledger.Head(ctx, req.DeploymentFP)
		if err != nil {
			return Response{Error: fmt.Sprintf("checkpoint: %v", err)}
		}
		return Response{OK: true, Head: head, LastExecutionID: execID, LastReceiptDigest: digest, WitnessFP: s.signer.Fingerprint()}
	case OpStatus:
		bound, err := s.ledger.BoundDeployment(ctx)
		if err != nil {
			return Response{Error: fmt.Sprintf("status: %v", err)}
		}
		fp := req.DeploymentFP
		if fp == "" {
			fp = bound
		}
		var n int64
		if fp != "" {
			if n, err = s.ledger.Records(ctx, fp); err != nil {
				return Response{Error: fmt.Sprintf("status: %v", err)}
			}
		}
		return Response{OK: true, WitnessFP: s.signer.Fingerprint(), DeploymentFP: fp, Records: n}
	case OpSubmit:
		if req.DeploymentFP == "" || req.Seq < 1 || req.ExecutionID == "" || req.ReceiptDigest == "" {
			return Response{Error: "submit requires deployment_fp, seq >= 1, execution_id, receipt_digest"}
		}
		ack, err := s.ledger.Submit(ctx, s.signer, req, s.pinnedFP)
		if err != nil {
			s.log.Warn("witness submission refused", "deployment", req.DeploymentFP, "seq", req.Seq, "execution", req.ExecutionID, "error", err)
			return Response{Error: err.Error()}
		}
		return Response{OK: true, Ack: ack, WitnessFP: s.signer.Fingerprint()}
	default:
		return Response{Error: fmt.Sprintf("unknown op %q", req.Op)}
	}
}

// Serve listens on socketPath and serves until ctx ends. The socket
// lands under a 0700 directory so only the owning account can reach it.
func (s *Service) Serve(ctx context.Context, socketPath string) error {
	dir := filepath.Dir(socketPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	_ = os.Remove(socketPath)
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("witness listen: %w", err)
	}
	defer ln.Close()
	go func() { <-ctx.Done(); ln.Close() }()
	s.log.Info("evidence custody witness listening", "socket", socketPath, "witness_fp", s.signer.Fingerprint())
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.serveConn(ctx, conn)
	}
}

func (s *Service) serveConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > maxRequestBytes {
		return
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return
	}
	var req Request
	if err := json.Unmarshal(payload, &req); err != nil {
		writeResponse(conn, Response{Error: fmt.Sprintf("malformed request: %v", err)})
		return
	}
	writeResponse(conn, s.Handle(ctx, req))
}

func writeResponse(conn net.Conn, resp Response) {
	payload, err := json.Marshal(resp)
	if err != nil {
		return
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	_, _ = conn.Write(hdr[:])
	_, _ = conn.Write(payload)
}
