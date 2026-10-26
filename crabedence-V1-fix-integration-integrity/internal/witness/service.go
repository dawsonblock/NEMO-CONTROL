package witness

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/openclaw/crabbox/internal/custody"
	"github.com/openclaw/crabbox/internal/evidence"
)

// Service is the custody witness: a separately administered process
// holding its own signing key and append-only ledger. It answers on a
// unix socket (local transport) or mutually authenticated TLS
// (separate-host custody) with framed JSON (4-byte BE length +
// payload).
//
// The service is pinned at construction to exactly one deployment
// identity — there is no trust-on-first-use: a witness with no
// deployment pin custodies nothing.
type Service struct {
	ledger       *Ledger
	deploymentID string
	kernelTrust  *custody.TrustSet
	log          *slog.Logger

	signer atomic.Value // *evidence.Signer — swapped by RotateSigner
}

// NewService wires the custody service. deploymentID is the mandatory
// deployment pin — only that deployment's submissions are accepted.
// kernelTrust is the pinned kernel-relay key set submissions must be
// signed under; an empty set fails closed — every submission is
// unverifiable.
func NewService(ledger *Ledger, signer *evidence.Signer, deploymentID string, kernelTrust *custody.TrustSet, log *slog.Logger) *Service {
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	s := &Service{ledger: ledger, deploymentID: deploymentID, kernelTrust: kernelTrust, log: log}
	s.signer.Store(signer)
	return s
}

// RotateSigner swaps the signing key after an authorized rotation and
// advances the signer epoch — acknowledgements then carry the new key
// identity, while records signed by the retired key remain valid only
// below the rotation point the trust file declares.
func (s *Service) RotateSigner(ctx context.Context, next *evidence.Signer) (int64, error) {
	epoch, err := s.ledger.AdvanceSignerEpoch(ctx)
	if err != nil {
		return 0, err
	}
	s.signer.Store(next)
	s.log.Info("witness signing key rotated", "signer_epoch", epoch, "key_id", next.Fingerprint())
	return epoch, nil
}

func (s *Service) currentSigner() *evidence.Signer {
	return s.signer.Load().(*evidence.Signer)
}

// Handle implements one request — shared by the socket loops and tests.
func (s *Service) Handle(ctx context.Context, req Request) Response {
	signer := s.currentSigner()
	switch req.Op {
	case OpCheckpoint:
		head, hash, execID, err := s.ledger.Head(ctx, s.deploymentID)
		if err != nil {
			return Response{Error: fmt.Sprintf("checkpoint: %v", err)}
		}
		epoch, err := s.ledger.SignerEpoch(ctx)
		if err != nil {
			return Response{Error: fmt.Sprintf("checkpoint: %v", err)}
		}
		h, err := SignCheckpoint(signer, s.deploymentID, &CheckpointHead{
			Seq: head, Hash: hash, LastExecutionID: execID, SignerEpoch: epoch,
		})
		if err != nil {
			return Response{Error: fmt.Sprintf("checkpoint: %v", err)}
		}
		return Response{OK: true, Head: h.Seq, HeadHash: h.Hash,
			LastExecutionID: h.LastExecutionID, SignerEpoch: h.SignerEpoch,
			CheckpointSig: h.Signature, WitnessFP: signer.Fingerprint()}
	case OpStatus:
		var n int64
		if s.deploymentID != "" {
			var err error
			if n, err = s.ledger.Records(ctx, s.deploymentID); err != nil {
				return Response{Error: fmt.Sprintf("status: %v", err)}
			}
		}
		epoch, _ := s.ledger.SignerEpoch(ctx)
		return Response{OK: true, WitnessFP: signer.Fingerprint(),
			DeploymentID: s.deploymentID, Records: n, SignerEpoch: epoch}
	case OpSubmit:
		ack, err := s.ledger.Submit(ctx, signer, req.Envelope, s.deploymentID, s.kernelTrust)
		if err != nil {
			s.log.Warn("witness submission refused", "deployment", req.DeploymentID, "error", err)
			return Response{Error: err.Error(), Code: refusalCode(err)}
		}
		return Response{OK: true, Ack: ack, WitnessFP: signer.Fingerprint()}
	case OpFenceBegin, OpFenceEnd, OpFenceAbort:
		return s.handleFence(ctx, signer, req.Fence)
	case OpFenceStatus:
		fence, err := s.ledger.ActiveFence(ctx, s.deploymentID)
		if err != nil {
			return Response{Error: fmt.Sprintf("fence status: %v", err)}
		}
		if fence == nil {
			return Response{OK: true, WitnessFP: signer.Fingerprint(), DeploymentID: s.deploymentID}
		}
		return Response{OK: true, Fence: fence.receipt(), WitnessFP: signer.Fingerprint()}
	default:
		return Response{Error: fmt.Sprintf("unknown op %q", req.Op)}
	}
}

// handleFence admits, closes, or aborts a migration epoch. The request
// must verify under the pinned kernel-relay set before it can touch
// the fence table — the witness does not take an unauthenticated
// kernel's word for it that a migration is under way.
func (s *Service) handleFence(ctx context.Context, signer *evidence.Signer, req *FenceRequest) Response {
	if err := VerifyFenceRequest(req, s.deploymentID, s.kernelTrust); err != nil {
		s.log.Warn("fence request refused", "op", req.Op, "error", err)
		return Response{Error: err.Error(), Code: CodeFenceState}
	}
	var (
		rec FenceRecord
		err error
	)
	switch req.Op {
	case OpFenceBegin:
		rec, err = s.ledger.OpenFence(ctx, req)
	case OpFenceEnd:
		rec, err = s.ledger.CloseFence(ctx, req)
	case OpFenceAbort:
		rec, err = s.ledger.AbortFence(ctx, req)
	}
	if err != nil {
		s.log.Warn("fence operation refused", "op", req.Op, "fence", req.FenceID, "error", err)
		return Response{Error: err.Error(), Code: refusalCode(err)}
	}
	epoch, err := s.ledger.SignerEpoch(ctx)
	if err != nil {
		return Response{Error: fmt.Sprintf("fence signer epoch: %v", err)}
	}
	receipt, err := SignFenceReceipt(signer, epoch, rec.receipt())
	if err != nil {
		return Response{Error: fmt.Sprintf("fence receipt: %v", err)}
	}
	s.log.Info("custody migration epoch transition", "op", req.Op, "fence", rec.FenceID,
		"epoch", rec.Epoch, "state", rec.State, "base_seq", rec.BaseSeq)
	return Response{OK: true, Fence: receipt, WitnessFP: signer.Fingerprint()}
}

// refusalCode maps a typed refusal onto a wire code so the kernel can
// tell "wait for the migration" from "escalate a contradiction".
func refusalCode(err error) string {
	switch {
	case errors.Is(err, ErrFenced):
		return CodeFenced
	case errors.Is(err, ErrFenceActive):
		return CodeFenceActive
	case errors.Is(err, ErrStaleFenceBase):
		return CodeStaleFence
	case errors.Is(err, ErrFenceState):
		return CodeFenceState
	case errors.Is(err, ErrContradiction):
		return CodeContradiction
	default:
		return ""
	}
}

// Serve listens on socketPath (local transport — the peer authenticates
// by filesystem ownership, so this form is for same-host custody only)
// and serves until ctx ends. The socket lands under a 0700 directory.
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
	return s.serve(ctx, ln)
}

// ServeTLS listens on addr with mutually authenticated TLS — the
// separate-host custody transport: the channel is encrypted and the
// client authenticates as a specific pinned kernel key. tlsCfg comes
// from ServerTLSConfig.
func (s *Service) ServeTLS(ctx context.Context, addr string, tlsCfg *tls.Config) error {
	ln, err := tls.Listen("tcp", addr, tlsCfg)
	if err != nil {
		return fmt.Errorf("witness tls listen: %w", err)
	}
	return s.serve(ctx, ln)
}

func (s *Service) serve(ctx context.Context, ln net.Listener) error {
	defer ln.Close()
	go func() { <-ctx.Done(); ln.Close() }()
	s.log.Info("evidence custody witness listening", "addr", ln.Addr().String(),
		"witness_fp", s.currentSigner().Fingerprint(), "deployment", s.deploymentID)
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
	payload, err := readFrame(conn)
	if err != nil {
		return
	}
	var req Request
	if err := json.Unmarshal(payload, &req); err != nil {
		writeResponse(conn, Response{Error: fmt.Sprintf("malformed request: %v", err)})
		return
	}
	writeResponse(conn, s.Handle(ctx, req))
}

// readFrame reads one 4-byte-BE-length-prefixed payload.
func readFrame(conn net.Conn) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > maxRequestBytes {
		return nil, fmt.Errorf("frame length %d out of bounds", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// writeFrame writes one 4-byte-BE-length-prefixed payload.
func writeFrame(conn net.Conn, payload []byte) error {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	if _, err := conn.Write(hdr[:]); err != nil {
		return err
	}
	_, err := conn.Write(payload)
	return err
}

func writeResponse(conn net.Conn, resp Response) {
	payload, err := json.Marshal(resp)
	if err != nil {
		return
	}
	_ = writeFrame(conn, payload)
}
