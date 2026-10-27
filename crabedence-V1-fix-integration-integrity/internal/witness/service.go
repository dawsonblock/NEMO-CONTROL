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
	"sync"
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

	// state holds one immutable *signerState. The signing key and the
	// signer epoch are a single logical value: a request must never
	// sign with one key and be numbered with another key's epoch, which
	// is what two independent reads produced in RC8.3.
	state atomic.Value // *signerState
	// rotMu serializes rotations so two of them cannot both read the
	// same durable epoch.
	rotMu sync.Mutex
}

// signerState is the atomic signing identity of the witness.
type signerState struct {
	signer *evidence.Signer
	epoch  int64
	err    error
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
	// The durable epoch is the authority on restart. A witness that
	// cannot read it must not issue anything: a guessed epoch is a
	// durable lie in every record it signs.
	epoch, err := ledger.SignerEpoch(context.Background())
	s.state.Store(&signerState{signer: signer, epoch: epoch, err: err})
	return s
}

// snapshot returns the single signing identity for one issuance.
func (s *Service) snapshot() (*signerState, error) {
	st, _ := s.state.Load().(*signerState)
	if st == nil {
		return nil, fmt.Errorf("witness: signer state is uninitialized")
	}
	if st.err != nil {
		return nil, fmt.Errorf("witness: signer epoch is unreadable: %w", st.err)
	}
	if st.signer == nil {
		return nil, fmt.Errorf("witness: no signing key")
	}
	return st, nil
}

// RotateSigner swaps the signing key after an authorized rotation and
// advances the signer epoch — acknowledgements then carry the new key
// identity, while records signed by the retired key remain valid only
// below the rotation point the trust file declares.
func (s *Service) RotateSigner(ctx context.Context, next *evidence.Signer) (int64, error) {
	s.rotMu.Lock()
	defer s.rotMu.Unlock()
	epoch, err := s.ledger.AdvanceSignerEpoch(ctx)
	if err != nil {
		return 0, err
	}
	s.state.Store(&signerState{signer: next, epoch: epoch})
	s.log.Info("witness signing key rotated", "signer_epoch", epoch, "key_id", next.Fingerprint())
	return epoch, nil
}

func (s *Service) currentSigner() *evidence.Signer {
	if st, err := s.snapshot(); err == nil {
		return st.signer
	}
	return nil
}

// Handle implements one request — shared by the socket loops and tests.
func (s *Service) Handle(ctx context.Context, req Request) Response {
	st, err := s.snapshot()
	if err != nil {
		return Response{Error: err.Error()}
	}
	signer, signerEpoch := st.signer, st.epoch
	switch req.Op {
	case OpCheckpoint:
		head, hash, execID, err := s.ledger.Head(ctx, s.deploymentID)
		if err != nil {
			return Response{Error: fmt.Sprintf("checkpoint: %v", err)}
		}
		h, err := SignCheckpoint(signer, s.deploymentID, &CheckpointHead{
			Seq: head, Hash: hash, LastExecutionID: execID, SignerEpoch: signerEpoch,
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
		return Response{OK: true, WitnessFP: signer.Fingerprint(),
			DeploymentID: s.deploymentID, Records: n, SignerEpoch: signerEpoch}
	case OpSubmit:
		ack, err := s.ledger.Submit(ctx, signer, signerEpoch, req.Envelope, s.deploymentID, s.kernelTrust)
		if err != nil {
			s.log.Warn("witness submission refused", "deployment", req.DeploymentID, "error", err)
			return Response{Error: err.Error(), Code: refusalCode(err)}
		}
		return Response{OK: true, Ack: ack, WitnessFP: signer.Fingerprint()}
	case OpFenceBegin, OpFenceEnd, OpFenceAbort:
		return s.handleFence(ctx, signer, signerEpoch, req.Fence)
	case OpFencePrepare:
		return s.handlePrepare(ctx, signer, signerEpoch, req.Prepare)
	case OpFenceFinalize:
		return s.handleFinalize(ctx, signer, signerEpoch, req.Finalize)
	case OpFenceAbortTx:
		return s.handleAbortTx(ctx, signer, signerEpoch, req.Finalize)
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
func (s *Service) handleFence(ctx context.Context, signer *evidence.Signer, signerEpoch int64, req *FenceRequest) Response {
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
	receipt, err := SignFenceReceipt(signer, signerEpoch, rec.receipt())
	if err != nil {
		return Response{Error: fmt.Sprintf("fence receipt: %v", err)}
	}
	s.log.Info("custody migration epoch transition", "op", req.Op, "fence", rec.FenceID,
		"epoch", rec.Epoch, "state", rec.State, "base_seq", rec.BaseSeq)
	return Response{OK: true, Fence: receipt, WitnessFP: signer.Fingerprint()}
}

// handlePrepare admits one migration transaction and returns its permit.
func (s *Service) handlePrepare(ctx context.Context, signer *evidence.Signer, signerEpoch int64, req *PrepareRequest) Response {
	if err := VerifyPrepareRequest(req, s.deploymentID, s.kernelTrust); err != nil {
		s.log.Warn("fence prepare refused", "error", err)
		return Response{Error: err.Error(), Code: CodeFenceState}
	}
	permit, err := s.ledger.PrepareMigration(ctx, signer, signerEpoch, req)
	if err != nil {
		s.log.Warn("fence prepare refused", "fence", req.FenceID, "tx", req.TxID, "error", err)
		return Response{Error: err.Error(), Code: refusalCode(err)}
	}
	s.log.Info("custody migration transaction admitted", "fence", permit.FenceID,
		"tx", permit.TxID, "target_seq", permit.TargetSeq, "epoch", permit.Epoch)
	return Response{OK: true, Permit: permit, WitnessFP: signer.Fingerprint()}
}

// handleFinalize records one transaction's committed local outcome.
func (s *Service) handleFinalize(ctx context.Context, signer *evidence.Signer, signerEpoch int64, req *FinalizeRequest) Response {
	if err := VerifyFinalizeRequest(req, s.deploymentID, s.kernelTrust); err != nil {
		s.log.Warn("fence finalize refused", "error", err)
		return Response{Error: err.Error(), Code: CodeFenceState}
	}
	result, err := s.ledger.FinalizeMigration(ctx, signer, signerEpoch, req)
	if err != nil {
		s.log.Warn("fence finalize refused", "tx", req.TxID, "error", err)
		return Response{Error: err.Error(), Code: refusalCode(err)}
	}
	s.log.Info("custody migration transaction finalized", "fence", result.FenceID,
		"tx", result.TxID, "journal_seq", result.JournalSeq)
	return Response{OK: true, Result: result, WitnessFP: signer.Fingerprint()}
}

// handleAbortTx releases one admitted transaction that never committed.
func (s *Service) handleAbortTx(ctx context.Context, signer *evidence.Signer, signerEpoch int64, req *FinalizeRequest) Response {
	if err := VerifyFinalizeRequest(req, s.deploymentID, s.kernelTrust); err != nil {
		s.log.Warn("fence abort refused", "error", err)
		return Response{Error: err.Error(), Code: CodeFenceState}
	}
	rec, err := s.ledger.AbortMigration(ctx, req)
	if err != nil {
		s.log.Warn("fence abort refused", "tx", req.TxID, "error", err)
		return Response{Error: err.Error(), Code: refusalCode(err)}
	}
	receipt, err := SignFenceReceipt(signer, signerEpoch, rec.receipt())
	if err != nil {
		return Response{Error: fmt.Sprintf("fence abort receipt: %v", err)}
	}
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
	case errors.Is(err, ErrPermitMissing):
		return CodePermitMissing
	case errors.Is(err, ErrPermitConsumed):
		return CodePermitUsed
	case errors.Is(err, ErrMigrationOutcomeUnknown):
		return CodeOutcomeUnknown
	case errors.Is(err, ErrFenceRecoveryRequired):
		return CodeRecoveryNeeded
	case errors.Is(err, ErrWrongTerminalReceipt):
		return CodeWrongTerminal
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
