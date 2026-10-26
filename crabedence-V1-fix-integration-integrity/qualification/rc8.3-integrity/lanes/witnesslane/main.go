//go:build witnesslane

// Command witnesslane runs the independent witness qualification over
// mutually authenticated TLS. It launches a separately administered
// witnessd process with its own signing key, ledger, deployment pin,
// and kernel trust root; the kernel side holds a distinct key and its
// own custodian trust root. Nothing is shared in-process.
//
// Scenarios: authenticated transport (both pin directions), valid
// custody, idempotent replay, conflicting replay, forged kernel
// signature, stale acknowledgement, checkpoint substitution, network
// partition, crash/restart persistence, and post-restart replay.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/openclaw/crabbox/internal/custody"
	"github.com/openclaw/crabbox/internal/evidence"
	"github.com/openclaw/crabbox/internal/witness"
)

const deployment = "dep-independent-a"

var failures int

func pass(format string, args ...any) { fmt.Printf("PASS  "+format+"\n", args...) }

func fail(format string, args ...any) {
	failures++
	fmt.Printf("FAIL  "+format+"\n", args...)
}

func must(err error, what string) {
	if err != nil {
		fmt.Printf("FATAL %s: %v\n", what, err)
		os.Exit(2)
	}
}

func writeTrustFile(path, role, dep string, signer *evidence.Signer) {
	doc := map[string]any{
		"version": 1,
		"keys": []map[string]any{{
			"role": role, "key_id": signer.Fingerprint(),
			"public_key":    base64.StdEncoding.EncodeToString(signer.PublicKey()),
			"deployment_id": dep, "valid_from_index": 0, "valid_until_index": 0,
		}},
	}
	raw, err := json.Marshal(doc)
	must(err, "trust json")
	must(os.WriteFile(path, raw, 0o600), "write trust")
}

func envelope(dep string, seq int64, prev, exec string, payload []byte, signer *evidence.Signer) *custody.Envelope {
	env := custody.New(custody.FamilyReceipt, dep,
		custody.ReleaseIdentity{Version: "0.55.0-rc8.3-integrity-closure"},
		"", custody.Subject{EffectID: exec, ExecutionID: exec},
		custody.Sequence{Domain: custody.FamilyReceipt, Epoch: 0, Index: seq, PreviousCheckpointHash: prev},
		custody.EncodingWitnessFrame, payload)
	must(custody.Sign(env, custody.RoleKernelRelay, signer), "sign envelope")
	return env
}

func startWitness(bin, dir, addr string, kernel *evidence.Signer) *exec.Cmd {
	logPath := filepath.Join(dir, "witnessd.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	must(err, "witness log")
	cmd := exec.Command(bin,
		"-listen", addr,
		"-client-fp", kernel.Fingerprint(),
		"-store", filepath.Join(dir, "witness-ledger.db"),
		"-key", filepath.Join(dir, "witness-signer.pem"),
		"-deployment", deployment,
		"-kernel-trust", filepath.Join(dir, "kernel-trust.json"),
	)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	must(cmd.Start(), "start witnessd")
	return cmd
}

func stopWitness(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Signal(syscall.SIGKILL)
	_, _ = cmd.Process.Wait()
}

func waitReady(client *witness.Client) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var last error
	for {
		if _, err := client.Checkpoint(ctx, deployment); err == nil {
			return nil
		} else {
			last = err
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("witness not ready: %w", last)
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func freeAddr() string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must(err, "pick port")
	defer ln.Close()
	return ln.Addr().String()
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: witnesslane <witnessd-binary>")
		os.Exit(2)
	}
	bin := os.Args[1]
	dir, err := os.MkdirTemp("", "witness-lane-")
	must(err, "temp dir")
	defer os.RemoveAll(dir)
	must(os.Chmod(dir, 0o700), "chmod temp dir")

	kernel, err := evidence.GenerateSigner()
	must(err, "kernel signer")
	witnessSigner, err := evidence.GenerateSigner()
	must(err, "witness signer")
	rogue, err := evidence.GenerateSigner()
	must(err, "rogue signer")

	writeTrustFile(filepath.Join(dir, "kernel-trust.json"), custody.RoleKernelRelay, deployment, kernel)
	writeTrustFile(filepath.Join(dir, "custodian-trust.json"), custody.RoleCustodian, deployment, witnessSigner)
	pem, err := witnessSigner.MarshalPEM()
	must(err, "witness pem")
	must(os.WriteFile(filepath.Join(dir, "witness-signer.pem"), pem, 0o600), "write witness pem")

	addr := freeAddr()
	cmd := startWitness(bin, dir, addr, kernel)
	defer stopWitness(cmd)

	clientTLS, err := witness.ClientTLSConfig(kernel, witnessSigner.Fingerprint())
	must(err, "client tls")
	client := witness.NewTLSClient(addr, clientTLS)
	client.Timeout = 3 * time.Second
	must(waitReady(client), "witness readiness")
	pass("mTLS transport established: kernel %s ↔ witness %s", kernel.Fingerprint()[:12], witnessSigner.Fingerprint()[:12])

	custodianTrust, err := custody.LoadTrustSetForRole(filepath.Join(dir, "custodian-trust.json"), custody.RoleCustodian)
	must(err, "custodian trust")

	// Negative transport: the server must reject a client key it does
	// not pin, and the client must reject an unpinned server key.
	rogueTLS, err := witness.ClientTLSConfig(rogue, witnessSigner.Fingerprint())
	must(err, "rogue client tls")
	rogueClient := witness.NewTLSClient(addr, rogueTLS)
	rogueClient.Timeout = 2 * time.Second
	if _, err := rogueClient.Checkpoint(context.Background(), deployment); err == nil {
		fail("witness accepted an unpinned kernel client certificate")
	} else {
		pass("witness rejected unpinned client key: %v", err)
	}
	wrongPinTLS, err := witness.ClientTLSConfig(kernel, rogue.Fingerprint())
	must(err, "wrong pin tls")
	wrongPinClient := witness.NewTLSClient(addr, wrongPinTLS)
	wrongPinClient.Timeout = 2 * time.Second
	if _, err := wrongPinClient.Checkpoint(context.Background(), deployment); err == nil {
		fail("client accepted an unpinned witness certificate")
	} else {
		pass("client rejected unpinned witness key: %v", err)
	}

	// Empty checkpoint.
	head0, err := client.Checkpoint(context.Background(), deployment)
	must(err, "initial checkpoint")
	if err := witness.VerifyCheckpoint(head0, deployment, custodianTrust); err != nil {
		fail("initial checkpoint does not verify: %v", err)
	} else {
		pass("initial signed checkpoint verifies (seq=%d)", head0.Seq)
	}

	// Valid custody.
	env1 := envelope(deployment, 1, "", "indep-exec-1", []byte(`{"receipt":"one"}`), kernel)
	ack1, err := client.Submit(context.Background(), deployment, env1)
	if err != nil {
		fmt.Printf("FATAL valid submission refused: %v\n", err)
		os.Exit(2)
	}
	if err := witness.VerifyAck(ack1, env1, custodianTrust); err != nil {
		fmt.Printf("FATAL valid ack does not verify: %v\n", err)
		os.Exit(2)
	}
	pass("valid envelope custodied and ack verifies (seq=%d)", ack1.Seq)

	// Idempotent replay.
	ackReplay, err := client.Submit(context.Background(), deployment, env1)
	if err != nil {
		fail("identical replay refused: %v", err)
	} else if ack1 == nil || ackReplay.Signature != ack1.Signature {
		fail("identical replay did not return the stored ack")
	} else {
		pass("identical replay returned the stored ack")
	}

	// Conflicting replay at the same index.
	conflict := envelope(deployment, 1, "", "indep-exec-1", []byte(`{"receipt":"different"}`), kernel)
	if _, err := client.Submit(context.Background(), deployment, conflict); err == nil {
		fail("conflicting envelope at the same sequence was admitted")
	} else {
		pass("conflicting envelope refused: %v", err)
	}

	// Forged kernel signature at a fresh index (extends the head, so the
	// refusal can only come from signature verification).
	forged := envelope(deployment, 2, ack1.EnvelopeHash, "indep-forged", []byte(`{"receipt":"forged"}`), rogue)
	if _, err := client.Submit(context.Background(), deployment, forged); err == nil {
		fail("envelope signed by an unpinned kernel key was admitted")
	} else if !strings.Contains(strings.ToLower(err.Error()), "trust") && !strings.Contains(strings.ToLower(err.Error()), "signature") {
		fail("forged signature refused for the wrong reason: %v", err)
	} else {
		pass("forged kernel signature refused by signature verification: %v", err)
	}

	// Checkpoint substitution.
	substituted := *head0
	substituted.Hash = strings.Repeat("0", 64)
	if err := witness.VerifyCheckpoint(&substituted, deployment, custodianTrust); err == nil {
		fail("checkpoint with a substituted head hash verified")
	} else {
		pass("substituted checkpoint hash rejected: %v", err)
	}
	substituted = *head0
	substituted.WitnessFP = rogue.Fingerprint()
	if err := witness.VerifyCheckpoint(&substituted, deployment, custodianTrust); err == nil {
		fail("checkpoint with a substituted witness identity verified")
	} else {
		pass("substituted witness identity rejected: %v", err)
	}

	// Network partition: kill the witness, then prove the client cannot
	// reach it and the durable head survives a restart.
	stopWitness(cmd)
	cmd = nil
	partitionClient := witness.NewTLSClient(addr, clientTLS)
	partitionClient.Timeout = 1 * time.Second
	if _, err := partitionClient.Checkpoint(context.Background(), deployment); err == nil {
		fail("checkpoint succeeded during a network partition")
	} else {
		pass("network partition refused custody: %v", err)
	}

	cmd = startWitness(bin, dir, addr, kernel)
	defer stopWitness(cmd)
	must(waitReady(client), "witness restart")
	headAfter, err := client.Checkpoint(context.Background(), deployment)
	if err != nil {
		fail("checkpoint after restart: %v", err)
	} else if headAfter.Seq != 1 || headAfter.Hash != ack1.EnvelopeHash {
		fail("crash/restart lost the custody head: seq=%d hash=%s", headAfter.Seq, headAfter.Hash)
	} else {
		pass("crash/restart preserved the custody head (seq=%d)", headAfter.Seq)
	}

	// Post-restart replay still returns the stored ack.
	ackAfter, err := client.Submit(context.Background(), deployment, env1)
	if err != nil {
		fail("post-restart replay refused: %v", err)
	} else if ackAfter.Signature != ack1.Signature {
		fail("post-restart replay returned a different ack")
	} else {
		pass("post-restart replay returned the stored ack")
	}

	// Stale acknowledgement: an ack for seq 1 must not verify for seq 2.
	env2 := envelope(deployment, 2, ack1.EnvelopeHash, "indep-exec-2", []byte(`{"receipt":"two"}`), kernel)
	if err := witness.VerifyAck(ack1, env2, custodianTrust); err == nil {
		fail("stale acknowledgement verified for a later envelope")
	} else {
		pass("stale acknowledgement rejected for a later envelope: %v", err)
	}
	ack2, err := client.Submit(context.Background(), deployment, env2)
	if err != nil {
		fmt.Printf("FATAL second valid submission refused: %v\n", err)
		os.Exit(2)
	}
	if err := witness.VerifyAck(ack2, env2, custodianTrust); err != nil {
		fmt.Printf("FATAL second ack does not verify: %v\n", err)
		os.Exit(2)
	}
	pass("second valid envelope custodied and ack verifies (seq=%d)", ack2.Seq)

	// Migration epoch across the real mTLS boundary: the fence protocol
	// is transport-agnostic, and an independently administered witness
	// is expected to run it over exactly this channel.
	fenceClient := &witness.FenceClient{
		Client: client, Signer: kernel, DeploymentID: deployment,
		GrantDigest: strings.Repeat("ab", 32),
		KernelTrust: custody.NewTrustSet(custody.TrustedKey{
			Role: custody.RoleKernelRelay, KeyID: kernel.Fingerprint(),
			PublicKey: kernel.PublicKey(), DeploymentID: deployment,
		}),
		CustodianTrust: custodianTrust,
	}
	fence, err := fenceClient.Begin(context.Background())
	if err != nil {
		fail("migration epoch did not open over mTLS: %v", err)
	} else if fence.BaseSeq != ack2.Seq || fence.BaseHash != ack2.EnvelopeHash {
		fail("epoch froze seq %d (%s), the custody head was seq %d (%s)", fence.BaseSeq, fence.BaseHash, ack2.Seq, ack2.EnvelopeHash)
	} else {
		pass("migration epoch opened over mTLS at seq %d (fence %s)", fence.BaseSeq, fence.FenceID[:12])
	}

	// A submission already on the wire must be refused while the epoch
	// is open — the defect this epoch exists to prevent.
	inflight := envelope(deployment, 3, ack2.EnvelopeHash, "indep-inflight", []byte(`{"receipt":"three"}`), kernel)
	if _, err := client.Submit(context.Background(), deployment, inflight); !errors.Is(err, witness.ErrFenced) {
		fail("submission inside an open epoch was not fenced: %v", err)
	} else {
		pass("in-flight submission refused inside the epoch: %v", err)
	}

	// A second epoch cannot be opened while one is live.
	second := &witness.FenceRequest{
		Op: witness.OpFenceBegin, DeploymentID: deployment,
		FenceID:     witness.FenceIDFor(deployment, strings.Repeat("cd", 32), fence.BaseSeq, fence.BaseHash),
		GrantDigest: strings.Repeat("cd", 32), BaseSeq: fence.BaseSeq, BaseHash: fence.BaseHash,
	}
	must(witness.SignFenceRequest(kernel, second), "sign second fence")
	if _, err := client.BeginFence(context.Background(), second); !errors.Is(err, witness.ErrFenceActive) {
		fail("a second epoch opened while one was live: %v", err)
	} else {
		pass("second epoch refused while one is live: %v", err)
	}

	// A fence receipt minted by an unpinned key is not authority.
	rogueReceipt := fence
	rogueReceipt.Signature = ""
	rogueReceipt.WitnessFP = rogue.Fingerprint()
	if _, err := witness.SignFenceReceipt(rogue, 0, &rogueReceipt); err == nil {
		if err := witness.VerifyFenceReceipt(&rogueReceipt, deployment, custodianTrust); err == nil {
			fail("fence receipt signed by an unpinned key verified")
		} else {
			pass("fence receipt under an unpinned key rejected: %v", err)
		}
	}

	// Closing the epoch resumes custody.
	closed, err := fenceClient.End(context.Background(), fence, strings.Repeat("11", 32))
	if err != nil {
		fail("epoch close over mTLS: %v", err)
	} else if closed.State != witness.FenceClosed {
		fail("epoch close returned state %s", closed.State)
	} else {
		pass("migration epoch closed over mTLS (result %s)", closed.ResultDigest[:12])
	}
	ack3, err := client.Submit(context.Background(), deployment, inflight)
	if err != nil {
		fail("submission refused after the epoch closed: %v", err)
	} else if err := witness.VerifyAck(ack3, inflight, custodianTrust); err != nil {
		fail("post-epoch ack does not verify: %v", err)
	} else {
		pass("submission resumed after the epoch closed (seq=%d)", ack3.Seq)
	}

	// An epoch is durable: a restart must not silently release it.
	fence2, err := fenceClient.Begin(context.Background())
	if err != nil {
		fail("second epoch did not open: %v", err)
	} else {
		stopWitness(cmd)
		cmd = startWitness(bin, dir, addr, kernel)
		defer stopWitness(cmd)
		must(waitReady(client), "witness restart with an open epoch")
		still := envelope(deployment, 5, ack3.EnvelopeHash, "indep-after-restart", []byte(`{"receipt":"five"}`), kernel)
		if _, err := client.Submit(context.Background(), deployment, still); !errors.Is(err, witness.ErrFenced) {
			fail("restart released an open epoch: %v", err)
		} else {
			pass("open epoch survived a witness restart: %v", err)
		}
		if _, err := fenceClient.End(context.Background(), fence2, strings.Repeat("22", 32)); err != nil {
			fail("closing the restarted epoch: %v", err)
		} else {
			pass("restarted epoch closed cleanly")
		}
	}

	if failures != 0 {
		fmt.Printf("RESULT FAIL (%d failures)\n", failures)
		os.Exit(1)
	}
	fmt.Println("RESULT PASS: independent TLS witness lane")
}
