package research

// G1 trust-repair fixtures for diagnosis, task-set construction, and
// promotion. Test IDs match qualification/rc8-required-tests.json
// gate g1-trust-repair.

import (
	"encoding/json"
	"testing"

	"github.com/openclaw/crabbox/internal/dream"
	"github.com/openclaw/crabbox/internal/experience"
	"github.com/openclaw/crabbox/internal/history"
)

const testTrustFP = "fp"

func testTrustSHA() string {
	return history.TrustSetSHA256(map[string]bool{testTrustFP: true})
}

func verify(t *testing.T, s *history.Store, dedupe, rules string) {
	t.Helper()
	if err := s.RecordAssessment(&history.Assessment{
		SubjectKey: dedupe, Verifier: "v", RulesVersion: rules,
		TrustSetSHA: testTrustSHA(), InputSHA: "in",
		Result: history.AssessmentVerified,
	}); err != nil {
		t.Fatal(err)
	}
}

// TestTrustMixedSignatures: a signature mixing verified and unassessed
// problems is untrusted in BOTH orders — all-evidence-verified means
// a clean later node can never launder an unassessed earlier history
// (or vice versa). Provenance of the untrusted contributors is kept.
func TestTrustMixedSignatures(t *testing.T) {
	for _, tc := range []struct {
		name        string
		verifyFirst bool
	}{
		{"verified-then-unassessed", true},
		{"unassessed-then-verified", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := openStore(t)
			appendEvent(t, s, "t:r1:F", "test_result", "pkg/F", 100, map[string]any{"status": "fail"})
			appendEvent(t, s, "t:r2:F", "test_result", "pkg/F", 200, map[string]any{"status": "fail"})
			if tc.verifyFirst {
				verify(t, s, "t:r1:F", "observation-v1")
			} else {
				verify(t, s, "t:r2:F", "observation-v1")
			}
			g, err := experience.Reconstruct(s, testTrustSHA())
			if err != nil {
				t.Fatal(err)
			}
			sigs := Diagnose(g)
			if len(sigs) != 1 {
				t.Fatalf("expected 1 signature, got %d", len(sigs))
			}
			sig := sigs[0]
			if sig.Trusted {
				t.Fatalf("mixed-trust signature reported trusted (verify_first=%v)", tc.verifyFirst)
			}
			if len(sig.UntrustedProblems) != 1 {
				t.Fatalf("untrusted provenance lost: %+v", sig.UntrustedProblems)
			}
			want := "t:r2:F"
			if !tc.verifyFirst {
				want = "t:r1:F"
			}
			if sig.UntrustedProblems[0] != want {
				t.Fatalf("untrusted problem %q, want %q", sig.UntrustedProblems[0], want)
			}
		})
	}

	// Fully verified signature: every contributing problem VERIFIED.
	s := openStore(t)
	appendEvent(t, s, "t:r1:F", "test_result", "pkg/F", 100, map[string]any{"status": "fail"})
	appendEvent(t, s, "t:r2:F", "test_result", "pkg/F", 200, map[string]any{"status": "fail"})
	verify(t, s, "t:r1:F", "observation-v1")
	verify(t, s, "t:r2:F", "observation-v1")
	g, err := experience.Reconstruct(s, testTrustSHA())
	if err != nil {
		t.Fatal(err)
	}
	sigs := Diagnose(g)
	if len(sigs) != 1 || !sigs[0].Trusted {
		t.Fatalf("all-verified signature not trusted: %+v", sigs)
	}
}

// TestTrustedTaskSetExcludesUnassessed: the task set admits only
// VERIFIED execution nodes — unassessed, adverse, and superseded
// executions contribute no task identities.
func TestTrustedTaskSetExcludesUnassessed(t *testing.T) {
	s := openStore(t)
	for _, e := range []*history.Event{
		{DedupeKey: "job:job-unassessed", Kind: "execution", Subject: "job-unassessed",
			Source: "test", OccurredAt: 100, Payload: mustJSON(t, map[string]any{"state": "succeeded"})},
		{DedupeKey: "job:job-verified", Kind: "execution", Subject: "job-verified",
			Source: "test", OccurredAt: 200, Payload: mustJSON(t, map[string]any{"state": "succeeded"})},
		{DedupeKey: "job:job-rejected", Kind: "execution", Subject: "job-rejected",
			Source: "test", OccurredAt: 300, Payload: mustJSON(t, map[string]any{"state": "succeeded"})},
	} {
		if _, err := s.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	verify(t, s, "job:job-verified", "observation-v1")
	if err := s.RecordAssessment(&history.Assessment{
		SubjectKey: "job:job-rejected", Verifier: "v", RulesVersion: "observation-v1",
		TrustSetSHA: testTrustSHA(), InputSHA: "in", Result: history.AssessmentRejected,
	}); err != nil {
		t.Fatal(err)
	}
	g, err := experience.Reconstruct(s, testTrustSHA())
	if err != nil {
		t.Fatal(err)
	}
	set := TrustedTaskSet(g)
	if set["job-unassessed"] {
		t.Fatal("unassessed execution admitted to the trusted task set")
	}
	if set["job-rejected"] {
		t.Fatal("rejected execution admitted to the trusted task set")
	}
	if !set["job-verified"] {
		t.Fatal("verified execution missing from the trusted task set")
	}
}

// TestUnverifiedNotPromoted: promotion paths refuse on every
// unverified basis — adverse verdicts at the gate, unassessed
// signatures in planning, empty task sets in evaluation.
func TestUnverifiedNotPromoted(t *testing.T) {
	// Promotion gate: any untrusted node count refuses.
	if r := CheckPromotion(PromotionEvidence{
		RealizedOutcomes: 10, UntrustedNodes: 1, ReplayDelta: 0.5,
	}); r == "" {
		t.Fatal("promotion allowed with untrusted memory in basis")
	}
	// Plan on an unassessed failure record never proposes an
	// experiment, even with free arms.
	s := openStore(t)
	appendEvent(t, s, "t:r1:F", "test_result", "pkg/F", 100, map[string]any{"status": "fail"})
	g, err := experience.Reconstruct(s, "")
	if err != nil {
		t.Fatal(err)
	}
	env := testEnvelope(t)
	ps := Plan(g, env, nil, dream.Task{ID: "fam"}, map[int]bool{})
	for _, p := range ps {
		if p.Decision == decideExperiment {
			t.Fatalf("experiment proposed on unverified memory: %+v", p)
		}
	}
	// A store with zero verified executions yields an empty task
	// set — the trusted-only variant trains on nothing.
	if set := TrustedTaskSet(g); len(set) != 0 {
		t.Fatalf("trusted task set non-empty on unverified store: %v", set)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
