package experience

// G1 trust-repair fixtures: every path that once admitted unassessed
// memory must now fail closed. Test IDs match
// qualification/rc8-required-tests.json gate g1-trust-repair.

import (
	"testing"

	"github.com/openclaw/crabbox/internal/history"
)

// TestTrustBlankIsUnverified: a node never assessed (Trust == "")
// is not a trusted observation, at either value.
func TestTrustBlankIsUnverified(t *testing.T) {
	n := &Node{ID: "x", Trust: ""}
	if IsTrustedObservation(n) {
		t.Fatal("blank trust reported as trusted")
	}
	if NormalizedTrust(n) != history.AssessmentUnverified {
		t.Fatalf("blank normalized to %q, want UNVERIFIED", NormalizedTrust(n))
	}
	if IsTrustedObservation(nil) {
		t.Fatal("nil node reported as trusted")
	}
	for _, v := range []string{"", "verified", "TRUSTED", "yes", "UNKNOWN"} {
		if IsTrustedObservation(&Node{ID: "x", Trust: v}) {
			t.Fatalf("trust %q reported as trusted", v)
		}
		if NormalizedTrust(&Node{Trust: v}) != history.AssessmentUnverified {
			t.Fatalf("unknown trust %q normalized to non-UNVERIFIED", v)
		}
	}
}

// TestTrustInvalidSignature: a receipt whose signature failed
// verification carries a REJECTED verdict — quarantined, not hidden.
func TestTrustInvalidSignature(t *testing.T) {
	s := openStore(t)
	e := appendEvent(t, s, "r:forged", "receipt", "exec-1", "", 100, map[string]any{"outcome": "completed"})
	trustSHA := history.TrustSetSHA256(map[string]bool{"fp": true})
	if err := s.RecordAssessment(&history.Assessment{
		SubjectKey: e.DedupeKey, Verifier: "v", RulesVersion: "receipt-v1",
		TrustSetSHA: trustSHA, InputSHA: "in", Result: history.AssessmentRejected,
		Detail: "signature invalid",
	}); err != nil {
		t.Fatal(err)
	}
	g, err := Reconstruct(s, trustSHA)
	if err != nil {
		t.Fatal(err)
	}
	if IsTrustedObservation(g.Nodes["r:forged"]) {
		t.Fatal("rejected (invalid-signature) record trusted")
	}
}

// TestTrustStalePolicyInvalid: a VERIFIED verdict under trust set A is
// STALE under trust set B — a policy change cannot launder trust.
func TestTrustStalePolicyInvalid(t *testing.T) {
	s := openStore(t)
	e := appendEvent(t, s, "r:old", "receipt", "exec-1", "", 100, map[string]any{"outcome": "completed"})
	trustA := history.TrustSetSHA256(map[string]bool{"fp-a": true})
	trustB := history.TrustSetSHA256(map[string]bool{"fp-b": true})
	if err := s.RecordAssessment(&history.Assessment{
		SubjectKey: e.DedupeKey, Verifier: "v", RulesVersion: "receipt-v1",
		TrustSetSHA: trustA, InputSHA: "in", Result: history.AssessmentVerified,
	}); err != nil {
		t.Fatal(err)
	}
	g, err := Reconstruct(s, trustB)
	if err != nil {
		t.Fatal(err)
	}
	n := g.Nodes["r:old"]
	if n.Trust != history.AssessmentStale {
		t.Fatalf("cross-policy verdict reported %q, want STALE", n.Trust)
	}
	if IsTrustedObservation(n) {
		t.Fatal("stale-policy verdict trusted")
	}
	if _, ok := g.Trusted().Nodes["r:old"]; ok {
		t.Fatal("stale-policy node in trusted graph")
	}
}

// TestTrustContradictoryAssessment: disagreeing verifiers produce
// CONFLICTED — the store reports the conflict instead of picking a
// winner, and the record is untrusted either way.
func TestTrustContradictoryAssessment(t *testing.T) {
	s := openStore(t)
	e := appendEvent(t, s, "r:conf", "receipt", "exec-1", "", 100, map[string]any{"outcome": "completed"})
	trustSHA := history.TrustSetSHA256(map[string]bool{"fp": true})
	for _, a := range []*history.Assessment{
		{SubjectKey: e.DedupeKey, Verifier: "v1", RulesVersion: "receipt-v1",
			TrustSetSHA: trustSHA, InputSHA: "in", Result: history.AssessmentVerified},
		{SubjectKey: e.DedupeKey, Verifier: "v2", RulesVersion: "receipt-v1",
			TrustSetSHA: trustSHA, InputSHA: "in", Result: history.AssessmentRejected},
	} {
		if err := s.RecordAssessment(a); err != nil {
			t.Fatal(err)
		}
	}
	g, err := Reconstruct(s, trustSHA)
	if err != nil {
		t.Fatal(err)
	}
	n := g.Nodes["r:conf"]
	if n.Trust != history.AssessmentConflicted {
		t.Fatalf("contradictory verdicts reported %q, want CONFLICTED", n.Trust)
	}
	if IsTrustedObservation(n) {
		t.Fatal("conflicted record trusted")
	}
}

// TestTrustSupersededEvidence: even a VERIFIED observation is
// quarantined once a later observation supersedes it — the current
// record speaks, the old one is searchable history.
func TestTrustSupersededEvidence(t *testing.T) {
	s := openStore(t)
	old := appendEvent(t, s, "job:h:a", "execution", "job-1", "h1", 100, map[string]any{"state": "running"})
	appendEvent(t, s, "job:h:b", "execution", "job-1", "h1", 200, map[string]any{"state": "succeeded"})
	trustSHA := history.TrustSetSHA256(map[string]bool{"fp": true})
	for _, key := range []string{old.DedupeKey, "job:h:b"} {
		if err := s.RecordAssessment(&history.Assessment{
			SubjectKey: key, Verifier: "v", RulesVersion: "observation-v1",
			TrustSetSHA: trustSHA, InputSHA: "in", Result: history.AssessmentVerified,
		}); err != nil {
			t.Fatal(err)
		}
	}
	g, err := Reconstruct(s, trustSHA)
	if err != nil {
		t.Fatal(err)
	}
	if !g.Superseded("job:h:a") {
		t.Fatal("earlier observation not superseded")
	}
	if _, ok := g.Trusted().Nodes["job:h:a"]; ok {
		t.Fatal("superseded node offered to the learner")
	}
	if _, ok := g.Trusted().Nodes["job:h:b"]; !ok {
		t.Fatal("current verified node missing from trusted graph")
	}
	if _, ok := g.Quarantined().Nodes["job:h:a"]; !ok {
		t.Fatal("superseded node missing from quarantine")
	}
}

// TestForgedAssessmentRejected: an adverse verdict excludes the
// record from every trusted surface — REJECTED is durable knowledge.
func TestForgedAssessmentRejected(t *testing.T) {
	s := openStore(t)
	e := appendEvent(t, s, "r:fake", "receipt", "exec-9", "", 100, map[string]any{"outcome": "completed"})
	trustSHA := history.TrustSetSHA256(map[string]bool{"fp": true})
	if err := s.RecordAssessment(&history.Assessment{
		SubjectKey: e.DedupeKey, Verifier: "v", RulesVersion: "receipt-v1",
		TrustSetSHA: trustSHA, InputSHA: "in", Result: history.AssessmentRejected,
		Detail: "assessment does not match stored evidence input",
	}); err != nil {
		t.Fatal(err)
	}
	g, err := Reconstruct(s, trustSHA)
	if err != nil {
		t.Fatal(err)
	}
	if IsTrustedObservation(g.Nodes["r:fake"]) || len(g.Trusted().Nodes) != 0 {
		t.Fatal("forged-evidence record reached a trusted surface")
	}
}

// TestTrustReplayRejected: a VERIFIED verdict recorded under a
// different rules version does not apply — the verdict is bound to
// the policy it was produced under, not replayable across policies.
func TestTrustReplayRejected(t *testing.T) {
	s := openStore(t)
	e := appendEvent(t, s, "r:replay", "receipt", "exec-1", "", 100, map[string]any{"outcome": "completed"})
	trustSHA := history.TrustSetSHA256(map[string]bool{"fp": true})
	// Verdict minted under a different rules version than
	// assessmentRules(receipt) resolves to (receipt-v1).
	if err := s.RecordAssessment(&history.Assessment{
		SubjectKey: e.DedupeKey, Verifier: "v", RulesVersion: "observation-v1",
		TrustSetSHA: trustSHA, InputSHA: "in", Result: history.AssessmentVerified,
	}); err != nil {
		t.Fatal(err)
	}
	g, err := Reconstruct(s, trustSHA)
	if err != nil {
		t.Fatal(err)
	}
	if IsTrustedObservation(g.Nodes["r:replay"]) {
		t.Fatal("verdict replayed across rules versions and trusted")
	}
}

// TestLegacyStoreMigrationKeepsUntrusted: records ingested before
// assessments existed carry no verdict — reconstructing under a
// pinned policy leaves them unassessed and untrusted until reverified.
// No bulk promotion is possible.
func TestLegacyStoreMigrationKeepsUntrusted(t *testing.T) {
	s := openStore(t)
	appendEvent(t, s, "job:legacy", "execution", "job-1", "h1", 100, map[string]any{"state": "succeeded"})
	appendEvent(t, s, "r:legacy", "receipt", "job-1", "h1", 200, map[string]any{"outcome": "completed"})
	trustSHA := history.TrustSetSHA256(map[string]bool{"fp": true})
	g, err := Reconstruct(s, trustSHA)
	if err != nil {
		t.Fatal(err)
	}
	for id, n := range g.Nodes {
		if n.Trust != "" {
			t.Fatalf("legacy record %s reported trust %q — unassessed must stay unassessed", id, n.Trust)
		}
		if IsTrustedObservation(n) {
			t.Fatalf("legacy record %s trusted without reverification", id)
		}
	}
	if len(g.Trusted().Nodes) != 0 {
		t.Fatal("legacy store produced trusted nodes without any verdict")
	}
	if len(g.Quarantined().Nodes) != len(g.Nodes) {
		t.Fatal("legacy records missing from quarantine")
	}
}
