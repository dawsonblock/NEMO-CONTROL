package history

// observation-v1 verifier fixtures: the independent evaluator mints
// verdicts only from evidence the store can independently produce —
// held source bytes and already-VERIFIED receipt verdicts — never
// from the observation's own payload.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func trust() string { return TrustSetSHA256(map[string]bool{"fp": true}) }

func verifyReceipt(t *testing.T, s *Store, dedupe, trustSHA string) {
	t.Helper()
	if err := s.RecordAssessment(&Assessment{
		SubjectKey: dedupe, Verifier: "v", RulesVersion: "receipt-v1",
		TrustSetSHA: trustSHA, InputSHA: "in", Result: AssessmentVerified,
	}); err != nil {
		t.Fatal(err)
	}
}

func appendRaw(t *testing.T, s *Store, dedupe, kind, subject, correlation string, payload any) *Event {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	evs, err := s.Append(&Event{
		DedupeKey: dedupe, Kind: kind, Subject: subject,
		Correlation: correlation, Source: "test", Payload: raw,
	})
	if err != nil {
		t.Fatal(err)
	}
	return evs[0]
}

func effective(t *testing.T, s *Store, dedupe, trustSHA string) string {
	t.Helper()
	a, err := s.EffectiveAssessment(dedupe, ObservationRulesV1, trustSHA)
	if err != nil {
		t.Fatal(err)
	}
	return a.Result
}

// An execution verifies only when a VERIFIED receipt attests a
// consistent outcome — and a verified receipt attesting the opposite
// is rejection, not ambiguity.
func TestObservationExecutionCorroboration(t *testing.T) {
	s := openStore(t)
	ts := trust()
	appendRaw(t, s, "job:j1", KindExecution, "j1", "", map[string]any{
		"job_id": "j1", "state": "SUCCEEDED"})

	// Unverified while no receipt vouches for it.
	v := &ObservationVerifier{ID: "ov"}
	if _, err := v.VerifyObservations(s, ts); err != nil {
		t.Fatal(err)
	}
	if got := effective(t, s, "job:j1", ts); got != AssessmentUnverified {
		t.Fatalf("uncorroborated execution: got %s, want UNVERIFIED", got)
	}

	// A consistent verified receipt → VERIFIED.
	appendRaw(t, s, "receipt:r1", KindReceipt, "j1", "", map[string]any{
		"execution_id": "j1", "outcome": "COMPLETED"})
	verifyReceipt(t, s, "receipt:r1", ts)
	if _, err := v.VerifyObservations(s, ts); err != nil {
		t.Fatal(err)
	}
	if got := effective(t, s, "job:j1", ts); got != AssessmentVerified {
		t.Fatalf("corroborated execution: got %s, want VERIFIED", got)
	}
}

// A verified receipt attesting NO_EFFECT for an execution recorded
// SUCCEEDED contradicts the claim — REJECTED.
func TestObservationExecutionContradiction(t *testing.T) {
	s := openStore(t)
	ts := trust()
	appendRaw(t, s, "job:j2", KindExecution, "j2", "", map[string]any{
		"job_id": "j2", "state": "SUCCEEDED"})
	appendRaw(t, s, "receipt:r2", KindReceipt, "j2", "", map[string]any{
		"execution_id": "j2", "outcome": "NO_EFFECT"})
	verifyReceipt(t, s, "receipt:r2", ts)
	v := &ObservationVerifier{ID: "ov"}
	if _, err := v.VerifyObservations(s, ts); err != nil {
		t.Fatal(err)
	}
	if got := effective(t, s, "job:j2", ts); got != AssessmentRejected {
		t.Fatalf("contradicted execution: got %s, want REJECTED", got)
	}
}

// A receipt the trust set does not vouch for corroborates nothing.
func TestObservationUntrustedReceiptNoCorroboration(t *testing.T) {
	s := openStore(t)
	ts := trust()
	appendRaw(t, s, "job:j3", KindExecution, "j3", "", map[string]any{
		"job_id": "j3", "state": "SUCCEEDED"})
	appendRaw(t, s, "receipt:r3", KindReceipt, "j3", "", map[string]any{
		"execution_id": "j3", "outcome": "COMPLETED"})
	// Receipt exists but is unassessed — it vouches for nothing.
	v := &ObservationVerifier{ID: "ov"}
	if _, err := v.VerifyObservations(s, ts); err != nil {
		t.Fatal(err)
	}
	if got := effective(t, s, "job:j3", ts); got != AssessmentUnverified {
		t.Fatalf("untrusted receipt corroborated: got %s, want UNVERIFIED", got)
	}
}

// A recorded test_result verifies when the held stream bytes
// re-derive the same case; a record disagreeing with the held bytes
// is rejected; absent bytes leave it unverifiable.
func TestObservationTestResultRederived(t *testing.T) {
	s := openStore(t)
	cs := openContent(t)
	ts := trust()
	if _, err := s.IngestTestStream(strings.NewReader(validStream), "suite", cs); err != nil {
		t.Fatal(err)
	}
	v := &ObservationVerifier{ID: "ov", Content: cs}
	rep, err := v.VerifyObservations(s, ts)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Verified != 3 || rep.Rejected != 0 || rep.Unverified != 0 {
		t.Fatalf("held stream verification wrong: %+v", rep)
	}
	results, err := s.Query(QueryOpts{Kinds: []string{KindTestResult}})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range results {
		if got := effective(t, s, e.DedupeKey, ts); got != AssessmentVerified {
			t.Fatalf("test_result %s: got %s, want VERIFIED", e.DedupeKey, got)
		}
	}

	// Tampered record: claims a pass the held stream doesn't derive.
	appendRaw(t, s, "test:forged", KindTestResult, "p/TestZ", "", testResultRecord{
		Run: results[0].Correlation, Package: "p", Test: "TestZ",
		Status: "pass", ElapsedSeconds: 1, TerminalEvents: 1, OutputSHA256: "aa",
	})
	if _, err := v.VerifyObservations(s, ts); err != nil {
		t.Fatal(err)
	}
	if got := effective(t, s, "test:forged", ts); got != AssessmentRejected {
		t.Fatalf("forged test_result: got %s, want REJECTED", got)
	}
}

// Without held bytes the same record stays unverifiable — memory
// reports what it could not prove, it does not trust it.
func TestObservationTestResultNoContent(t *testing.T) {
	s := openStore(t)
	ts := trust()
	if _, err := s.IngestTestStream(strings.NewReader(validStream), "suite", nil); err != nil {
		t.Fatal(err)
	}
	v := &ObservationVerifier{ID: "ov"}
	rep, err := v.VerifyObservations(s, ts)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Verified != 0 || rep.Unverified != 3 {
		t.Fatalf("unheld stream should be all unverified: %+v", rep)
	}
}

// An experiment verifies when its declared source bytes are held and
// re-derive the recorded claim; held bytes that disagree reject it.
func TestObservationExperimentHeldSource(t *testing.T) {
	s := openStore(t)
	cs := openContent(t)
	ts := trust()
	dir := t.TempDir()
	rec := `{"experiment_id":"exp-1","hypothesis":"arm1 better","arm":"1","outcome":"improved","ts":"2026-01-01T00:00:00Z"}`
	if err := os.WriteFile(filepath.Join(dir, "exp.json"), []byte(rec), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.IngestExperiments(dir, cs); err != nil {
		t.Fatal(err)
	}
	v := &ObservationVerifier{ID: "ov", Content: cs}
	if _, err := v.VerifyObservations(s, ts); err != nil {
		t.Fatal(err)
	}
	events, err := s.Query(QueryOpts{Kinds: []string{KindExperiment}})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 experiment event, got %d", len(events))
	}
	if got := effective(t, s, events[0].DedupeKey, ts); got != AssessmentVerified {
		t.Fatalf("held-source experiment: got %s, want VERIFIED", got)
	}

	// Forged record: claims a source digest whose bytes tell a
	// different story — the held bytes reject the claim.
	var p experimentRecord
	if err := json.Unmarshal(events[0].Payload, &p); err != nil {
		t.Fatal(err)
	}
	forged := p
	forged.Outcome = "catastrophic"
	appendRaw(t, s, "experiment:forged", KindExperiment, "exp-2", p.SourceSHA, forged)
	if _, err := v.VerifyObservations(s, ts); err != nil {
		t.Fatal(err)
	}
	if got := effective(t, s, "experiment:forged", ts); got != AssessmentRejected {
		t.Fatalf("forged experiment: got %s, want REJECTED", got)
	}
}
