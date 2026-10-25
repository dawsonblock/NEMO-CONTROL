package history

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/openclaw/crabbox/internal/sandboxexecutor"
)

// ObservationRulesV1 is the rules identity of the observation
// verifier — the independent evaluator named by D-13. Unlike the
// ingest-time verifiers (receipt-v1, checkpoint-v1, custody-v1),
// which attest intrinsic well-formedness as records arrive,
// observation-v1 re-derives each observation's claim from
// *independent* evidence: held source bytes re-scanned under the
// canonical derivation, or already-VERIFIED receipt verdicts. An
// observation's own payload is never the basis of its verdict —
// the verifier corroborates or contradicts it, and observations the
// evidence cannot reach stay UNVERIFIED.
const ObservationRulesV1 = "observation-v1"

// observationInputDomain separates the verifier's input digest from
// every other digest in the store.
const observationInputDomain = "crabedence.observation-input.v1\x00"

// ObservationReport is the verifier run's honest accounting: how
// many observations were verified, rejected, left unverified, and
// which kinds were covered. Skipped counts observations of covered
// kinds whose verdict could not be derived (never silently dropped —
// each lands an UNVERIFIED assessment with the reason recorded).
type ObservationReport struct {
	Verified   int      `json:"verified"`
	Rejected   int      `json:"rejected"`
	Unverified int      `json:"unverified"`
	Kinds      []string `json:"kinds"`
}

// ObservationVerifier mints observation-v1 assessments. It is
// deliberately a separate actor from every ingester: it holds no
// ingest path's private state and re-derives truth only from the
// durable record — the content store's held bytes and the
// assessments the evidence verifiers already minted.
type ObservationVerifier struct {
	// ID is the verifier identity recorded on each assessment.
	ID string
	// Content holds the source bytes observations link to; a nil
	// store means stream- and file-backed observations can never
	// reach VERIFIED — absent evidence is unverifiable, not trusted.
	Content *ContentStore
}

// VerifyObservations evaluates every stored observation of the
// covered kinds and records an observation-v1 assessment for each
// under trustSHA — the trust set the verdicts name. Verification is
// append-only: a re-run after new evidence lands mints a fresh
// verdict rather than editing the old one; an identical verdict
// re-derived from identical inputs dedupes at the store.
func (v *ObservationVerifier) VerifyObservations(s *Store, trustSHA string) (*ObservationReport, error) {
	if v == nil {
		return nil, fmt.Errorf("missing observation verifier")
	}
	id := v.ID
	if id == "" {
		id = "observation-verifier"
	}
	kinds := []string{KindExecution, KindTestResult, KindTestRun, KindExperiment}
	rep := &ObservationReport{Kinds: kinds}
	var verdicts []*Assessment
	for _, kind := range kinds {
		events, err := s.Query(QueryOpts{Kinds: []string{kind}})
		if err != nil {
			return nil, err
		}
		for _, e := range events {
			result, detail, inputSHA := v.verifyOne(s, e, trustSHA)
			verdicts = append(verdicts, &Assessment{
				SubjectKey:   e.DedupeKey,
				Verifier:     id,
				RulesVersion: ObservationRulesV1,
				TrustSetSHA:  trustSHA,
				InputSHA:     inputSHA,
				Result:       result,
				Detail:       detail,
			})
			switch result {
			case AssessmentVerified:
				rep.Verified++
			case AssessmentRejected:
				rep.Rejected++
			default:
				rep.Unverified++
			}
		}
	}
	if err := s.RecordAssessment(verdicts...); err != nil {
		return nil, err
	}
	return rep, nil
}

// verifyOne applies the per-kind corroboration rule and returns the
// verdict, an audit detail, and the input digest binding the verdict
// to the exact evidence set it was derived from.
func (v *ObservationVerifier) verifyOne(s *Store, e *Event, trustSHA string) (result, detail, inputSHA string) {
	switch e.Kind {
	case KindExecution:
		return v.verifyExecution(s, e, trustSHA)
	case KindTestResult:
		return v.verifyTestResult(e)
	case KindTestRun:
		return v.verifyTestRun(e)
	case KindExperiment:
		return v.verifyExperiment(e)
	}
	return AssessmentUnverified, "kind has no observation-v1 rule", obsInput(e.Kind, "no-rule")
}

// verifyExecution: an execution claim verifies only when a
// VERIFIED receipt names the same execution with a consistent
// outcome — the evidence layer's own verdict, independently
// derived. A verified receipt attesting a contradictory outcome is
// rejection, not ambiguity: the signed evidence disagrees with the
// recorded state.
func (v *ObservationVerifier) verifyExecution(s *Store, e *Event, trustSHA string) (string, string, string) {
	var p struct {
		JobID string `json:"job_id"`
		State string `json:"state"`
	}
	if err := json.Unmarshal(e.Payload, &p); err != nil || p.JobID == "" {
		return AssessmentRejected, "execution payload carries no job identity", obsInput(e.Kind, "malformed")
	}
	receipts, err := s.Query(QueryOpts{Kinds: []string{KindReceipt}, Subject: p.JobID})
	if err != nil {
		return AssessmentUnverified, "receipt query failed", obsInput(e.Kind, "error")
	}
	var verified, contradictory []string
	for _, r := range receipts {
		eff, err := s.EffectiveAssessment(r.DedupeKey, "receipt-v1", trustSHA)
		if err != nil || eff == nil || eff.Result != AssessmentVerified {
			continue
		}
		var rp struct {
			Outcome string `json:"outcome"`
		}
		if err := json.Unmarshal(r.Payload, &rp); err != nil {
			continue
		}
		if outcomesConsistent(p.State, rp.Outcome) {
			verified = append(verified, r.DedupeKey)
		} else {
			contradictory = append(contradictory, r.DedupeKey)
		}
	}
	sort.Strings(verified)
	sort.Strings(contradictory)
	input := obsInput(e.Kind, append(append([]string{}, verified...), contradictory...)...)
	switch {
	case len(verified) > 0:
		return AssessmentVerified,
			fmt.Sprintf("verified receipt corroborates %s", p.State), input
	case len(contradictory) > 0:
		return AssessmentRejected,
			fmt.Sprintf("verified receipts attest a contradictory outcome for %s", p.State), input
	default:
		return AssessmentUnverified, "no verified receipt corroborates this execution", input
	}
}

// outcomesConsistent maps the job-state vocabulary onto the receipt
// outcome vocabulary: SUCCEEDED requires the effect to have
// occurred, FAILED requires provably no effect. Any other pairing
// is a contradiction.
func outcomesConsistent(state, receiptOutcome string) bool {
	switch state {
	case sandboxexecutor.JobStateSucceeded:
		return receiptOutcome == "COMPLETED"
	case sandboxexecutor.JobStateFailed:
		return receiptOutcome == "NO_EFFECT"
	}
	return false
}

// verifyTestResult re-scans the held stream bytes and checks the
// recorded case against the independently derived one. The stream
// digest is the event's correlation — the content store either holds
// those bytes or the record can never verify.
func (v *ObservationVerifier) verifyTestResult(e *Event) (string, string, string) {
	var p testResultRecord
	if err := json.Unmarshal(e.Payload, &p); err != nil || p.Run == "" || p.Test == "" {
		return AssessmentRejected, "test_result payload carries no run/test identity", obsInput(e.Kind, "malformed")
	}
	raw, ok := v.heldStream(p.Run)
	if !ok {
		return AssessmentUnverified, "stream bytes not held — outcome cannot be independently derived", obsInput(e.Kind, p.Run)
	}
	sc := scanStream(raw)
	if len(sc.findings) > 0 {
		return AssessmentRejected, "held stream fails the canonical lifecycle", obsInput(e.Kind, p.Run)
	}
	rec := sc.cases[p.Test]
	if rec == nil {
		return AssessmentRejected, "no case derived for this test in the held stream", obsInput(e.Kind, p.Run)
	}
	outSum := sha256.Sum256(rec.Out)
	if rec.Status == p.Status && rec.TerminalEvents == p.TerminalEvents &&
		rec.Elapsed == p.ElapsedSeconds && hex.EncodeToString(outSum[:]) == p.OutputSHA256 &&
		sc.testPkg[p.Test] == p.Package {
		return AssessmentVerified, "held stream re-derives the recorded outcome", obsInput(e.Kind, p.Run, p.Test)
	}
	return AssessmentRejected, "held stream derives a different outcome than recorded", obsInput(e.Kind, p.Run, p.Test)
}

// verifyTestRun re-derives the run-level counts from the held
// stream — the same independent check as per-case results.
func (v *ObservationVerifier) verifyTestRun(e *Event) (string, string, string) {
	var p testRunRecord
	if err := json.Unmarshal(e.Payload, &p); err != nil || p.StreamSHA256 == "" {
		return AssessmentRejected, "test_run payload carries no stream digest", obsInput(e.Kind, "malformed")
	}
	raw, ok := v.heldStream(p.StreamSHA256)
	if !ok {
		return AssessmentUnverified, "stream bytes not held — counts cannot be independently derived", obsInput(e.Kind, p.StreamSHA256)
	}
	sc := scanStream(raw)
	if len(sc.findings) > 0 {
		return AssessmentRejected, "held stream fails the canonical lifecycle", obsInput(e.Kind, p.StreamSHA256)
	}
	var passed, failed, skipped, benched int
	pkgs := map[string]bool{}
	for _, name := range sc.order {
		pkgs[sc.testPkg[name]] = true
		switch sc.cases[name].Status {
		case "pass":
			passed++
		case "fail":
			failed++
		case "skip":
			skipped++
		case benchAction:
			benched++
		}
	}
	if passed != p.Passed || failed != p.Failed || skipped != p.Skipped ||
		benched != p.Benched || len(sc.order) != p.Tests || len(pkgs) != len(p.Packages) {
		return AssessmentRejected, "held stream derives different run counts than recorded", obsInput(e.Kind, p.StreamSHA256)
	}
	for _, pkg := range p.Packages {
		if !pkgs[pkg] {
			return AssessmentRejected, "recorded package set disagrees with held stream", obsInput(e.Kind, p.StreamSHA256)
		}
	}
	return AssessmentVerified, "held stream re-derives the recorded run", obsInput(e.Kind, p.StreamSHA256)
}

// verifyExperiment: the experiment record's declared source digest
// must resolve to held bytes that re-parse into the recorded fields.
// A record whose source the store cannot produce is unverifiable;
// one whose held source disagrees with the recorded claim is
// rejected.
func (v *ObservationVerifier) verifyExperiment(e *Event) (string, string, string) {
	var p experimentRecord
	if err := json.Unmarshal(e.Payload, &p); err != nil || p.ExperimentID == "" {
		return AssessmentRejected, "experiment payload carries no experiment identity", obsInput(e.Kind, "malformed")
	}
	src := p.SourceSHA
	if src == "" {
		src = e.Correlation
	}
	if src == "" || v.Content == nil {
		return AssessmentUnverified, "experiment declares no held source bytes", obsInput(e.Kind, src)
	}
	raw, err := v.Content.Read(src)
	if err != nil {
		return AssessmentUnverified, "source bytes not held — record cannot be independently checked", obsInput(e.Kind, src)
	}
	var held experimentRecord
	if err := json.Unmarshal(raw, &held); err != nil {
		return AssessmentRejected, "held source does not re-parse as an experiment record", obsInput(e.Kind, src)
	}
	// Re-apply the ingester's own field normalization so the
	// comparison is field-for-field, not serialization luck.
	if held.ExperimentID == "" {
		held.ExperimentID = firstFieldRaw(raw, "id", "name", "experiment")
	}
	if held.Timestamp == "" {
		held.Timestamp = firstFieldRaw(raw, "ts", "time", "created_at")
	}
	// The recorded claim must agree with the held source on every
	// field the source carries — file/source_sha are the ingest
	// path's own annotations, checked separately.
	p.SourceSHA, p.File = "", ""
	if hp, err := json.Marshal(held); err != nil || !bytes.Equal(hp, mustMarshal(p)) {
		return AssessmentRejected, "held source disagrees with the recorded experiment fields", obsInput(e.Kind, src)
	}
	return AssessmentVerified, "held source re-derives the recorded claim", obsInput(e.Kind, src)
}

// heldStream returns the stored stream bytes for a digest, or
// reports them absent — absent content is unverifiable, never an
// error that could be laundered into a verdict.
func (v *ObservationVerifier) heldStream(digest string) ([]byte, bool) {
	if v.Content == nil || digest == "" {
		return nil, false
	}
	raw, err := v.Content.Read(digest)
	if err != nil {
		return nil, false
	}
	return raw, true
}

// obsInput digests the corroborating evidence identity set so an
// assessment names exactly which inputs produced it.
func obsInput(kind string, parts ...string) string {
	sort.Strings(parts)
	h := sha256.New()
	h.Write([]byte(observationInputDomain))
	h.Write([]byte(kind))
	for _, p := range parts {
		h.Write([]byte{0})
		h.Write([]byte(p))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func mustMarshal(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return b
}
