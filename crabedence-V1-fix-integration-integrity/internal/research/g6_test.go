package research

// G6 research-boundary fixtures. Test IDs match
// qualification/rc8-required-tests.json gate g6-research-boundary.
// Each test exercises the real sealed-eval / promotion path — no
// stubs: proposals record through the append-only store, outcomes
// verify under real Ed25519 signatures, and the operator gate is
// the same DecidePromotion production code calls.

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/openclaw/crabbox/internal/dream"
	"github.com/openclaw/crabbox/internal/evidence"
	"github.com/openclaw/crabbox/internal/experience"
	"github.com/openclaw/crabbox/internal/history"
)

func newSigner(t *testing.T) *evidence.Signer {
	t.Helper()
	s, err := evidence.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// testSpec builds a valid pre-registered eval contract over env,
// trusting the given evaluator fingerprints.
func testSpec(t *testing.T, env *dream.Envelope, evaluators ...string) *EvalSpec {
	t.Helper()
	if len(evaluators) == 0 {
		t.Fatal("spec needs at least one evaluator")
	}
	return &EvalSpec{
		EvalID:      "eval-1",
		EnvelopeSHA: EnvelopeDigest(env),
		BaselineArm: len(env.Arms) - 1,
		MinDelta:    0.0001,
		MinEvidence: 3,
		Evaluators:  append([]string(nil), evaluators...),
	}
}

// sealHoldout seals every arm of every holdout task under the
// evaluator — the equal-budget outcome set the eval scores.
func sealHoldout(t *testing.T, signer *evidence.Signer, spec *EvalSpec, tasks []dream.Task, outcomes map[string][]dream.Outcome) []*SealedEvalTask {
	t.Helper()
	var out []*SealedEvalTask
	for _, task := range tasks {
		armOutcomes := outcomes[task.ID]
		if armOutcomes == nil {
			t.Fatalf("no outcomes declared for task %q", task.ID)
		}
		st := &SealedEvalTask{Task: task}
		for arm, o := range armOutcomes {
			seal, err := SealOutcome(signer, spec, task, arm, o, task.ID+"-arm"+fmt.Sprint(arm))
			if err != nil {
				t.Fatal(err)
			}
			st.Seals = append(st.Seals, seal)
		}
		out = append(out, st)
	}
	return out
}

// evalFixture trains the adaptive variants to prefer the small arm
// (light tasks succeed under it, the big arm pays for headroom) and
// returns a sealed eval proving a verified delta.
func evalFixture(t *testing.T) (*dream.Envelope, *EvalSpec, *evidence.Signer, []*history.Event, []*SealedEvalTask) {
	t.Helper()
	env := testEnvelope(t)
	eval := newSigner(t)
	spec := testSpec(t, env, eval.Fingerprint())
	var train []*history.Event
	for i := 0; i < 6; i++ {
		train = append(train,
			execEvent(t, fmt.Sprintf("small-%d", i), "SUCCEEDED", 256, 1, 60, 512, 4096, int64(1000+i)),
			execEvent(t, fmt.Sprintf("big-%d", i), "SUCCEEDED", 1024, 2, 300, 2048, 16384, int64(2000+i)))
	}
	var tasks []dream.Task
	outcomes := map[string][]dream.Outcome{}
	for i := 0; i < 4; i++ {
		id := fmt.Sprintf("holdout-%d", i)
		tasks = append(tasks, dream.Task{ID: id, Features: map[string]string{
			"image": "img-b", "principal": "root", "argv0": "run.sh"}})
		outcomes[id] = []dream.Outcome{
			{Success: true, DurationMS: 500},
			{Success: true, DurationMS: 900},
		}
	}
	return env, spec, eval, train, sealHoldout(t, eval, spec, tasks, outcomes)
}

// TestEvalLeakageDetected: a holdout task sharing the train window's
// task identity or feature-family contaminates the eval — the whole
// evaluation is refused, not silently filtered.
func TestEvalLeakageDetected(t *testing.T) {
	env, spec, eval, train, holdout := evalFixture(t)

	if rep, err := EvaluateSealed(env, spec, train, nil, holdout); err != nil || rep == nil {
		t.Fatalf("clean sealed eval failed: rep=%v err=%v", rep, err)
	}

	// Identity leak: holdout task id is a train job.
	leakID := dream.Task{ID: "small-0", Features: map[string]string{"image": "img-x"}}
	bad := append(append([]*SealedEvalTask{}, holdout...), &SealedEvalTask{
		Task:  leakID,
		Seals: mustSeals(t, eval, spec, leakID, []dream.Outcome{{Success: true}, {Success: true}}),
	})
	if _, err := EvaluateSealed(env, spec, train, nil, bad); err == nil {
		t.Fatal("identity-leaking holdout accepted")
	}

	// Family leak: a different id but the exact feature vector of a
	// train task — the same family under a new name.
	var leaked *history.Event
	for _, e := range train {
		if e.Subject == "small-0" {
			leaked = e
		}
	}
	var p struct {
		Image     string   `json:"image"`
		Principal string   `json:"principal"`
		Argv      []string `json:"argv"`
	}
	if err := json.Unmarshal(leaked.Payload, &p); err != nil {
		t.Fatal(err)
	}
	familyLeak := dream.Task{ID: "renamed-task", Features: map[string]string{
		dream.FeatureImage:     p.Image,
		dream.FeaturePrincipal: p.Principal,
		dream.FeatureArgv0:     "run.sh",
	}}
	bad2 := append(append([]*SealedEvalTask{}, holdout...), &SealedEvalTask{
		Task:  familyLeak,
		Seals: mustSeals(t, eval, spec, familyLeak, []dream.Outcome{{Success: true}, {Success: true}}),
	})
	if _, err := EvaluateSealed(env, spec, train, nil, bad2); err == nil {
		t.Fatal("feature-family-leaking holdout accepted")
	}
}

func mustSeals(t *testing.T, signer *evidence.Signer, spec *EvalSpec, task dream.Task, outcomes []dream.Outcome) []*OutcomeSeal {
	t.Helper()
	var seals []*OutcomeSeal
	for arm, o := range outcomes {
		seal, err := SealOutcome(signer, spec, task, arm, o, task.ID+"-s"+fmt.Sprint(arm))
		if err != nil {
			t.Fatal(err)
		}
		seals = append(seals, seal)
	}
	return seals
}

// TestForgedOutcomeRejected: a seal whose outcome or signature was
// altered after signing, or signed by a non-evaluator key, fails
// verification and the evaluation is refused.
func TestForgedOutcomeRejected(t *testing.T) {
	env, spec, _, train, holdout := evalFixture(t)

	// Tampered outcome bytes under an otherwise valid-looking seal.
	forged := *holdout[0].Seals[0]
	forged.Success = !forged.Success
	bad := append([]*SealedEvalTask{}, holdout...)
	bad[0] = &SealedEvalTask{Task: bad[0].Task, Seals: append([]*OutcomeSeal{}, bad[0].Seals...)}
	bad[0].Seals[0] = &forged
	if _, err := EvaluateSealed(env, spec, train, nil, bad); err == nil {
		t.Fatal("forged seal outcome accepted")
	}

	// A valid signature from a key the spec never registered.
	rogue := newSigner(t)
	rogueSeal, err := SealOutcome(rogue, spec, holdout[0].Task, 0, dream.Outcome{Success: true}, "rogue-nonce")
	if err != nil {
		t.Fatal(err)
	}
	bad2 := append([]*SealedEvalTask{}, holdout...)
	bad2[0] = &SealedEvalTask{Task: bad2[0].Task, Seals: append([]*OutcomeSeal{}, bad2[0].Seals...)}
	bad2[0].Seals[0] = rogueSeal
	if _, err := EvaluateSealed(env, spec, train, nil, bad2); err == nil {
		t.Fatal("non-evaluator seal accepted")
	}
}

// TestReceiptReplayRejected: a seal consumed twice — same nonce, or a
// verbatim resubmission — or minted for a different eval session is
// a replay, and the evaluation refuses it.
func TestReceiptReplayRejected(t *testing.T) {
	env, spec, eval, train, holdout := evalFixture(t)

	// Same nonce on two different seals — a replayed outcome.
	dup := append([]*SealedEvalTask{}, holdout...)
	dup[0] = &SealedEvalTask{Task: dup[0].Task, Seals: append([]*OutcomeSeal{}, dup[0].Seals...)}
	reseal, err := SealOutcome(eval, spec, dup[0].Task, 0, dream.Outcome{Success: false, DurationMS: 1}, dup[1].Seals[0].Nonce)
	if err != nil {
		t.Fatal(err)
	}
	dup[0].Seals[0] = reseal
	if _, err := EvaluateSealed(env, spec, train, nil, dup); err == nil {
		t.Fatal("replayed seal nonce accepted")
	}

	// A seal minted under a different eval session — cross-session
	// replay of a legitimately signed outcome.
	other := &EvalSpec{
		EvalID: "eval-2", EnvelopeSHA: EnvelopeDigest(env), BaselineArm: spec.BaselineArm,
		MinDelta: spec.MinDelta, MinEvidence: spec.MinEvidence, Evaluators: spec.Evaluators,
	}
	crossSeal, err := SealOutcome(eval, other, holdout[0].Task, 0, dream.Outcome{Success: true}, "cross-1")
	if err != nil {
		t.Fatal(err)
	}
	bad := append([]*SealedEvalTask{}, holdout...)
	bad[0] = &SealedEvalTask{Task: bad[0].Task, Seals: append([]*OutcomeSeal{}, bad[0].Seals...)}
	bad[0].Seals[0] = crossSeal
	if _, err := EvaluateSealed(env, spec, train, nil, bad); err == nil {
		t.Fatal("cross-session seal replay accepted")
	}
}

// TestProposalImmutable: a recorded proposal's committed identity IS
// its content digest — mutating the stored record or substituting a
// different proposal under the same name is detected.
func TestProposalImmutable(t *testing.T) {
	s := openStore(t)
	p := &Proposal{
		Signature:  &Signature{Subject: "pkg/F", Count: 3, Trusted: true},
		Experiment: &Experiment{TaskID: "fam", Arm: 1, ArmParams: "x", Signature: "pkg/F", Why: "recurring"},
		Decision:   decideExperiment,
		Reason:     "verified signature, untried arm",
	}
	e, err := RecordProposal(s, p)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyProposalRecord(e); err != nil {
		t.Fatalf("recorded proposal failed self-verification: %v", err)
	}

	// Mutate the stored payload under the same committed identity —
	// the content no longer digests to its own name.
	var stored Proposal
	if err := json.Unmarshal(e.Payload, &stored); err != nil {
		t.Fatal(err)
	}
	stored.Experiment.Arm = 0 // retarget the arm after commitment
	mutPayload, _ := json.Marshal(stored)
	mutated := &history.Event{
		DedupeKey: e.DedupeKey, Kind: e.Kind, Subject: e.Subject,
		Source: e.Source, Payload: mutPayload,
	}
	if err := VerifyProposalRecord(mutated); err == nil {
		t.Fatal("mutated proposal verified under its original identity")
	}

	// A different proposal mints a different digest — substitution
	// under the recorded name fails.
	alt := *p
	alt.Reason = "rewritten rationale"
	if ProposalDigest(&alt) == ProposalDigest(p) {
		t.Fatal("mutated proposal digest identical to original")
	}
}

// TestPromotionRequiresOperatorSignature: a fully evidenced request
// without an operator signature is refused — evidence alone never
// promotes.
func TestPromotionRequiresOperatorSignature(t *testing.T) {
	env, spec, _, train, holdout := evalFixture(t)
	report, err := EvaluateSealed(env, spec, train, nil, holdout)
	if err != nil {
		t.Fatal(err)
	}
	s := openStore(t)
	prop := &Proposal{Signature: &Signature{Subject: "pkg/F", Trusted: true}, Decision: decideExperiment}
	rec, err := RecordProposal(s, prop)
	if err != nil {
		t.Fatal(err)
	}
	var rp Proposal
	if err := json.Unmarshal(rec.Payload, &rp); err != nil {
		t.Fatal(err)
	}
	op := newSigner(t)
	ops := map[string]bool{op.Fingerprint(): true}

	req := &PromotionRequest{
		ProposalDigest:   ProposalDigest(&rp),
		EvalReportDigest: report.ReportDigest,
		ClaimedDelta:     report.DeltaOverBaseline,
		RealizedOutcomes: 10,
	}
	// Unsigned: refused before any claim is even read.
	if r := DecidePromotion(req, ops, report, ProposalDigest(&rp), spec); r == "" {
		t.Fatal("unsigned promotion request allowed")
	}

	// Signed end-to-end success — proves the gate admits only on the
	// full conjunction, not vacuously.
	signed := *req
	if err := SignPromotion(op, &signed); err != nil {
		t.Fatal(err)
	}
	if r := DecidePromotion(&signed, ops, report, ProposalDigest(&rp), spec); r != "" {
		t.Fatalf("fully evidenced signed promotion refused: %s", r)
	}

	// No operator trust set at all: fail closed even when signed.
	if r := DecidePromotion(&signed, nil, report, ProposalDigest(&rp), spec); r == "" {
		t.Fatal("promotion allowed with no operator trust set")
	}
}

// TestNonAuthorizedPromotionRejected: a correctly formed signature
// from a key outside the operator trust set is refused — valid
// cryptography under the wrong authority is not authorization.
func TestNonAuthorizedPromotionRejected(t *testing.T) {
	env, spec, _, train, holdout := evalFixture(t)
	report, err := EvaluateSealed(env, spec, train, nil, holdout)
	if err != nil {
		t.Fatal(err)
	}
	s := openStore(t)
	prop := &Proposal{Signature: &Signature{Subject: "pkg/F", Trusted: true}, Decision: decideExperiment}
	rec, err := RecordProposal(s, prop)
	if err != nil {
		t.Fatal(err)
	}
	var rp Proposal
	if err := json.Unmarshal(rec.Payload, &rp); err != nil {
		t.Fatal(err)
	}
	op := newSigner(t)
	rogue := newSigner(t)
	req := &PromotionRequest{
		ProposalDigest:   ProposalDigest(&rp),
		EvalReportDigest: report.ReportDigest,
		ClaimedDelta:     report.DeltaOverBaseline,
		RealizedOutcomes: 10,
	}
	if err := SignPromotion(rogue, req); err != nil {
		t.Fatal(err)
	}
	// The trust set names the operator — not the rogue signer.
	if r := DecidePromotion(req, map[string]bool{op.Fingerprint(): true}, report, ProposalDigest(&rp), spec); r == "" {
		t.Fatal("non-authorized operator signature allowed promotion")
	}
}

// TestSelfReportedDeltaInsufficient: a signed request carrying a
// positive delta but binding no sealed report — or a report it did
// not earn — is refused. The claim is only what the sealed evidence
// proves.
func TestSelfReportedDeltaInsufficient(t *testing.T) {
	env, spec, _, train, holdout := evalFixture(t)
	report, err := EvaluateSealed(env, spec, train, nil, holdout)
	if err != nil {
		t.Fatal(err)
	}
	s := openStore(t)
	prop := &Proposal{Signature: &Signature{Subject: "pkg/F", Trusted: true}, Decision: decideExperiment}
	rec, err := RecordProposal(s, prop)
	if err != nil {
		t.Fatal(err)
	}
	var rp Proposal
	if err := json.Unmarshal(rec.Payload, &rp); err != nil {
		t.Fatal(err)
	}
	op := newSigner(t)
	ops := map[string]bool{op.Fingerprint(): true}

	for _, tc := range []struct {
		name   string
		mutate func(*PromotionRequest)
	}{
		{"no report bound", func(r *PromotionRequest) { r.EvalReportDigest = "" }},
		{"foreign report", func(r *PromotionRequest) { r.EvalReportDigest = "deadbeef" }},
	} {
		req := &PromotionRequest{
			ProposalDigest: ProposalDigest(&rp), EvalReportDigest: report.ReportDigest,
			ClaimedDelta: 0.75, RealizedOutcomes: 50,
		}
		tc.mutate(req)
		if err := SignPromotion(op, req); err != nil {
			t.Fatal(err)
		}
		if r := DecidePromotion(req, ops, report, ProposalDigest(&rp), spec); r == "" {
			t.Fatalf("%s: self-reported delta promoted", tc.name)
		}
	}
}

// TestFalseImprovementDetected: a claim whose signed delta disagrees
// with the sealed evidence — or whose sealed delta never cleared the
// floor — is refused; the report, not the request, states the gain.
func TestFalseImprovementDetected(t *testing.T) {
	env, spec, _, train, holdout := evalFixture(t)
	report, err := EvaluateSealed(env, spec, train, nil, holdout)
	if err != nil {
		t.Fatal(err)
	}
	if report.DeltaOverBaseline <= 0 {
		t.Fatalf("fixture produced no positive delta: %v", report.DeltaOverBaseline)
	}
	s := openStore(t)
	prop := &Proposal{Signature: &Signature{Subject: "pkg/F", Trusted: true}, Decision: decideExperiment}
	rec, err := RecordProposal(s, prop)
	if err != nil {
		t.Fatal(err)
	}
	var rp Proposal
	if err := json.Unmarshal(rec.Payload, &rp); err != nil {
		t.Fatal(err)
	}
	op := newSigner(t)
	ops := map[string]bool{op.Fingerprint(): true}

	// Inflated claim: the signature is genuine, the number is not
	// what the sealed eval produced.
	req := &PromotionRequest{
		ProposalDigest: ProposalDigest(&rp), EvalReportDigest: report.ReportDigest,
		ClaimedDelta: report.DeltaOverBaseline + 0.5, RealizedOutcomes: 10,
	}
	if err := SignPromotion(op, req); err != nil {
		t.Fatal(err)
	}
	if r := DecidePromotion(req, ops, report, ProposalDigest(&rp), spec); r == "" {
		t.Fatal("inflated delta claim promoted")
	}

	// Flat eval: the sealed outcomes give the adaptive variant's
	// chosen arm a failure — the verified delta is negative, so even
	// an honestly reported claim cannot promote.
	env2, spec2, eval2, train2, _ := evalFixture(t)
	flatTasks := []dream.Task{
		{ID: "flat-1", Features: map[string]string{"image": "img-c"}},
		{ID: "flat-2", Features: map[string]string{"image": "img-c"}},
	}
	flatOut := map[string][]dream.Outcome{}
	for _, ft := range flatTasks {
		// Adaptive prefers arm 0 (cheaper headroom on its global
		// mean); arm 0 fails on every flat task → delta < 0.
		flatOut[ft.ID] = []dream.Outcome{{Success: false, DurationMS: 500}, {Success: true, DurationMS: 500}}
	}
	flat, err := EvaluateSealed(env2, spec2, train2, nil, sealHoldout(t, eval2, spec2, flatTasks, flatOut))
	if err != nil {
		t.Fatal(err)
	}
	if flat.DeltaOverBaseline >= 0 {
		t.Fatalf("flat fixture produced positive delta %v — redesign the scenario", flat.DeltaOverBaseline)
	}
	req2 := &PromotionRequest{
		ProposalDigest: ProposalDigest(&rp), EvalReportDigest: flat.ReportDigest,
		ClaimedDelta: flat.DeltaOverBaseline, RealizedOutcomes: 10,
	}
	if err := SignPromotion(op, req2); err != nil {
		t.Fatal(err)
	}
	if r := DecidePromotion(req2, ops, flat, ProposalDigest(&rp), spec2); r == "" {
		t.Fatalf("zero-advantage promotion allowed (delta %v)", flat.DeltaOverBaseline)
	}
}

// TestUnverifiedEvidenceExcluded: unverified memory contributes
// nothing the gate counts — not to the trusted fit, and not to the
// promotion basis.
func TestUnverifiedEvidenceExcluded(t *testing.T) {
	env, spec, _, train, holdout := evalFixture(t)
	// Trust only the small-* jobs; the big-* executions stay
	// unassessed — they must not feed the trusted variant.
	trusted := map[string]bool{}
	for _, e := range train {
		if len(e.Subject) > 6 && e.Subject[:6] == "small-" {
			trusted[e.Subject] = true
		}
	}
	rep, err := EvaluateSealed(env, spec, train, trusted, holdout)
	if err != nil {
		t.Fatal(err)
	}
	if rep.TrustedRecords >= rep.TrainRecords {
		t.Fatalf("unverified records leaked into the trusted fit: %d/%d", rep.TrustedRecords, rep.TrainRecords)
	}
	var trustedScore *VariantScore
	for i := range rep.Scores {
		if rep.Scores[i].Variant == VariantTrustedOnly {
			trustedScore = &rep.Scores[i]
		}
	}
	if trustedScore == nil || trustedScore.Scored == 0 {
		t.Fatal("trusted variant scored nothing — trusted-only path broken")
	}

	// And the promotion basis: any adverse node refuses outright.
	op := newSigner(t)
	prop := &Proposal{Signature: &Signature{Subject: "pkg/F", Trusted: true}, Decision: decideExperiment}
	s := openStore(t)
	rec, err := RecordProposal(s, prop)
	if err != nil {
		t.Fatal(err)
	}
	var rp Proposal
	if err := json.Unmarshal(rec.Payload, &rp); err != nil {
		t.Fatal(err)
	}
	req := &PromotionRequest{
		ProposalDigest: ProposalDigest(&rp), EvalReportDigest: rep.ReportDigest,
		ClaimedDelta: rep.DeltaOverBaseline, RealizedOutcomes: 10, UntrustedNodes: 1,
	}
	if err := SignPromotion(op, req); err != nil {
		t.Fatal(err)
	}
	if r := DecidePromotion(req, map[string]bool{op.Fingerprint(): true}, rep, ProposalDigest(&rp), spec); r == "" {
		t.Fatal("promotion allowed over an untrusted basis")
	}
}

// TestBoundedExperimentBudget: experiment proposals are bounded by
// the declared budget AND the envelope — the controller proposes
// only while trials remain, and never outside the declared arms.
func TestBoundedExperimentBudget(t *testing.T) {
	s := openStore(t)
	trustSHA := history.TrustSetSHA256(map[string]bool{"fp": true})
	// Two verified failing signatures → two experiment proposals.
	for _, tc := range []struct{ key, subj string }{
		{"t:r1:F", "pkg/F"}, {"t:r1:G", "pkg/G"},
	} {
		appendEvent(t, s, tc.key, "test_result", tc.subj, 100, map[string]any{"status": "fail"})
		if err := s.RecordAssessment(&history.Assessment{
			SubjectKey: tc.key, Verifier: "v", RulesVersion: "observation-v1",
			TrustSetSHA: trustSHA, InputSHA: "in", Result: history.AssessmentVerified,
		}); err != nil {
			t.Fatal(err)
		}
	}
	g, err := experience.Reconstruct(s, trustSHA)
	if err != nil {
		t.Fatal(err)
	}
	env := testEnvelope(t)
	budget := &ExperimentBudget{TaskFamily: "fam", MaxTrials: 2}

	// used=1 → one proposal may spend the last trial; the other is
	// refused inside the same plan — the bound is on trials, not on
	// proposals considered.
	ps := PlanBudgeted(g, env, nil, dream.Task{ID: "fam"}, map[int]bool{}, budget, 1)
	var experiments, refused int
	for _, p := range ps {
		switch p.Decision {
		case decideExperiment:
			experiments++
			if p.Experiment.Arm < 0 || p.Experiment.Arm >= len(env.Arms) {
				t.Fatalf("proposal names arm %d outside the envelope", p.Experiment.Arm)
			}
		case "budget":
			refused++
		}
	}
	if experiments != 1 || refused != 1 {
		t.Fatalf("budget bound wrong: %d experiments, %d refused, want 1/1", experiments, refused)
	}
}

// TestBudgetExhaustionBounded: consumed trials are counted from the
// durable record — an exhausted budget survives a restart, and no
// proposal spends past it.
func TestBudgetExhaustionBounded(t *testing.T) {
	dir := t.TempDir()
	dbPath := dir + "/h.db"
	s, err := history.OpenStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	trustSHA := history.TrustSetSHA256(map[string]bool{"fp": true})
	appendEvent(t, s, "t:r1:F", "test_result", "pkg/F", 100, map[string]any{"status": "fail"})
	if err := s.RecordAssessment(&history.Assessment{
		SubjectKey: "t:r1:F", Verifier: "v", RulesVersion: "observation-v1",
		TrustSetSHA: trustSHA, InputSHA: "in", Result: history.AssessmentVerified,
	}); err != nil {
		t.Fatal(err)
	}
	// Two realized trials committed under the family.
	for i, dg := range []string{"aaaa", "bbbb"} {
		if err := RecordTrial(s, "fam", i, dg, json.RawMessage(`{"outcome":"ok"}`)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// Cold restore: the used count comes from the record, not
	// memory — a restart grants nothing back.
	s2, err := history.OpenStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	used, err := TrialsUsed(s2, "fam")
	if err != nil {
		t.Fatal(err)
	}
	if used != 2 {
		t.Fatalf("trials used %d after restart, want 2", used)
	}
	g, err := experience.Reconstruct(s2, trustSHA)
	if err != nil {
		t.Fatal(err)
	}
	ps := PlanBudgeted(g, testEnvelope(t), nil, dream.Task{ID: "fam"}, map[int]bool{},
		&ExperimentBudget{TaskFamily: "fam", MaxTrials: 2}, used)
	for _, p := range ps {
		if p.Decision == decideExperiment {
			t.Fatalf("experiment proposed past exhausted budget: %+v", p)
		}
		if p.Decision != "budget" && p.Decision != decideResolved && p.Decision != decideUntrusted {
			t.Fatalf("unexpected decision %q", p.Decision)
		}
	}
}
