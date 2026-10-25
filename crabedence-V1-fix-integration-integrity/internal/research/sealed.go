package research

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"

	"github.com/openclaw/crabbox/internal/dream"
	"github.com/openclaw/crabbox/internal/evidence"
	"github.com/openclaw/crabbox/internal/history"
)

// Sealed evaluation: the independent-outcome side of INV-5. A
// learning claim is only as strong as the outcomes it is scored on,
// so holdout truth arrives as evaluator-signed seals under a
// pre-registered eval contract — never as self-reported numbers.
// The eval names its session, its envelope, its baseline, its
// required delta, and exactly which evaluator keys may vouch; all of
// it is fixed before any outcome is revealed, so moving the
// goalposts requires a new contract identity.
const (
	// outcomeSealDomain separates evaluator seals from every other
	// signature in the system.
	outcomeSealDomain = "crabedence.research-eval-outcome.v1\x00"
	// evalDigestDomain separates eval spec/report/task digests.
	evalDigestDomain = "crabedence.research-eval.v1\x00"
)

// EvalSpec is the pre-registered evaluation contract: the session,
// the envelope the policies are bound to, the baseline arm, the
// required verified gain, the evidence floor, and the evaluator
// fingerprints allowed to seal outcomes. Changing any clause is a
// different contract — its digest changes and prior seals stop
// resolving under it.
type EvalSpec struct {
	EvalID      string   `json:"eval_id"`
	EnvelopeSHA string   `json:"envelope_sha256"`
	BaselineArm int      `json:"baseline_arm"`
	MinDelta    float64  `json:"min_delta"`
	MinEvidence int      `json:"min_evidence"`
	Evaluators  []string `json:"evaluators"`
}

// EvaluatorSet projects the spec's declared evaluators into the
// membership map verification consults.
func (s *EvalSpec) EvaluatorSet() map[string]bool {
	out := make(map[string]bool, len(s.Evaluators))
	for _, fp := range s.Evaluators {
		out[fp] = true
	}
	return out
}

// EnvelopeDigest is the eval's binding to the declared arm space —
// an eval scored under a different envelope is a different claim.
func EnvelopeDigest(env *dream.Envelope) string {
	h := sha256.New()
	h.Write([]byte(evalDigestDomain))
	h.Write([]byte("envelope"))
	for _, a := range env.Arms {
		fmt.Fprintf(h, "\narm|%d|%d|%g|%d|%d", a.TimeoutSeconds, a.MemoryMB, a.CPUs, a.DiskMB, a.MaxOutputBytes)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// SpecDigest is the contract's content identity — the value seals
// and reports bind so criteria cannot drift mid-evaluation.
func SpecDigest(s *EvalSpec) string {
	h := sha256.New()
	h.Write([]byte(evalDigestDomain))
	h.Write([]byte("spec"))
	raw, _ := json.Marshal(s)
	h.Write(raw)
	return hex.EncodeToString(h.Sum(nil))
}

// ValidateSpec checks the contract is complete, self-consistent,
// and pinned to this envelope. An evaluator set is mandatory — an
// eval naming no trusted evaluator can verify nothing, so absence
// fails closed rather than admitting every self-seal.
func ValidateSpec(s *EvalSpec, env *dream.Envelope) error {
	if s == nil {
		return fmt.Errorf("missing eval spec")
	}
	if s.EvalID == "" {
		return fmt.Errorf("eval spec names no session")
	}
	if s.EnvelopeSHA != EnvelopeDigest(env) {
		return fmt.Errorf("eval spec binds a different envelope")
	}
	if s.BaselineArm < 0 || s.BaselineArm >= len(env.Arms) {
		return fmt.Errorf("baseline arm %d outside the envelope", s.BaselineArm)
	}
	if s.MinDelta < 0 {
		return fmt.Errorf("min_delta negative — a regression floor is not a criterion")
	}
	if s.MinEvidence < 0 {
		return fmt.Errorf("min_evidence negative")
	}
	if len(s.Evaluators) == 0 {
		return fmt.Errorf("eval spec trusts no evaluators — nothing can seal outcomes")
	}
	for _, fp := range s.Evaluators {
		if fp == "" {
			return fmt.Errorf("evaluator set contains an empty fingerprint")
		}
	}
	return nil
}

// TaskDigest is a holdout task's canonical identity — task id plus
// the full feature vector, so the leakage check compares task
// *families*, not just names.
func TaskDigest(t dream.Task) string {
	h := sha256.New()
	h.Write([]byte(evalDigestDomain))
	h.Write([]byte("task"))
	h.Write([]byte{0})
	h.Write([]byte(t.ID))
	h.Write([]byte(featureDigest(t)))
	return hex.EncodeToString(h.Sum(nil))
}

// featureDigest digests the task's feature vector alone — the
// family identity. Two tasks with different ids but identical
// features are the same family, which is what the leakage check
// must catch.
func featureDigest(t dream.Task) string {
	h := sha256.New()
	h.Write([]byte(evalDigestDomain))
	h.Write([]byte("family"))
	feat := make([]string, 0, len(t.Features))
	for k, v := range t.Features {
		feat = append(feat, k+"="+v)
	}
	sort.Strings(feat)
	for _, f := range feat {
		h.Write([]byte{0})
		h.Write([]byte(f))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// OutcomeSeal is the evaluator's signed attestation that one holdout
// task's chosen arm realized exactly this outcome. The seal binds
// the eval session, the task's canonical identity, the arm, the
// outcome, and a unique nonce — the nonce is what makes replay
// detectable, since two honest seals for the same arm carry
// different nonces.
type OutcomeSeal struct {
	EvalID     string `json:"eval_id"`
	TaskDigest string `json:"task_digest"`
	Arm        int    `json:"arm"`
	Success    bool   `json:"success"`
	DurationMS int64  `json:"duration_ms"`
	Nonce      string `json:"nonce"`
	Signer     string `json:"signer"`
	PublicKey  string `json:"public_key"`
	Signature  string `json:"signature"`
}

// sealFields is the signed field tuple, in order.
func (s *OutcomeSeal) sealFields() []string {
	return []string{s.EvalID, s.TaskDigest, strconv.Itoa(s.Arm),
		strconv.FormatBool(s.Success), strconv.FormatInt(s.DurationMS, 10), s.Nonce}
}

// SealOutcome mints a signed seal for one arm's realized outcome.
func SealOutcome(signer *evidence.Signer, spec *EvalSpec, task dream.Task, arm int, o dream.Outcome, nonce string) (*OutcomeSeal, error) {
	seal := &OutcomeSeal{
		EvalID:     spec.EvalID,
		TaskDigest: TaskDigest(task),
		Arm:        arm,
		Success:    o.Success,
		DurationMS: o.DurationMS,
		Nonce:      nonce,
		Signer:     signer.Fingerprint(),
		PublicKey:  base64.StdEncoding.EncodeToString(signer.PublicKey()),
	}
	sig, err := signer.SignRecord(outcomeSealDomain, seal.sealFields()...)
	if err != nil {
		return nil, err
	}
	seal.Signature = sig
	return seal, nil
}

// VerifyOutcomeSeal checks a seal against the contract: the session
// must match, the signer must be a pre-registered evaluator whose
// fingerprint binds the embedded key, the task identity must match,
// and the signature must verify. A seal is never trusted from its
// own contents — every clause resolves against the spec.
func VerifyOutcomeSeal(seal *OutcomeSeal, spec *EvalSpec, taskDigest string) error {
	if seal.EvalID != spec.EvalID {
		return fmt.Errorf("seal belongs to eval %q, not %q — a cross-session replay", seal.EvalID, spec.EvalID)
	}
	if seal.TaskDigest != taskDigest {
		return fmt.Errorf("seal binds task %q, not this task", seal.TaskDigest)
	}
	if seal.Nonce == "" {
		return fmt.Errorf("seal carries no nonce — replay protection absent")
	}
	if !spec.EvaluatorSet()[seal.Signer] {
		return fmt.Errorf("seal signer %q is not a registered evaluator", seal.Signer)
	}
	pub, err := base64.StdEncoding.DecodeString(seal.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("seal public key malformed")
	}
	if evidence.Fingerprint(ed25519.PublicKey(pub)) != seal.Signer {
		return fmt.Errorf("seal public key does not match its declared signer")
	}
	if err := evidence.VerifyRecordSignature(ed25519.PublicKey(pub), outcomeSealDomain, seal.Signature, seal.sealFields()...); err != nil {
		return fmt.Errorf("seal signature invalid: %w", err)
	}
	return nil
}

// SealedEvalTask is one holdout task plus the sealed realized
// outcome of every envelope arm — the equal-budget requirement in
// concrete form: every variant is scored on the same attested
// outcome set, so an arm without a seal is incomplete evidence, not
// a zero.
type SealedEvalTask struct {
	Task  dream.Task     `json:"task"`
	Seals []*OutcomeSeal `json:"seals"`
}

// SealedEvalReport is the verified evaluation result: per-variant
// scores over sealed outcomes, the verified delta over the declared
// baseline, and a report digest binding every scored claim — the
// identity a promotion request must name.
type SealedEvalReport struct {
	SpecDigest        string         `json:"spec_digest"`
	EvalID            string         `json:"eval_id"`
	TrainRecords      int            `json:"train_records"`
	TrustedRecords    int            `json:"trusted_records"`
	HoldoutTasks      int            `json:"holdout_tasks"`
	Scores            []VariantScore `json:"scores"`
	DeltaOverBaseline float64        `json:"delta_over_baseline"`
	ReportDigest      string         `json:"report_digest"`
}

// EvaluateSealed runs the independently verified evaluation. Every
// scored outcome is a signature-verified seal under the spec's
// evaluator set; the holdout cannot overlap the train window's task
// families; each seal is consumed exactly once. Any violation —
// forged seal, replayed nonce, leaking task family, incomplete seal
// coverage, wrong session — fails the whole evaluation: a partially
// honest eval is a dishonest eval.
func EvaluateSealed(env *dream.Envelope, spec *EvalSpec, train []*history.Event, trusted map[string]bool, holdout []*SealedEvalTask) (*SealedEvalReport, error) {
	if err := ValidateSpec(spec, env); err != nil {
		return nil, err
	}
	trainRecords, _ := dream.RecordsFromEvents(env, train)

	// Leakage: the holdout must share no task family with anything
	// the policies trained on. Identity match is the obvious leak;
	// an identical feature vector is the same family under a new
	// name — a contaminated eval is invalid, not merely suspect.
	trainFamilies := map[string]bool{}
	trainIDs := map[string]bool{}
	for _, r := range trainRecords {
		trainFamilies[featureDigest(r.Task)] = true
		trainIDs[r.Task.ID] = true
	}

	// Seal verification, completeness, and replay checks — all
	// before any scoring, so a forged or replayed outcome can never
	// contribute to a claim.
	type scoredTask struct {
		task     dream.Task
		outcomes []dream.Outcome
	}
	scored := make([]scoredTask, 0, len(holdout))
	seenNonces := map[string]bool{}
	seenSeals := map[string]bool{}
	for _, h := range holdout {
		td := TaskDigest(h.Task)
		if trainFamilies[featureDigest(h.Task)] || trainIDs[h.Task.ID] {
			return nil, fmt.Errorf("eval leakage: holdout task %q shares a train-window task family", h.Task.ID)
		}
		if len(h.Seals) != len(env.Arms) {
			return nil, fmt.Errorf("holdout task %q carries %d seals, want one per arm (%d) — incomplete coverage is unusable evidence", h.Task.ID, len(h.Seals), len(env.Arms))
		}
		outcomes := make([]dream.Outcome, len(env.Arms))
		armed := make([]bool, len(env.Arms))
		for _, seal := range h.Seals {
			if err := VerifyOutcomeSeal(seal, spec, td); err != nil {
				return nil, fmt.Errorf("holdout task %q: %w", h.Task.ID, err)
			}
			if seal.Arm < 0 || seal.Arm >= len(env.Arms) {
				return nil, fmt.Errorf("holdout task %q: seal names arm %d outside the envelope", h.Task.ID, seal.Arm)
			}
			if armed[seal.Arm] {
				return nil, fmt.Errorf("holdout task %q: duplicate seal for arm %d", h.Task.ID, seal.Arm)
			}
			if seenNonces[seal.Nonce] {
				return nil, fmt.Errorf("seal nonce %q replayed — each outcome may be sealed once", seal.Nonce)
			}
			sealRaw, _ := json.Marshal(seal)
			sum := sha256.Sum256(sealRaw)
			if seenSeals[hex.EncodeToString(sum[:])] {
				return nil, fmt.Errorf("identical seal replayed on task %q", h.Task.ID)
			}
			seenNonces[seal.Nonce] = true
			seenSeals[hex.EncodeToString(sum[:])] = true
			armed[seal.Arm] = true
			outcomes[seal.Arm] = dream.Outcome{Success: seal.Success, DurationMS: seal.DurationMS}
		}
		scored = append(scored, scoredTask{task: h.Task, outcomes: outcomes})
	}

	// Fit policies exactly as the unsealed eval does — identical
	// training paths, identical scoring, so the only difference is
	// the evidence's provenance.
	trustedRecords := trustedOnly(trainRecords, trusted)
	adaptive, err := dream.FitPolicy(env, trainRecords)
	if err != nil {
		return nil, fmt.Errorf("fit adaptive: %w", err)
	}
	trustedFit, err := dream.FitPolicy(env, trustedRecords)
	if err != nil {
		return nil, fmt.Errorf("fit trusted: %w", err)
	}
	policies := map[Variant]dream.Policy{
		VariantBaseline:    dream.StaticPolicy{Arm: spec.BaselineArm},
		VariantAdaptive:    adaptive,
		VariantTrustedOnly: trustedFit,
		VariantController:  trustedFit,
	}
	rep := &SealedEvalReport{
		SpecDigest:     SpecDigest(spec),
		EvalID:         spec.EvalID,
		TrainRecords:   len(trainRecords),
		TrustedRecords: len(trustedRecords),
		HoldoutTasks:   len(scored),
	}
	for _, v := range Variants {
		sc := VariantScore{Variant: v}
		for _, t := range scored {
			arm := policies[v].Choose(env, t.task)
			if arm < 0 || arm >= len(t.outcomes) {
				sc.Skipped++
				continue
			}
			o := t.outcomes[arm]
			sc.Scored++
			if o.Success {
				sc.Successes++
			}
			sc.RewardSum += env.Reward(arm, o)
		}
		if sc.Scored > 0 {
			sc.MeanReward = sc.RewardSum / float64(sc.Scored)
		}
		rep.Scores = append(rep.Scores, sc)
	}
	var base, ctrl float64
	var baseN, ctrlN int
	for _, sc := range rep.Scores {
		switch sc.Variant {
		case VariantBaseline:
			base, baseN = sc.RewardSum, sc.Scored
		case VariantController:
			ctrl, ctrlN = sc.RewardSum, sc.Scored
		}
	}
	if baseN > 0 && ctrlN > 0 {
		rep.DeltaOverBaseline = ctrl/float64(ctrlN) - base/float64(baseN)
	}
	rep.ReportDigest = rep.digest()
	return rep, nil
}

// digest binds the report's scored content — the identity a
// promotion must cite so the claim it names is exactly the claim
// the evidence produced.
func (r *SealedEvalReport) digest() string {
	h := sha256.New()
	h.Write([]byte(evalDigestDomain))
	h.Write([]byte("report"))
	h.Write([]byte{0})
	h.Write([]byte(r.SpecDigest))
	h.Write([]byte{0})
	h.Write([]byte(r.EvalID))
	fmt.Fprintf(h, "\ntrain=%d trusted=%d holdout=%d delta=%.10g",
		r.TrainRecords, r.TrustedRecords, r.HoldoutTasks, r.DeltaOverBaseline)
	for _, sc := range r.Scores {
		fmt.Fprintf(h, "\n%s scored=%d skipped=%d reward=%.10g mean=%.10g ok=%d",
			sc.Variant, sc.Scored, sc.Skipped, sc.RewardSum, sc.MeanReward, sc.Successes)
	}
	return hex.EncodeToString(h.Sum(nil))
}
