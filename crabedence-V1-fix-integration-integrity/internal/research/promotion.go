package research

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/openclaw/crabbox/internal/dream"
	"github.com/openclaw/crabbox/internal/evidence"
	"github.com/openclaw/crabbox/internal/experience"
	"github.com/openclaw/crabbox/internal/history"
)

// promotionDomain separates operator promotion signatures from
// every other record signature in the system.
const promotionDomain = "crabedence.research-promotion.v1\x00"

// proposalDigestDomain separates proposal content digests.
const proposalDigestDomain = "crabedence.research-proposal.v1\x00"

// ── Immutable proposals ─────────────────────────────────────────
//
// A proposal the system can silently edit is a proposal the system
// can promote under a name it did not earn. Proposals therefore
// land as content-addressed decision events: the dedupe key IS the
// canonical content digest, so a mutated record either fails to
// append under its claimed identity or reads back detectably
// inconsistent.

// ProposalDigest is the canonical content identity of a proposal:
// every field that describes what was proposed and why, hashed
// under the proposal domain. Two proposals differing in any
// clause are different proposals.
func ProposalDigest(p *Proposal) string {
	h := sha256.New()
	h.Write([]byte(proposalDigestDomain))
	raw, _ := json.Marshal(p)
	h.Write(raw)
	return hex.EncodeToString(h.Sum(nil))
}

// RecordProposal appends a proposal to memory keyed on its own
// content digest. The event is advisory — it records what was
// proposed; it cannot execute, sign, or promote anything.
func RecordProposal(s *history.Store, p *Proposal) (*history.Event, error) {
	if p == nil {
		return nil, fmt.Errorf("missing proposal")
	}
	d := ProposalDigest(p)
	payload, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	subject := ""
	if p.Signature != nil {
		subject = p.Signature.Subject
	}
	appended, err := s.Append(&history.Event{
		DedupeKey: "proposal:" + d,
		Kind:      history.KindDecision,
		Subject:   subject,
		Source:    "research",
		Payload:   payload,
	})
	if err != nil {
		return nil, err
	}
	if len(appended) == 0 {
		return nil, fmt.Errorf("proposal already recorded")
	}
	return appended[0], nil
}

// VerifyProposalRecord re-derives a stored proposal event's digest
// and compares it to the dedupe identity the event was committed
// under — a tampered record fails its own name.
func VerifyProposalRecord(e *history.Event) error {
	if e == nil || e.Kind != history.KindDecision || len(e.DedupeKey) < len("proposal:") || e.DedupeKey[:len("proposal:")] != "proposal:" {
		return fmt.Errorf("not a recorded proposal")
	}
	var p Proposal
	if err := json.Unmarshal(e.Payload, &p); err != nil {
		return fmt.Errorf("proposal payload does not re-parse")
	}
	if e.DedupeKey != "proposal:"+ProposalDigest(&p) {
		return fmt.Errorf("proposal record mutated — content no longer matches its committed identity")
	}
	return nil
}

// ── Experiment budgets ──────────────────────────────────────────
//
// Exploration is bounded twice: the envelope bounds WHAT may be
// tried, and the budget bounds HOW MUCH a task family may consume.
// The used count is derived from the durable experiment record —
// a restart cannot reset it, and a ledger that cannot produce the
// trial events never inflates the allowance.

// ExperimentBudget bounds one task family's realized trials.
// MaxTrials is the total number of trial records the family may
// accumulate; the envelope still bounds each trial's arm.
type ExperimentBudget struct {
	TaskFamily string `json:"task_family"`
	MaxTrials  int    `json:"max_trials"`
}

// Validate checks the budget is a real bound, not an open door.
func (b *ExperimentBudget) Validate() error {
	if b == nil || b.TaskFamily == "" {
		return fmt.Errorf("budget names no task family")
	}
	if b.MaxTrials <= 0 {
		return fmt.Errorf("budget max_trials must be positive — zero is no exploration at all")
	}
	return nil
}

// RecordTrial commits one realized trial to the durable experiment
// record. The dedupe key binds family, arm, and the outcome's own
// digest, so a retried record lands once and a fabricated extra
// trial cannot reuse a sibling's identity.
func RecordTrial(s *history.Store, family string, arm int, outcomeDigest string, payload json.RawMessage) error {
	if family == "" || outcomeDigest == "" || len(payload) == 0 {
		return fmt.Errorf("trial requires family, outcome digest, and payload")
	}
	if !json.Valid(payload) {
		return fmt.Errorf("trial payload is not valid JSON")
	}
	_, err := s.Append(&history.Event{
		DedupeKey: "trial:" + family + ":" + strconv.Itoa(arm) + ":" + outcomeDigest,
		Kind:      history.KindExperiment,
		Subject:   family,
		Source:    "research-trial",
		Payload:   payload,
	})
	return err
}

// TrialsUsed counts a family's recorded trials — the durable,
// restart-safe consumption figure.
func TrialsUsed(s *history.Store, family string) (int, error) {
	events, err := s.Query(history.QueryOpts{Kinds: []string{history.KindExperiment}, Subject: family})
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range events {
		if len(e.DedupeKey) > len("trial:") && e.DedupeKey[:len("trial:")] == "trial:" {
			n++
		}
	}
	return n, nil
}

// PlanBudgeted is Plan under a declared budget: every clause of
// Plan holds, plus an experiment decision requires a remaining
// trial. An exhausted budget does not delete the proposal — it is
// recorded with decision "budget" so the refusal is auditable,
// while nothing beyond the bound is ever proposed.
func PlanBudgeted(g *experience.Graph, env *dream.Envelope, fit Estimator, task dream.Task, tried map[int]bool, budget *ExperimentBudget, used int) []*Proposal {
	ps := Plan(g, env, fit, task, tried)
	if budget == nil {
		return ps
	}
	remaining := budget.MaxTrials - used
	for _, p := range ps {
		if p.Decision != decideExperiment {
			continue
		}
		if remaining <= 0 {
			p.Decision = "budget"
			p.Experiment = nil
			p.Reason = fmt.Sprintf("experiment budget exhausted for %s: %d of %d trials consumed — further trials require a renewed operator budget",
				budget.TaskFamily, used, budget.MaxTrials)
			continue
		}
		remaining--
	}
	return ps
}

// ── Operator-signed promotion ───────────────────────────────────
//
// INV-5: research cannot self-promote. The eval may prove a real,
// sealed, verified gain and promotion is STILL a separate operator
// act — a signature over the proposal it adopts, the report that
// proves it, and the trust basis it stood on, from a key the
// operator trust set names. Nothing the request carries is
// trusted; every field is re-checked against the records it binds.

// PromotionRequest is the operator's signed adoption decision.
// Each field is a binding, not a claim: the digests must match the
// records, the delta must match the sealed report, and the basis
// must meet the spec's floor.
type PromotionRequest struct {
	ProposalDigest   string  `json:"proposal_digest"`
	EvalReportDigest string  `json:"eval_report_digest"`
	ClaimedDelta     float64 `json:"claimed_delta"`
	RealizedOutcomes int     `json:"realized_outcomes"`
	UntrustedNodes   int     `json:"untrusted_nodes"`
	Operator         string  `json:"operator"`
	PublicKey        string  `json:"public_key"`
	Signature        string  `json:"signature"`
}

// promotionFields is the signed field tuple, in order.
func (r *PromotionRequest) promotionFields() []string {
	return []string{r.ProposalDigest, r.EvalReportDigest,
		strconv.FormatFloat(r.ClaimedDelta, 'g', -1, 64),
		strconv.Itoa(r.RealizedOutcomes), strconv.Itoa(r.UntrustedNodes)}
}

// SignPromotion signs the request — the operator's key binds every
// claim it carries.
func SignPromotion(signer *evidence.Signer, r *PromotionRequest) error {
	r.Operator = signer.Fingerprint()
	r.PublicKey = base64.StdEncoding.EncodeToString(signer.PublicKey())
	sig, err := signer.SignRecord(promotionDomain, r.promotionFields()...)
	if err != nil {
		return err
	}
	r.Signature = sig
	return nil
}

// DecidePromotion evaluates a signed promotion request against the
// sealed eval report and the recorded proposal. It returns a
// refusal reason or "" when promotion is allowed. The checks run
// in fail-closed order: signature first (an unverifiable request
// is refused before its claims are even read), then the bindings,
// then the evidence floor.
func DecidePromotion(r *PromotionRequest, operators map[string]bool, report *SealedEvalReport, proposalDigest string, spec *EvalSpec) string {
	// 1. Signature: the request must be signed by a key the operator
	// trust set names — unsigned and unauthorized signatures are
	// refused identically at the boundary.
	if r == nil {
		return "missing promotion request"
	}
	if r.Signature == "" {
		return "promotion requires an operator signature"
	}
	if len(operators) == 0 {
		return "no operator trust set — promotion cannot be authorized"
	}
	if !operators[r.Operator] {
		return fmt.Sprintf("operator %q is not authorized to promote", r.Operator)
	}
	pub, err := base64.StdEncoding.DecodeString(r.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return "operator public key malformed"
	}
	if evidence.Fingerprint(ed25519.PublicKey(pub)) != r.Operator {
		return "operator public key does not match the declared signer"
	}
	if err := evidence.VerifyRecordSignature(ed25519.PublicKey(pub), promotionDomain, r.Signature, r.promotionFields()...); err != nil {
		return fmt.Sprintf("operator signature invalid: %v", err)
	}

	// 2. Bindings: the request must name the sealed report and the
	// exact recorded proposal — a self-reported delta, a forged
	// report reference, or a mutated proposal all fail here.
	if report == nil || r.EvalReportDigest == "" || r.EvalReportDigest != report.ReportDigest {
		return "promotion binds no sealed evaluation — a self-reported outcome is not evidence"
	}
	if r.ProposalDigest == "" || r.ProposalDigest != proposalDigest {
		return "proposal digest does not match the recorded proposal — mutated or forged reference"
	}

	// 3. The claim must agree with the sealed evidence: claimed
	// delta equals the verified delta, and the verified delta
	// clears the pre-registered floor.
	if r.ClaimedDelta != report.DeltaOverBaseline {
		return fmt.Sprintf("claimed delta %.6g disagrees with the sealed evaluation's %.6g", r.ClaimedDelta, report.DeltaOverBaseline)
	}
	minDelta := 0.0001
	if spec != nil && spec.MinDelta > 0 {
		minDelta = spec.MinDelta
	}
	if report.DeltaOverBaseline < minDelta {
		return fmt.Sprintf("no verified advantage: sealed delta %.6g below required %.6g", report.DeltaOverBaseline, minDelta)
	}

	// 4. Evidence floor: enough realized outcomes and no untrusted
	// nodes in the basis — the same gate CheckPromotion enforces,
	// now over signed fields.
	minEv := 3
	if spec != nil && spec.MinEvidence > 0 {
		minEv = spec.MinEvidence
	}
	if r.RealizedOutcomes < minEv {
		return fmt.Sprintf("insufficient realized evidence: %d outcomes, need %d", r.RealizedOutcomes, minEv)
	}
	if r.UntrustedNodes > 0 {
		return fmt.Sprintf("%d memory nodes carry adverse verdicts — promotion requires a clean trust basis", r.UntrustedNodes)
	}
	return ""
}
