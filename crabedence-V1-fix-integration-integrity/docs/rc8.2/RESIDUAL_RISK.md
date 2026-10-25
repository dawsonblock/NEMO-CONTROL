# RC8.2 Residual-Risk Register

Every entry is a known limitation of the `0.55.0-rc8.2-dev` candidate
(commit `32654ced`, artifact sha256 `57f4f6a6…`). NONE may be read as
acceptance of a hidden defect — each is a documented boundary between
what is tested and what remains to be qualified.

## RR-01 — Sandbox conditional deletion is not atomic (P1)

- **State:** `msb` v0.7.8 exposes no identity-conditional delete;
  `msb rm` resolves a name/label and destroys unconditionally.
- **Mitigation shipped:** deterministic nonce-bound handles, label +
  boot-generation verification before removal, post-removal bounded
  verification, `REMOVAL_UNCERTAIN` on any unproven step, durable
  cleanup obligations, and the enforced exclusive-namespace mode
  (`-msb-namespace` / `SANDBOX_EXECUTOR_MSB_NAMESPACE`).
- **Residual:** a same-namespace substitution can still land inside
  the runtime's own resolve-then-delete window if the runtime itself
  is compromised or the name space is shared. High-assurance cleanup
  claims hold **only** under a deployment-exclusive namespace;
  shared-namespace deployments are NO-GO.
- **Exit:** a runtime release offering atomic conditional delete, or a
  trusted catalog/VMM operation with enforceable identity binding.

## RR-02 — External witness custody not exercised on a separate
administrative host (P1)

- **State:** durable obligations, high-water replay, verified
  readiness, sticky repair-required, and adversarial restart/ack tests
  all pass in-process and on-loopback.
- **Residual:** a custodian under different administrative control has
  not run; clock skew, network partition behavior, and key custody
  separation are unqualified.
- **Exit:** G8 custody lane on an independently administered witness
  host.

## RR-03 — Live sandbox lanes (apple-hypervisor / Linux-KVM) not run
for this commit (P1)

- **State:** the full `internal/sandboxexecutor` suite passes under
  `-race` against the instrumented fake runtime (942s), including all
  RC8.1 G5 adversarial cases plus the new namespace cases.
- **Residual:** fake-runtime coverage cannot prove real-hypervisor
  behavior; host-lane crashes, real `msb` timing, and firmware quirks
  are unverified for `32654ced`.
- **Exit:** gate D execution on the pinned lanes. Unavailable
  hardware remains NOT_RUN — never a pass.

## RR-04 — Post-dispatch ambiguity lane

- **State:** the ambiguous-wait and late-response properties are
  covered by the ordinary suite with shortened waits, and the full
  32s/65s qualification cases were executed on this commit:
  `CRABBOX_QUALIFICATION_POST_DISPATCH=1 go1.26.5 test -timeout=240s
  -run 'TestPostDispatchTimeoutQualification|TestLateResponseAfterConnectionLifetime'
  ./internal/execution/` → ok 108.089s.
- **Residual:** none — both timing-qualified variants PASS at this
  candidate identity.

## RR-05 — NEMO relay workspace tests and ABI vectors

- **State:** Rust workspace suite runs under the pinned 1.96.1
  toolchain; ABI vectors carry 40 wire vectors (the current corpus —
  the RC8-era audit referenced 68; corpus evolution is recorded
  honestly rather than padded).
- **Residual:** seeded differential fuzzing (2,000 cases per the
  earlier audit spec) is not part of this sweep unless separately
  invoked.

## RR-06 — Research-governance surface

- **State:** INV-11 is enforced by the trust/research gates
  (g1, g6) — unverified assessments cannot promote or authorize.
- **Residual:** AI-generated changes to this very release required
  the same independent-verification chain; the gate table records
  which evidence is machine-verified vs. reviewer-attested.

## RR-07 — fleet.ts size (P3, maintainability)

- **State:** 24,278 lines in one DO module; extraction boundaries and
  characterization-test requirements are scoped in
  `docs/rc8.2/FLEET_SCOPING.md`.
- **Residual:** review/change-risk concentration persists until the
  scoped extractions land in a later cycle.
