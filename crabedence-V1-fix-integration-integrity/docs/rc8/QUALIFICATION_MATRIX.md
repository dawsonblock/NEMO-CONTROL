# RC8 Qualification Matrix

Every gate evaluates the **same exact candidate commit** and its signed
artifact. `NOT_RUN`, `FAIL`, `SKIP`, missing hardware, or absent required
capability all mean the lane is **not** qualified — never PASS-by-absence.
Evidence from a different source commit, toolchain, pin manifest, deployment
identity, or trust root is rejected (INV-6).

## Gate table

| Gate | Scope | Pass condition | Status |
|---|---|---|---|
| G0 | Verified parent, reproducible source inventory, clean checkout, pinned toolchains, no stale qualified status | Parent commit in authenticated history AND tree byte-matches signed candidate manifest AND attestation verifies | **PASS** (2026-10-24 — see BASELINE.md §2) |
| G1 | PR-01 trust repair | Zero unassessed records reach trusted retrieval/task-set/promotion; deterministic failure fixtures pass | NOT RUN |
| G2 | PR-02 authority + ABI | Exact Go/Rust agreement on normative corpus; every malformed input denied or classified identically; zero unreviewed semantic regressions in dispatch/admission/reconcile | NOT RUN |
| G3 | PR-03 release controls | Kernel-compromised process cannot make a signed halt/revoke vanish; only separately-authorized signed transitions change state | NOT RUN |
| G4 | PR-04 custody | Receipts and sandbox evidence verify under distinct crypto domains; witness downtime never yields unverified terminal custody success | NOT RUN |
| G5 | PR-05 sandbox lifecycle | No blind replay, no unauthorized VM adoption/removal, no false verified-absent; all runtime residuals explicit | NOT RUN |
| G6 | PR-06 research boundary | All research paths advisory; claimed improvements have independently replayable outcomes + pre-registered criteria | NOT RUN |
| G7 | PR-07 reproducible packaging | Clean checkout and cold archive extraction yield identical tracked state, version/provenance IDs, signed manifests; no stale qualification | NOT RUN |
| G8 | PR-08 live qualification | Every mandatory lane PASS for the same candidate commit + signed artifact; no unclosed P0/P1 | NOT RUN |
| G9 | PR-09 efficacy (optional) | Rollout decision supported by measured effectiveness on qualified candidate | NOT RUN |

## G8 mandatory lanes

| Lane | Required activities | Proof to retain |
|---|---|---|
| Linux build/runtime | pinned Go 1.26.5; `go vet`; `go test -race -timeout=20m ./...`; PostgreSQL integration; packaging | commands, exit codes, toolchain, commit, digest, signed logs |
| Rust bridge/plugin host | pinned Rust 1.96.1; `cargo test --workspace --locked --no-fail-fast`; lint/security gates; executed Go/Rust ABI differential | crate locks, fixtures, corpus digests |
| Node/worker/tools | pinned Node 24.x; `npm ci` lockfile install; relevant suites | install/test evidence bound to source manifest |
| Linux live microVM | physical/VM host with `/dev/kvm`; **all** `TestMSBLive*` common cases + `TestMSBLiveLinuxKVM`; real kill/fault injection | per-test run+pass proof, host/runtime attestations |
| Apple live microVM | bare-metal Apple Silicon, `kern.hv_support == 1`; **all** `TestMSBLive*` common cases; real kill/fault injection | per-test run+pass proof, host/runtime attestations |
| Independent custody | separately administered host + separately controlled keys; outage/replay/forgery/restore tests | external signed checkpoint + verifier output |
| Security/authority | live halt/resume/revocation transitions; key rotation; replay/rollback; UNKNOWN/duplicate-dispatch; cleanup replacement race | tamper-resistant negative-test receipts |
| Artifact | fresh extraction in isolated runner; symlinks + permissions preserved; manifest/signature/provenance verified | package hash, verifier version, signer trust-root provenance |

Test inventory: `qualification/required-tests.json` (RC7.6 lineage: 13 common
live cases + `TestMSBLiveLinuxKVM`) plus `qualification/rc8-required-tests.json`
for RC8-specific additions. Gate compares run/pass event evidence against the
inventory — omitted or skipped cases fail the lane. Inventory changes require
review + signature.

## Stop/GO policy

- Development GO: G0 — **granted** for `codex/rc8-authority-integration`.
- Integration GO: G1–G7 all PASS.
- Qualification GO: G8 prerequisites incl. independent custody + real fault
  injection on both lanes.
- Production GO: G8 + operator-signed authorization + residual-risk acceptance
  + canary plan. G9 only if claiming measured agent gains.
- Immediate NO-GO: mismatched manifests, missing trust roots, unassessed
  trusted memory, unauthenticated control clear, forged/unchecked witness ack,
  blind UNKNOWN retry, unsafe VM deletion, a mandatory test that did not
  execute, or evidence bound to different source bytes.
