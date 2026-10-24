# ADR-0001: Canonical Source and Signed-Candidate Primacy

- Status: Accepted (PR-00)
- Date: 2026-10-24
- Deciders: RC8 integration
- Related: INV-6, D-08, BASELINE.md §1–§3

## Context

Two candidate baselines exist for the RC8 integration parent:

1. `chore/rc7.6-qualification` tip `b501963` — carries refreshed
   `msb-lane-image-pins.json` for a moved `python:3.12` registry tag, applied
   **after** the signed candidate was cut.
2. `13566f1a` — the commit bound by the signed RC7.6 development candidate
   (SHA-256 `73815dbd…`), whose source manifest was verified byte-exact
   against the tracked tree, with a valid `rc75-release` attestation.

The Main-side import source also exists in two forms: an authenticated `main`
branch (`655d4e2`, VERSION `0.53.2`) and the plan's unauthenticated
"NEMO-CONTROL-main 17.zip".

## Decision

- Branch `codex/rc8-authority-integration` from `13566f1a`, the signed
  candidate's source commit — not from the branch tip.
- The signed candidate's `qualification/msb-lane-image-pins.json`
  (`f86821a7…`) is the lane-pin identity of record. The `b501963` refresh is
  held as a pending, separately-reviewed pin decision; adopting it requires
  regenerating the manifest and re-running affected lanes (INV-6).
- Import Main-side content exclusively from the authenticated `main` branch
  in this repository. The ZIP, if it later appears, is reference-only and its
  files must hash-match the INTEGRATION_INVENTORY table before use.
- Never `git init` a ZIP extraction and treat it as history.

## Consequences

- The pinned image digest for `python:3.12` in the signed candidate may point
  at an older registry digest than today's tag resolution. Any live lane that
  pulls by tag must pin by digest from the manifest of record, or the lane
  evidence binds a different identity and fails G7/G8.
- Qualification evidence bound to `13566f1a` remains meaningful for the RC7.6
  candidate; RC8 evidence must be generated on RC8 commits.
- A future ADR may adopt the `b501963` pin refresh; it must cite the
  requalification scope it triggers.
