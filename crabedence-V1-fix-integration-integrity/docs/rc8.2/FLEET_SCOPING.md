# F-09 — `worker/src/fleet.ts` maintainability scoping

Status: **scoped — no refactor in the RC8.2 candidate.** F-09 keeps
maintainability work separate from the frozen security-qualification
candidate (commit `32654ced`); this document records the extraction
analysis a follow-on PR must satisfy.

## Module shape (measured)

- `worker/src/fleet.ts`: 24,278 lines — the largest module in the
  worker by ~5× (next: `fleet-providers.ts` 4,507, `azure.ts` 4,515).
- One Durable Object: `class FleetCoordinator` at line 1077 spanning
  to ~19140 — `fetch` (1194), `webSocketMessage` (1900), `alarm`
  (3119) plus all domain logic as class methods.
- A `runExclusive`-wrapped subclass at ~19145 serializing the three
  DO entry points.
- 342 top-level helper functions concentrated at lines 19277–24268
  (workspace API surface, runtime-adapter helpers, ready-pool
  counters, canonical-JSON/crypto utilities).

## Candidate extraction boundaries (ranked by safety)

1. **Canonical serialization & crypto utilities** (~23436 and
   neighbors: `escapeJSONSeparators`, digest/canonical-bytes
   helpers). Pure functions, no DO state — safest first extraction;
   characterization tests are trivially writable (byte-exact output
   fixtures, incl. the U+2028/U+2029 escaping parity with Go's
   `json.Encoder`).
2. **Ticket/session viewers** (webVNC portal viewer, code viewer,
   native VNC tickets — TTL constants at 490–496, interfaces at
   585–626/1064). Self-contained protocol domain; exits through a
   narrow grant/ticket record shape.
3. **Runtime-adapter dispatch & deletion** (pending queues, delete
   retry/backoff, buffered-byte caps — constants 497–509). State is
   DO-storage-backed; extraction needs storage-shim characterization
   tests.
4. **Ready-pool management** (typed + legacy ready-pool counters,
   desired records, fill claims — constants 539–544 + helpers at
   ~19310–20154).
5. **Orphan sweeps & deferred cleanup** (aws/azure orphan sweep,
   azure deferred cleanup, interrupted-provisioning recovery —
   constants 513–521, 538 + sweep functions at ~24091–24199).
6. **Provider reconciliation circuit** (candidate/circuit prefixes
   535–536 + helpers ~24182–24195).
7. **Workspace API surface** (40 `workspace*` functions,
   19277–22966) — largest and most coupled; extract last, likely as
   several modules (provisioning, lease lifecycle, SSH/terminal).
8. **External-runner sync** (constants 489 + sync functions
   ~19772–19776).

## Hard rules for the extraction PR

- Characterization (golden) tests must exist for a boundary *before*
  it moves: `worker/test` Vitest coverage pinning request/response
  shapes, storage key layouts, retry/backoff timing, and the
  `runExclusive` serialization contract.
- Moves are mechanical (cut/paste + import wiring) — no behavioral
  edits inside an extraction commit.
- Each extraction lands as its own commit with before/after
  `npm test --prefix worker` evidence (baseline: 3053 pass, 2 skip).
- Nothing from this effort may be cherry-picked into the RC8.2
  candidate — any fleet.ts change invalidates candidate commit
  `32654ced` and its packaging/attestation evidence.
- Provider-neutral core rule applies: provider-specific logic
  (aws/azure/gcp orphan handling, ingress reconcile) moves behind
  adapter seams or into the existing provider modules, never into
  core fleet code paths.
