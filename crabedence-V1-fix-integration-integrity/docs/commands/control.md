# control

`crabbox control` is the operator release-control surface. It appends
operator-signed transitions to an append-only control ledger and folds that
ledger into the admission decision the execution service enforces before any
`MUTATION`/`CRITICAL` dispatch. `PURE`/`READ` invocations are never gated —
evidence and recovery paths continue during a halt.

The ledger (`internal/releasectl`) is a hash-chained JSONL store: every event
binds sequence, previous-event hash, the folded deployment state it claims to
follow (`prev_state_hash`), deployment identity, epoch, signer role, and
reason. Deleting the ledger file does not clear a restriction — state is
folded from verified events on every open, never from file presence.

```sh
crabbox control halt    --ledger ctl.jsonl --trust-roots roots.txt --deployment prod-a --reason "incident 4821"
crabbox control resume  --ledger ctl.jsonl --trust-roots roots.txt --deployment prod-a --reason "all clear" --key operator.pem
crabbox control status  --ledger ctl.jsonl --trust-roots roots.txt
```

## Transitions

- `halt`, `revoke` — tightening events; may be recorded unsigned so emergency
  stop never waits on key availability. They take effect on the next
  admission check.
- `resume`, `unrevoke`, `stage`, `stage-clear` — relaxations; require a
  valid Ed25519 signature (`--key`, domain `nemo/releasectl/v1`) from an
  allowlisted signer *and* checkpoint coverage before they take effect.
- `stage` additionally binds `--release` and `--evidence` references to
  qualification evidence for the staged level.
- `status` verifies the chain and checkpoint and prints folded state; it
  never writes.

A relaxation appended while the checkpoint lags is recorded but stays
*pending*: `status` reports it under `pending-relaxations`, and it takes
effect only when a later append advances the checkpoint over it. Any append
advances the checkpoint over the entire chain, so the CLI warns to stderr
before committing when another writer's pending relaxations would be
authorized by the advance.

## Trust roots and rotation

`--trust-roots` is the externally provisioned signer allowlist: one
lowercase-hex Ed25519 fingerprint per line (`#` comments allowed), or
`<epoch>:<fingerprint>` to scope a signer to one trust generation. An event
verifies against the root set of its own epoch — rotate by bumping the epoch
and re-scoping roots; the retired epoch's history still verifies. Removing a
fingerprint outright is a deliberate freeze: every relaxation that key ever
signed fails on next open.

## Deployment posture

The service-side gate is configured through `CRABEDENCE_CONTROL_LEDGER`,
`CRABEDENCE_CONTROL_CHECKPOINT`, `CRABEDENCE_CONTROL_TRUST_ROOTS`, and
`CRABEDENCE_DEPLOYMENT` — all required in production. Production requires an
explicit checkpoint path placed outside the writable runtime's authority
(the development default `<ledger>.checkpoint` is refused) and refuses to
start when the ledger file is missing: provision it here first. In
development a missing ledger is auto-provisioned empty. The checkpoint is
written by this CLI — the daemon only reads it.

Writers serialize on an `O_EXCL` lockfile at `<ledger>.lock`. A stale lock
(writer killed between acquire and release) denies appends until removed
manually — deletion can only deny, never clear restrictions.

## Flags

All transition subcommands share:

```text
--ledger <path>          (required)
--checkpoint <path>      (default <ledger>.checkpoint)
--trust-roots <path>     (required)
--deployment <id>        (required)
--reason <text>          (required)
--release <64-hex>       release/artifact digest the event binds
--policy <64-hex>        policy digest the event binds
--epoch <n>              trust-root epoch (default: ledger maximum)
--key <pem>              operator private key (required for relaxations)
--break-glass            record the signer role as breakglass
--dev-untrusted-signers  development only: accept relaxations signed by
                         non-allowlisted keys (signatures still verify;
                         refused in production)
```

`stage` adds `--stage <level>` and `--evidence <ref>` (repeatable). `status`
takes `--ledger`, `--checkpoint`, `--trust-roots`, and optional
`--deployment` (default: report every recorded deployment).

## Output

Transitions print the recorded event ID and sequence, then the folded
deployment state (`halted`, `revoked`, `stage`, `pending-relaxations`).
`status` prints the ledger length, maximum epoch, trusted-root count, and
one line per deployment including the effective `admit` verdict.

## See also

- [`status`](status.md) — lease status (unrelated to control state).
- `docs/spec/capability-invocation-abi.md` — operator-control environment
  variables and dispatch-gate placement.
- `docs/rc8/ADRs/0002-operator-controls.md` — the ledger's design contract.
