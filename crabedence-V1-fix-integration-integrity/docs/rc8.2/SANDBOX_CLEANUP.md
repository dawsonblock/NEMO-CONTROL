# F-06 — Sandbox Conditional Deletion: Runtime Capability Inventory and Exclusive-Namespace Enforcement

Status: **implemented (fallback mode)** — enforced exclusive namespace, honest `REMOVAL_UNCERTAIN`, no atomicity claimed.

## Runtime primitive inventory

Audited against the installed runtime, `msb` (Microsandbox CLI) **v0.7.8** at
`~/.local/bin/msb`:

| Operation | Surface | Conditional/atomic identity check |
|---|---|---|
| `msb rm` / `msb remove` | positional names or `--label <k=v>`, `--force` | **None.** Name/label is resolved to an object, then deleted. No generation, owner-token, or compare-and-delete flag exists. |
| `msb inspect` | `--job`, positional name; returns the sandbox document | Read-only; used for pre- and post-removal verification. |
| `msb create` | `--name`, `--label`, `--deployment-profile`, ... | Exclusive create: refuses an existing name. |

Conclusion: **the runtime has no native identity-conditional delete.** The
ADR-0004 preferred branch (atomic check-and-destroy inside the runtime) is
unavailable in v0.7.8. Every software-side inspect-then-delete sequence retains
a substitution window between the check and the destructive call.

## Enforced mitigation: deployment-exclusive namespace

`MSBBackend.Namespace` (`-msb-namespace` / `SANDBOX_EXECUTOR_MSB_NAMESPACE`)
declares a deployment-exclusive sandbox namespace. When set:

- `ValidateNamespace` enforces a short DNS-label-style identifier
  (`[a-z0-9][a-z0-9-]{0,31}`) at daemon startup — invalid values are fatal.
- `handlePrefix()` derives `sx-<ns>-`; `msbJobName`, `Inspect`, and `Cleanup`
  all resolve through it, so namespaced handles are minted inside the
  deployment's space and handles outside it are refused as
  `IDENTITY_UNVERIFIABLE`.
- `createArgs` stamps `--label crabedence.namespace=<ns>` on every sandbox.
- `Cleanup` refuses (classifies `IDENTITY_MISMATCH`, never deletes) an occupant
  that presents the authorized dispatch/job labels but a foreign or absent
  namespace label — the cross-deployment collision shape.

This is a **deployment constraint, not atomicity**. It bounds which tenants
can write into the name space the cleanup path resolves, and it makes any
cross-deployment occupant a classified non-deletion. It does not remove the
same-namespace substitution window inside a compromised or shared runtime.

## What remains true in every mode

- Identity validation (`CleanupRequest.Validate`, prefix fence, nonce suffix,
  `crabedence.dispatch` + `crabedence.job` + `crabedence.namespace` labels)
  always precedes the destructive `msb rm -f <handle>` call.
- Any unresolved result — transport failure, timeout after rm issued, failed
  post-removal verify — is `REMOVAL_UNCERTAIN`, never treated as proof of
  absence.
- Post-removal verification distinguishes: authorized identity still present
  (`REMOVAL_UNCERTAIN`), absent (`REMOVED_VERIFIED` /
  `ALREADY_ABSENT_VERIFIED`), foreign replacement (`REMOVED_VERIFIED` — our
  instance is gone; the replacement is not ours to claim), and uninspectable
  (`REMOVAL_UNCERTAIN`).
- Cleanup obligations persist durably for retry and operator escalation.
- `RETAINED_BY_POLICY` keeps `KeepSandboxes` resources out of the destructive
  path entirely.

## Production qualification implication

- **Exclusive-namespace deployment**: cleanup identity is enforceable; the
  residual trust is (a) the runtime honoring its own name exclusivity and
  labels, and (b) the deployment actually running a dedicated name space. The
  candidate's sandbox-cleanup gate can qualify **for this deployment shape
  only**.
- **Shared-namespace deployment**: the substitution window is unbounded —
  another tenant can place a foreign occupant on a resolved name inside the
  check/delete window. Sandbox cleanup under the high-assurance profile is
  **NO-GO** in a shared namespace, per ADR-0004.

See `docs/rc8/ADRs/0004-conditional-sandbox-cleanup.md` for the original
decision and `internal/sandboxexecutor/namespace_test.go` for the enforced
behavior.
