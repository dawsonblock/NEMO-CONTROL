# Qualification data

This directory holds release-qualification data files that gates verify
mechanically. Nothing here is documentation-only: each file is bound to a
checker so the declared state cannot drift from the tree.

| File | Verifier | What it binds |
| --- | --- | --- |
| `msb-lane-image-pins.json` | `scripts/check-image-pins.mjs` (CI, alongside `check-docker-base-images.mjs`) | Every execution-plane image default — macOS microVM, Linux microVM, container runtime, coordinator, CI services, and cloud catalog names — with its pin class, declaring sources, and qualification status. Undeclared `Image:` defaults, unpinned `FROM` lines, and unpinned workflow service images fail the check. |

## Pin classes

- `registry-digest` — an OCI `name@sha256:` reference; immutable.
- `oci-manifest-bound` — a digest reference whose pulled bytes are verified
  against a manifest embedded in the binary (Tart).
- `immutable-url-sha256` — a date-pinned artifact URL plus checksum, verified
  against the publisher's checksum file (Apple VM cloud images).
- `local-operator-image` — built and trusted by the operator; no upstream
  identity exists (Lume golden image).
- `provider-catalog-name` — resolved at provision time by the provider API;
  not OCI-pinnable (AWS/Azure/GCP/Hetzner/Linode/OVH/Scaleway/Incus/Multipass/
  Namespace).
- `mutable-tag` — registry-pullable but tag-bound. Only valid as a declared
  finding.
- `development` — outside the qualified execution plane (devcontainers).

Findings use `F-PIN-*` identifiers. `open` findings are reported on every
checker run; `accepted-limitation` findings are documented classes the release
authority has accepted; `resolved` findings record the fix.
