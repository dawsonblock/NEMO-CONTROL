# RC8.3 Baseline

| Field | Value |
|---|---|
| Branch | `codex/rc8.3-custody-sandbox-qualification` |
| Baseline source commit | `32654cedd2699d27e23314ec3a91309ff71229ad` (`codex/rc8.2-security-qualification` frozen candidate) |
| Baseline signed package | `NEMO-CONTROL-v0.55.0-rc8.2-development.zip` sha256 `57f4f6a6555edbc89a0c32a89240b1d6ed3fb25a1af6340e349413b2ef543fcc` |
| Baseline inventory | 4,329 entries; tree root digest `fe654970404897ad0dc9ee68ec231a6a820feb392ffe908c71b52475bd6ffdca` |
| Development version | `0.55.0-rc8.3-dev` (bumped in the first development commit) |
| Local toolchain | go1.27.2 (project gates pin go1.26.5), node v24.16.0, msb 0.7.8 |

## Provenance boundary

The branch was created directly at the verified baseline commit — no
import, no fabricated ancestry. Post-freeze RC8.2 documentation
(release-readiness, findings-register addenda F-10..F-13) is treated
as supplemental audit notes per the RC8.3 charter; the defects they
recorded map to PR-02/PR-03/PR-05 and are carried in
`docs/rc8.3/DEFECT_REGISTER.md`.

Upstream G1–G7 PASS claims in the signed release are recorded as
upstream claims, not freshly reproduced results; RC8.3 re-runs its
own lanes (PR-07).
