import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

// The unsigned release contract, asserted mechanically.
//
// `CRABBOX_RELEASE_APPLE_SIGNING=none` declares that macOS artifacts are
// unsigned and not notarized. That declaration is only worth anything if
// the verifier PROVES it — so these tests require the verifier to accept an
// unsigned artifact and to REJECT a signed one. A skipped check would pass
// both cases, which is exactly the failure mode this guards against.

const root = path.resolve(import.meta.dirname, "..");
const verifier = path.join(root, "scripts/verify-macos-binary.sh");
const darwin = process.platform === "darwin";

const writeExecutable = (file, body) => {
  fs.writeFileSync(file, body);
  fs.chmodSync(file, 0o755);
};

/**
 * Run the verifier against a mock artifact. `signed` selects what the mock
 * codesign reports, so the same harness can prove both directions.
 */
function runVerifier({ signed }) {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), "crabbox-unsigned-"));
  try {
    const bin = path.join(work, "bin");
    fs.mkdirSync(bin);
    const log = path.join(work, "calls.log");
    fs.writeFileSync(log, "");

    const binary = path.join(work, "crabbox");
    writeExecutable(binary, "#!/bin/sh\nexit 0\n");

    // Only the tools the unsigned branch touches.
    writeExecutable(
      path.join(bin, "lipo"),
      `#!/bin/bash\n[[ "$1" == -archs ]] || exit 98\necho arm64\n`,
    );
    writeExecutable(
      path.join(bin, "codesign"),
      `#!/bin/bash
set -eu
printf 'codesign:%s\\n' "$*" >>${JSON.stringify(log)}
binary=\${!#}
case "$*" in
  "-dvvv $binary")
    ${
      signed
        ? `printf 'Identifier=%s\\n' "$CRABBOX_RELEASE_CLI_IDENTIFIER"
printf 'Authority=%s\\n' "$CRABBOX_RELEASE_AUTHORITY"
printf 'TeamIdentifier=%s\\n' "$CRABBOX_RELEASE_TEAM_ID"
exit 0`
        : `printf '%s\\n' "$binary: code object is not signed at all"
exit 1`
    }
    ;;
  "--verify --strict $binary")
    ${signed ? "exit 0" : "exit 1"}
    ;;
  "--verify --strict --check-notarization -R=notarized $binary")
    ${signed ? "exit 0" : "exit 1"}
    ;;
  *)
    exit 98
    ;;
esac
`,
    );

    const result = spawnSync("/bin/bash", [verifier, "io.github.dawsonblock.crabbox", "arm64", binary], {
      cwd: work,
      encoding: "utf8",
      env: {
        PATH: `${bin}:${process.env.PATH}`,
        HOME: work,
        TMPDIR: work,
        CRABBOX_RELEASE_APPLE_SIGNING: "none",
      },
    });
    return { result, calls: fs.readFileSync(log, "utf8") };
  } finally {
    fs.rmSync(work, { recursive: true, force: true });
  }
}

test("the unsigned contract accepts an unsigned artifact", { skip: !darwin }, () => {
  const { result, calls } = runVerifier({ signed: false });
  assert.equal(result.status, 0, result.stderr);
  // The signature surface was actually consulted, not skipped.
  assert.match(calls, /codesign:-dvvv /);
  assert.match(calls, /codesign:--verify --strict /);
});

test("the unsigned contract rejects a signed artifact", { skip: !darwin }, () => {
  const { result } = runVerifier({ signed: true });
  assert.notEqual(result.status, 0, "a signed artifact must fail the unsigned contract");
  assert.match(result.stderr, /unsigned release policy: binary carries a code signature/);
});

test("the default signing mode is the declared unsigned contract", () => {
  const config = fs.readFileSync(path.join(root, "scripts/release-config.sh"), "utf8");
  assert.match(config, /CRABBOX_RELEASE_APPLE_SIGNING=\$\{CRABBOX_RELEASE_APPLE_SIGNING:-none\}/);
});
