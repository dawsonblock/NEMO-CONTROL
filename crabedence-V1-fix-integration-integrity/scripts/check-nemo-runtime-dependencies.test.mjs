import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

const script = path.join(import.meta.dirname, "check-nemo-runtime-dependencies.sh");

function check(t, dependency = "", fail = false) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "nemo-dependencies-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.mkdirSync(path.join(root, "scripts"));
  fs.mkdirSync(path.join(root, "runtimes/nemo-relay"), { recursive: true });
  fs.mkdirSync(path.join(root, "bin"));
  fs.copyFileSync(script, path.join(root, "scripts/check.sh"));
  const cargo = path.join(root, "bin/cargo");
  fs.writeFileSync(cargo, `#!/bin/bash
[[ "$*" == *"--locked"* && "$*" == *"--all-features"* && "$*" == *"--target all"* && "$*" == *"normal,build"* ]] || exit 2
if [[ "$*" == *"-p nemo-crabedence-runtime "* ]]; then
  [[ "$FAIL_RESOLUTION" != 1 ]] || exit 1
  printf 'nemo-crabedence-runtime\\n%s\\n' "$TEST_DEPENDENCY"
else
  printf 'nemo-relay\\n'
fi
`);
  fs.chmodSync(cargo, 0o755);
  return spawnSync("bash", [path.join(root, "scripts/check.sh")], {
    encoding: "utf8",
    env: {
      ...process.env,
      PATH: `${path.join(root, "bin")}${path.delimiter}${process.env.PATH}`,
      TEST_DEPENDENCY: dependency,
      FAIL_RESOLUTION: fail ? "1" : "0",
    },
  });
}

test("production composition permits executor and ledger contract types", (t) => {
  const result = check(t, "nemo-relay-executor\nnemo-relay-ledger");
  assert.equal(result.status, 0, result.stderr);
});

for (const dependency of [
  "nemo-relay-authority",
  "nemo-effect-runtime",
  "nemo-experimental-effect-kernel",
  "nemo-effect-qualification",
]) {
  test(`production composition refuses ${dependency}`, (t) => {
    const result = check(t, dependency);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /production composition root reaches/);
  });
}

test("unresolvable production composition fails closed", (t) => {
  const result = check(t, "", true);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /could not resolve production composition root/);
});

test("outer repository CI runs the production guards and provenance checks", () => {
  const workflow = fs.readFileSync(
    path.resolve(import.meta.dirname, "../../.github/workflows/consolidation.yml"),
    "utf8",
  );
  for (const gate of [
    "bash scripts/check-nemo-runtime-dependencies.sh",
    "bash scripts/check-nemo-credential-isolation.sh",
    "python3 scripts/verify-nemo-transfer.py --require-source",
    "bash scripts/check-provenance-docs.sh",
    "scripts/outer-release-manifest.test.mjs",
  ]) {
    assert.ok(workflow.includes(gate), `outer CI must run ${gate}`);
  }
  assert.match(workflow, /persist-credentials: false/);
});
