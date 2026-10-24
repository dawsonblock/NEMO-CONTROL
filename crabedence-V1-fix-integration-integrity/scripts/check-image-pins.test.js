import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  checkDeclaredSources,
  checkInventoryConsistency,
  checkTartManifestBinding,
  checkUndeclaredDefaults,
  imageLiterals,
  unpinnedDockerfileRefs,
  workflowImageRefs,
} from "./check-image-pins.mjs";

function tmpdir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "image-pins-"));
}

function write(root, rel, content) {
  const file = path.join(root, rel);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, content);
}

test("imageLiterals extracts quoted Image fields only", () => {
  const src = `Config{
    Islo: IsloConfig{ Image: "docker.io/library/ubuntu:24.04" },
    LocalContainer: LocalContainerConfig{ Image: containerImage },
    Smolvm: SmolvmConfig{ Image: "alpine" },
  }`;
  assert.deepEqual(imageLiterals(src), ["docker.io/library/ubuntu:24.04", "alpine"]);
});

test("unpinnedDockerfileRefs collects refs lacking a digest pin", () => {
  const ok = `FROM --platform=$BUILDPLATFORM node:24-bookworm@sha256:${"a".repeat(64)} AS build\n`;
  assert.deepEqual(unpinnedDockerfileRefs(ok), []);
  assert.deepEqual(
    unpinnedDockerfileRefs("FROM node:24-bookworm AS build\nFROM ubuntu:24.04\n"),
    ["node:24-bookworm", "ubuntu:24.04"],
  );
});

test("workflowImageRefs collects service image references", () => {
  const src = `services:\n  postgres:\n    image: postgres:16@sha256:${"f".repeat(64)}\n  cache:\n    image: redis:7\n`;
  assert.deepEqual(workflowImageRefs(src), [`postgres:16@sha256:${"f".repeat(64)}`, "redis:7"]);
});

test("checkInventoryConsistency enforces class/status rules", () => {
  const base = { images: [], findings: [] };
  assert.deepEqual(checkInventoryConsistency(base), []);

  const bad = {
    images: [
      { id: "a", pin_class: "mutable-tag", status: "pinned", reference: "alpine", sources: [] },
      { id: "b", pin_class: "registry-digest", status: "finding", finding: "F-MISSING", reference: "x", sources: [] },
      { id: "b", pin_class: "registry-digest", status: "pinned", reference: "y", sources: [] },
    ],
    findings: [],
  };
  const errors = checkInventoryConsistency(bad);
  assert.ok(errors.some((e) => e.includes("requires a digest-bound pin_class")));
  assert.ok(errors.some((e) => e.includes("missing finding F-MISSING")));
  assert.ok(errors.some((e) => e.includes("duplicate image id")));
});

test("checkDeclaredSources verifies each reference at each declared source", () => {
  const root = tmpdir();
  write(root, "src/provider.go", `const image = "alpine@sha256:${"b".repeat(64)}"`);
  const inventory = {
    images: [
      {
        id: "ok",
        reference: `alpine@sha256:${"b".repeat(64)}`,
        digest: `sha256:${"b".repeat(64)}`,
        sources: ["src/provider.go"],
      },
      { id: "missing-file", reference: "alpine", sources: ["src/absent.go"] },
      { id: "missing-ref", reference: "debian", sources: ["src/provider.go"] },
    ],
    findings: [],
  };
  const errors = checkDeclaredSources(root, inventory);
  assert.equal(errors.length, 2);
  assert.ok(errors[0].includes("declared source missing: src/absent.go"));
  assert.ok(errors[1].includes("does not contain declared reference debian"));
});

test("checkUndeclaredDefaults flags undeclared config literals and dockerfiles", () => {
  const root = tmpdir();
  write(root, "internal/cli/config.go", `Smolvm: SmolvmConfig{ Image: "alpine" }`);
  write(root, "worker/Dockerfile.node", "FROM node:22-slim\n");
  const declared = {
    images: [{ id: "smolvm", reference: "alpine", sources: [] }],
    findings: [],
  };
  const errors = checkUndeclaredDefaults(root, declared);
  assert.equal(errors.length, 1);
  assert.ok(errors[0].includes("unpinned base image not declared"));
  assert.ok(errors[0].includes("node:22-slim"));

  declared.images.push({ id: "node", reference: "node:22-slim", sources: [] });
  assert.deepEqual(checkUndeclaredDefaults(root, declared), []);
});

test("checkUndeclaredDefaults flags unpinned workflow images but accepts digest pins and expressions", () => {
  const root = tmpdir();
  write(
    root,
    ".github/workflows/ci.yml",
    `services:\n  postgres:\n    image: postgres:16@sha256:${"f".repeat(64)}\n  cache:\n    image: redis:7\n  dyn:\n    image: \${{ matrix.image }}\n`,
  );
  const inventory = { images: [{ id: "redis", reference: "redis:7", sources: [] }], findings: [] };
  assert.deepEqual(checkUndeclaredDefaults(root, inventory), []);
  inventory.images = [];
  const errors = checkUndeclaredDefaults(root, inventory);
  assert.equal(errors.length, 1);
  assert.ok(errors[0].includes("redis:7"));
});

test("checkTartManifestBinding compares the embedded manifest digest", () => {
  const root = tmpdir();
  const manifest = '{"layers":[]}';
  write(root, "internal/providers/tart/images/sequoia.manifest.json", manifest);
  const digest = "sha256:" + crypto.createHash("sha256").update(manifest).digest("hex");
  const ok = {
    images: [{ id: "tart", pin_class: "oci-manifest-bound", digest, sources: [] }],
    findings: [],
  };
  assert.deepEqual(checkTartManifestBinding(root, ok), []);
  ok.images[0].digest = "sha256:" + "0".repeat(64);
  const errors = checkTartManifestBinding(root, ok);
  assert.equal(errors.length, 1);
  assert.ok(errors[0].includes("embedded manifest digest"));
});
