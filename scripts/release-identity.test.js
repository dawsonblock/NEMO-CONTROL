import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

// Release-identity policy: every file the release pipeline executes or
// publishes must carry this repository's identity, never the upstream one.
// The release repository is configurable only to test the pipeline itself;
// the workflows pin github.repository to the configured value.

const repoRoot = path.resolve(import.meta.dirname, "..");
const read = (file) => fs.readFileSync(path.join(repoRoot, file), "utf8");

const RELEASE_IDENTITY = "dawsonblock/crabedence-V1";
const RELEASE_TAP = "dawsonblock/tap";

test("release configuration carries only the fork identity", () => {
  const config = read("scripts/release-config.sh");
  assert.match(config, new RegExp(`CRABBOX_RELEASE_REPOSITORY=\\$\\{CRABBOX_RELEASE_REPOSITORY:-${RELEASE_IDENTITY.replace("/", "\\/")}\\}`));
  assert.match(config, new RegExp(`CRABBOX_RELEASE_TAP=\\$\\{CRABBOX_RELEASE_TAP:-${RELEASE_TAP.replace("/", "\\/")}\\}`));
  assert.match(config, /io\.github\.dawsonblock\.crabbox/);
  assert.match(config, /io\.github\.dawsonblock\.crabbox\.apple-vm-helper/);
  assert.match(config, /io\.github\.dawsonblock\.crabbox\.apple-vm-vmd/);
  for (const upstream of [
    /openclaw\/crabbox/,
    /org\.openclaw/,
    /OpenClaw Foundation/,
    /FWJYW4S8P8/,
    /openclaw\/homebrew-tap/,
    /openclaw\/tap/,
  ]) {
    assert.doesNotMatch(config, upstream, `release-config.sh still carries upstream identity: ${upstream}`);
  }
});

test("release workflows assert the configured repository identity explicitly", () => {
  for (const file of [
    ".github/workflows/release-assets.yml",
    ".github/workflows/verify-homebrew.yml",
  ]) {
    const workflow = read(file);
    assert.match(
      workflow,
      new RegExp(`"\\$GITHUB_REPOSITORY" == ${RELEASE_IDENTITY.replace("/", "\\/")}`),
      `${file} must assert github.repository, not trust the environment`,
    );
    assert.doesNotMatch(workflow, /github\.com\/openclaw|openclaw\/homebrew-tap|openclaw\/tap/);
  }
});

test("protected signing and packaging tooling carries no upstream identity", () => {
  for (const file of [
    "scripts/package-release.sh",
    "scripts/verify-release.sh",
    "scripts/verify-homebrew-release.sh",
    "scripts/verify-release-source.sh",
    "scripts/verify-macos-binary.sh",
    "scripts/codesign-macos.sh",
    "scripts/release-provenance.mjs",
    "scripts/validate-release-publication.mjs",
    "scripts/verify-github-release-policy.mjs",
    "scripts/publish-release.sh",
    "scripts/create-release-draft.sh",
  ]) {
    const source = read(file);
    for (const upstream of [
      /github\.com\/openclaw(?!\/crabbox\/cmd)/, // release URLs/API paths; the Go module path is separate
      /api\.github\.com\/repos\/openclaw/,
      /org\.openclaw/,
      /OpenClaw Foundation/,
      /FWJYW4S8P8/,
      /openclaw\/homebrew-tap/,
      /openclaw\/tap/,
      /@openclaw\//,
      /source.*"openclaw"/,
    ]) {
      assert.doesNotMatch(source, upstream, `${file} still carries upstream identity: ${upstream}`);
    }
  }
});

test("security ownership, signer policy, and the release manifest are fork-owned", () => {
  const codeowners = read(".github/CODEOWNERS");
  assert.doesNotMatch(codeowners, /@openclaw\//);
  assert.match(codeowners, /@dawsonblock/);
  const manifest = read(".mac-release.env");
  assert.match(manifest, /^CRABBOX_RELEASE_APPLE_SIGNING='none'$/m);
  assert.doesNotMatch(manifest, /openclaw|OpenClaw|FWJYW4S8P8/i);
  const allowedSigners = read(".github/release-allowed-signers");
  assert.doesNotMatch(allowedSigners, /openclaw/i);
});

test("release records and documentation bind the fork repository", () => {
  const recordsDir = path.join(repoRoot, "release/records");
  for (const name of fs.readdirSync(recordsDir)) {
    if (!name.endsWith(".json")) continue;
    const record = JSON.parse(fs.readFileSync(path.join(recordsDir, name), "utf8"));
    assert.equal(record.repository, RELEASE_IDENTITY, `${name} binds a foreign repository`);
  }
  const releasing = read("docs/RELEASING.md");
  // The bare module path github.com/openclaw/crabbox may appear where the doc
  // explains why the public go-install channel resolves upstream; release
  // machinery URLs and the signing wrapper may not.
  assert.doesNotMatch(
    releasing,
    /github\.com\/openclaw\/crabbox\/releases|api\.github\.com\/repos\/openclaw|ls-remote https:\/\/github\.com\/openclaw|github\.com\/openclaw\/crabbox\s*\||github\.com\/openclaw\/crabbox\.git|openclaw\/homebrew-tap|openclaw\/tap|codesign-run --with-package-secrets/,
  );
});
