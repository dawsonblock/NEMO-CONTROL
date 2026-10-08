import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import {
  archive, canonical, createSource, evidenceDigest, extract, finalize, safePath,
  requiredQualificationGates, sha256, verifyBundle,
} from "./outer-release-manifest.mjs";

const scripts = path.dirname(fileURLToPath(import.meta.url));
const CRAB = "crabedence-V1-fix-integration-integrity";
const FROZEN = "NEMO-feat-native-plugin-isolation";
const RUNTIME = `${CRAB}/runtimes/nemo-relay`;
const verifier = path.join(scripts, "verify-nemo-transfer.py");
const command = (cmd, args, cwd) => execFileSync(cmd, args, {
  cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"],
  env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1", GIT_CONFIG_NOSYSTEM: "1" },
});
function put(root, p, value, mode = 0o644) {
  const full = path.join(root, p);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, value, { mode });
}
function fixture(t) {
  const workspace = path.join(scripts, `.outer-provenance-tests-${process.pid}-${crypto.randomUUID()}`);
  fs.mkdirSync(workspace);
  t.after(() => fs.rmSync(workspace, { recursive: true, force: true }));
  const root = path.join(workspace, "checkout");
  fs.mkdirSync(root);
  put(root, ".gitignore", "target/\nreal-authority/\n");
  put(root, ".gitattributes", "*.cmd text eol=crlf\n");
  put(root, "checkout-filter.cmd", "echo fixture\r\n");
  put(root, "README.md", "outer source\n");
  put(root, `long/${"a".repeat(160)}/${"b".repeat(120)}.txt`, "PAX long-path fixture\n");
  put(root, "authority/policy.json", '{"decision":"deny"}\n');
  put(root, `${CRAB}/go.mod`, "module outerfixture\n\ngo 1.20\n");
  put(root, `${CRAB}/scripts/build.sh`, "#!/bin/sh\nexit 0\n", 0o755);
  put(root, `${CRAB}/scripts/verify-nemo-transfer.py`, fs.readFileSync(verifier));
  for (const p of ["check-release-admission.sh", "lib/qualification-gates.sh"]) {
    put(root, `${CRAB}/scripts/${p}`, fs.readFileSync(path.join(scripts, p)));
  }
  put(root, `${CRAB}/scripts/generate-release-evidence.sh`,
    "run_gate exact-toolchain BUILD fixture\nrun_live_postgres_gate postgres fixture.ts\nrun_required_live_go_gate critical INTEGRATION fixture\n");
  // A standard-library-only fixture authority, not a replacement production registry.
  put(root, `${CRAB}/cmd/registry-digest/main.go`, `package main
import("fmt";"crypto/sha256";"encoding/base64")
func main(){p:=[]byte("[]");fmt.Printf("{\\"registry_sha256\\":\\"%x\\",\\"canonical_payload\\":\\"%s\\"}\\n",sha256.Sum256(p),base64.StdEncoding.EncodeToString(p))}
`);
  for (const tree of [FROZEN, RUNTIME]) {
    put(root, `${tree}/Cargo.toml`, '[workspace]\nmembers = []\n[workspace.package]\nversion = "1.0.0"\n');
    put(root, `${tree}/Cargo.lock`, "# fixture dependency lock\n");
    for (const crate of ["plugin-host", "native-loader", "native-abi", "worker-proto"]) {
      put(root, `${tree}/crates/${crate}/src/lib.rs`, `// ${crate}\n`);
    }
    fs.symlinkSync("Cargo.toml", path.join(root, tree, "manifest-link"));
  }
  const policy = {
    provenance_format_version: 2, enumeration: {
      excluded_dir_names: [".git", "__pycache__", "target"],
      generated_paths: ["TRANSFER-PROVENANCE.md"],
    },
  };
  put(root, `${CRAB}/runtimes/nemo-provenance-policy.json`, JSON.stringify(policy));
  command("python3", ["-B", "-c", `
import importlib.util,os,json,sys
root=sys.argv[1];os.chdir(os.path.join(root,${JSON.stringify(CRAB)}))
spec=importlib.util.spec_from_file_location("v","scripts/verify-nemo-transfer.py")
v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
policy=v.read_policy("runtimes/nemo-provenance-policy.json")
src=v.digest_runtime_v2("../${FROZEN}",policy)
ship=v.digest_runtime_v2("runtimes/nemo-relay",policy)
m={"provenance_format_version":2,"tree":"runtimes/nemo-relay","runtime_version":"1.0.0","shipped_tree_sha256":ship["nemo_runtime_sha256"],"file_count":ship["file_count"],"symlink_count":ship["symlink_count"],"policy":{"path":"runtimes/nemo-provenance-policy.json","sha256":v.file_digest("runtimes/nemo-provenance-policy.json")},"source":{"path":"../${FROZEN}","sha256":src["nemo_runtime_sha256"],"file_count":src["file_count"],"symlink_count":src["symlink_count"]},"delta":{}}
doc=v.render_delta_block_v2(m)+"\\n"+v.render_source_block_v2(m["source"])+"\\n"
for tree in ("runtimes/nemo-relay","../${FROZEN}"):
 with open(os.path.join(tree,"TRANSFER-PROVENANCE.md"),"w") as f:f.write(doc)
with open("runtimes/nemo-transfer-manifest.json","w") as f:json.dump(m,f)
`, root], root);
  command("git", ["init", "-q"], root);
  command("git", ["add", "."], root);
  command("git", ["-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
    "-c", "commit.gpgsign=false", "commit", "-qm", "fixture"], root);
  const bundle = path.join(workspace, "source");
  const manifest = createSource(root, bundle);
  const expected = sha256(fs.readFileSync(path.join(bundle, "source-manifest.json")));
  return { workspace, root, bundle, manifest, expected };
}
function qualification(f) {
  const evidence = path.join(f.workspace, "qualification-evidence");
  fs.mkdirSync(evidence);
  const artifactBindings = {};
  for (const role of ["nemo_runtime", "crabedence", "plugin_host"]) {
    const bytes = Buffer.from(`synthetic fixture artifact: ${role}\n`);
    const file = `artifacts/${role}`;
    put(evidence, file, bytes, 0o755);
    artifactBindings[role] = { file, sha256: sha256(bytes) };
  }
  const gates = Object.entries(requiredQualificationGates(path.join(f.bundle, "root"))).map(([id, type]) => {
    const file = `gate-results/${id}.log`;
    const bytes = Buffer.from(`synthetic fixture evidence: ${id}\n`);
    put(evidence, file, bytes);
    return {
      gate_id: id, gate_type: type, mandatory: true, status: "PASS", exit_code: 0,
      tests_executed: ["TEST", "INTEGRATION"].includes(type) ? 1 : 0,
      tests_failed: 0, tests_skipped: 0, duration_ms: 1,
      evidence: { file, sha256: sha256(bytes) },
    };
  });
  const inner = {
    schema_version: 2, gates,
    release_status: "PASS", artifact_promotable: true,
    gate_summary: { total: gates.length, passed: gates.length, failed: 0 },
    outer_provenance: {
      source_commit: f.manifest.source_commit,
      source_tree_digest: f.manifest.source_tree_digest,
      capability_registry_digest: f.manifest.capability_registry_digest,
      artifact_bindings: artifactBindings,
    },
  };
  put(evidence, "qualification.json", JSON.stringify(inner));
  const record = {
    format: "nemo-outer-qualification-v1", status: "passed",
    source_commit: f.manifest.source_commit,
    source_tree_digest: f.manifest.source_tree_digest,
    capability_registry_digest: f.manifest.capability_registry_digest,
    qualification_bundle_digest: evidenceDigest(evidence),
    inner_qualification: "qualification.json", artifact_bindings: artifactBindings,
    checks: gates.map((g) => ({ gate_id: g.gate_id, command: `synthetic fixture ${g.gate_id}`,
      exit_code: 0, evidence_paths: [g.evidence.file] })),
  };
  const recordPath = path.join(f.workspace, "qualification.json");
  put(f.workspace, "qualification.json", JSON.stringify(record));
  return { evidence, record, recordPath, inner };
}

test("canonical source binds all HEAD paths, outer documents, symlinks and executable modes", (t) => {
  const f = fixture(t);
  const expectedPaths = command("git", ["ls-tree", "-rz", "--name-only", "HEAD"], f.root).split("\0").filter(Boolean);
  assert.deepEqual(f.manifest.entries.map((e) => e.path).sort(), expectedPaths.sort());
  assert.equal(f.manifest.dirty_paths.length, 0);
  assert.ok(f.manifest.head_byte_differences.includes("checkout-filter.cmd"));
  assert.equal(fs.readFileSync(path.join(f.bundle, "root/checkout-filter.cmd"), "utf8"), "echo fixture\r\n");
  assert.ok(f.manifest.entries.find((e) => e.path === `${RUNTIME}/manifest-link`).target === "Cargo.toml");
  assert.equal(f.manifest.entries.find((e) => e.path === `${CRAB}/scripts/build.sh`).executable, true);
  assert.equal(f.manifest.qualification_bundle_digest, null);
  assert.equal(f.manifest.capability_registry_digest, sha256("[]"));
  assert.ok(f.manifest.digest_semantics.plugin_host_digest.includes("NOT a binary"));
  const second = path.join(f.workspace, "second-source");
  assert.equal(canonical(createSource(f.root, second)), canonical(f.manifest));
  assert.equal(verifyBundle(second, f.expected).source_tree_digest, f.manifest.source_tree_digest);
});

test("extracted verification fails content, executable mode, symlink, missing and extra paths", (t) => {
  const f = fixture(t);
  const mutations = [
    (root) => put(root, "README.md", "tampered"),
    (root) => fs.chmodSync(path.join(root, CRAB, "scripts/build.sh"), 0o644),
    (root) => { fs.unlinkSync(path.join(root, RUNTIME, "manifest-link")); fs.symlinkSync("Cargo.lock", path.join(root, RUNTIME, "manifest-link")); },
    (root) => fs.unlinkSync(path.join(root, "authority/policy.json")),
    (root) => put(root, "injected.txt", "extra"),
    (root) => fs.mkdirSync(path.join(root, "empty-extra-directory")),
  ];
  mutations.forEach((mutate, i) => {
    const copy = path.join(f.workspace, `tamper-${i}`);
    fs.cpSync(f.bundle, copy, { recursive: true, verbatimSymlinks: true });
    mutate(path.join(copy, "root"));
    assert.throws(() => verifyBundle(copy, f.expected), /tampered|missing\/extra/);
  });
});

test("manifest trust anchor rejects replacement manifest and forged registry payload", (t) => {
  const f = fixture(t);
  assert.throws(() => verifyBundle(f.bundle), /trusted/);
  const p = path.join(f.bundle, "source-manifest.json");
  const changed = structuredClone(f.manifest);
  changed.registry_envelope.canonical_payload = Buffer.from('[{"forged":true}]').toString("base64");
  fs.writeFileSync(p, `${canonical(changed)}\n`);
  assert.throws(() => verifyBundle(f.bundle, f.expected), /trusted SHA/);
  assert.throws(() => verifyBundle(f.bundle, sha256(fs.readFileSync(p))), /envelope payload mismatch/);
});

test("unsafe paths, normalized collisions and symlink ancestors fail closed", (t) => {
  for (const p of ["/absolute", "../escape", "x/../escape", "x\\y", "x\nname", "x/.git/config", ".github/agents/private"]) {
    assert.throws(() => safePath(p), /unsafe/);
  }
  const f = fixture(t);
  put(f.root, "Case.txt", "one");
  put(f.root, "case.txt", "two");
  command("git", ["add", "Case.txt", "case.txt"], f.root);
  command("git", ["-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
    "-c", "commit.gpgsign=false", "commit", "-qm", "collision"], f.root);
  assert.throws(() => createSource(f.root, path.join(f.workspace, "collision")), /colliding/);
  command("git", ["reset", "--hard", "-q", "HEAD~1"], f.root);
  put(f.root, "Folder/a", "one");
  put(f.root, "folder/b", "two");
  command("git", ["add", "Folder/a", "folder/b"], f.root);
  command("git", ["-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
    "-c", "commit.gpgsign=false", "commit", "-qm", "directory collision"], f.root);
  assert.throws(() => createSource(f.root, path.join(f.workspace, "directory-collision")), /colliding path component/);
  command("git", ["reset", "--hard", "-q", "HEAD~1"], f.root);
  fs.renameSync(path.join(f.root, "authority"), path.join(f.root, "real-authority"));
  fs.symlinkSync("real-authority", path.join(f.root, "authority"));
  assert.throws(() => createSource(f.root, path.join(f.workspace, "ancestor")), /unsafe ancestor/);
});

test("dirty worktree content is captured, not confused with HEAD, and cannot finalize", (t) => {
  const f = fixture(t);
  put(f.root, "README.md", "dirty worktree\n");
  fs.chmodSync(path.join(f.root, CRAB, "scripts/build.sh"), 0o644);
  const source = path.join(f.workspace, "dirty-source");
  const m = createSource(f.root, source);
  assert.notEqual(m.source_tree_digest, f.manifest.source_tree_digest);
  assert.equal(m.source_commit, f.manifest.source_commit);
  assert.deepEqual(m.dirty_paths, ["README.md", `${CRAB}/scripts/build.sh`]);
  const expected = sha256(fs.readFileSync(path.join(source, "source-manifest.json")));
  verifyBundle(source, expected);
  const q = qualification({ ...f, manifest: m });
  assert.throws(() => finalize(f.root, source, expected, q.recordPath, q.evidence,
    path.join(f.workspace, "release")), /HEAD-clean/);
});

test("runtime canonical union includes ignored untracked source but excludes generated output", (t) => {
  const f = fixture(t);
  // The policy omits the provenance document from canonical runtime inventory,
  // but Git HEAD still binds it in the outer inventory.
  assert.ok(f.manifest.entries.some((e) => e.path === `${RUNTIME}/TRANSFER-PROVENANCE.md`));
  assert.ok(!f.manifest.runtime_inventory.includes(`${RUNTIME}/TRANSFER-PROVENANCE.md`));
  put(f.root, `${RUNTIME}/target/generated`, "not source");
  put(f.root, `${FROZEN}/target/generated`, "not source");
  const m = createSource(f.root, path.join(f.workspace, "with-build-output"));
  assert.equal(m.source_tree_digest, f.manifest.source_tree_digest);
  // Add the same canonical, untracked source to BOTH runtimes and rebind the
  // existing transfer declarations using its verifier's canonical implementation.
  for (const tree of [RUNTIME, FROZEN]) put(f.root, `${tree}/new-source.rs`, "// union\n");
  command("python3", ["-B", "-c", `
import importlib.util,os,json,sys
os.chdir(os.path.join(sys.argv[1],${JSON.stringify(CRAB)}))
spec=importlib.util.spec_from_file_location("v","scripts/verify-nemo-transfer.py");v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
with open("runtimes/nemo-transfer-manifest.json") as f:m=json.load(f)
p=v.read_policy(m["policy"]["path"]);ship=v.digest_runtime_v2(m["tree"],p);src=v.digest_runtime_v2(m["source"]["path"],p)
m["shipped_tree_sha256"]=ship["nemo_runtime_sha256"];m["file_count"]=ship["file_count"]
m["source"]["sha256"]=src["nemo_runtime_sha256"];m["source"]["file_count"]=src["file_count"]
doc=v.render_delta_block_v2(m)+"\\n"+v.render_source_block_v2(m["source"])+"\\n"
for tree in (m["tree"],m["source"]["path"]):
 with open(os.path.join(tree,"TRANSFER-PROVENANCE.md"),"w") as f:f.write(doc)
with open("runtimes/nemo-transfer-manifest.json","w") as f:json.dump(m,f)
`, f.root], f.root);
  const union = createSource(f.root, path.join(f.workspace, "union"));
  for (const tree of [RUNTIME, FROZEN]) {
    assert.ok(union.entries.some((e) => e.path === `${tree}/new-source.rs`));
    assert.ok(union.dirty_paths.includes(`${tree}/new-source.rs`));
  }
});

test("finalization requires source identity, registry identity, actual check evidence and bundle digest", (t) => {
  const f = fixture(t);
  const q = qualification(f);
  const circular = path.join(q.evidence, "outer-record.json");
  put(q.evidence, "outer-record.json", JSON.stringify(q.record));
  assert.throws(() => finalize(f.root, f.bundle, f.expected, circular, q.evidence,
    path.join(f.workspace, "circular-release")), /circular hashes/);
  fs.unlinkSync(circular);
  for (const mutation of [
    { source_commit: "0".repeat(40) },
    { source_tree_digest: "0".repeat(64) },
    { capability_registry_digest: "0".repeat(64) },
    { qualification_bundle_digest: "0".repeat(64) },
    { status: "not-run" },
    { checks: [] },
    { checks: [{ command: "failed", exit_code: 1, evidence_paths: ["checks/log.txt"] }] },
    { checks: [{ command: "missing", exit_code: 0, evidence_paths: ["absent.log"] }] },
  ]) {
    fs.writeFileSync(q.recordPath, JSON.stringify({ ...q.record, ...mutation }));
    assert.throws(() => finalize(f.root, f.bundle, f.expected, q.recordPath, q.evidence,
      path.join(f.workspace, "bad-release")), /mismatch|required|missing check/);
    assert.equal(fs.existsSync(path.join(f.workspace, "bad-release")), false);
  }
  fs.writeFileSync(q.recordPath, JSON.stringify(q.record));
  const release = path.join(f.workspace, "release");
  const r = finalize(f.root, f.bundle, f.expected, q.recordPath, q.evidence, release);
  assert.equal(r.qualification_bundle_digest, q.record.qualification_bundle_digest);
  assert.match(r.qualification_statement, /did not execute/);
  const expectedRelease = sha256(fs.readFileSync(path.join(release, "release-manifest.json")));
  assert.throws(() => verifyBundle(release, f.expected), /expected-release-manifest/);
  verifyBundle(release, f.expected, expectedRelease);
  put(release, "evidence/gate-results/outer-source-archive.log", "tampered evidence");
  assert.throws(() => verifyBundle(release, f.expected, expectedRelease), /tampered/);
  const changed = JSON.parse(fs.readFileSync(path.join(release, "release-manifest.json")));
  changed.qualification_statement = "forged claim";
  put(release, "release-manifest.json", canonical(changed));
  assert.throws(() => verifyBundle(release, f.expected, expectedRelease), /release manifest.*trusted/);
});

test("finalization refuses post-qualification source or HEAD changes", (t) => {
  const f = fixture(t);
  const q = qualification(f);
  put(f.root, "untracked-source.go", "package unexpected\n");
  assert.throws(() => finalize(f.root, f.bundle, f.expected, q.recordPath, q.evidence,
    path.join(f.workspace, "untracked-release")), /untracked outer paths/);
  assert.throws(() => createSource(f.root, path.join(f.workspace, "untracked-source")), /untracked outer paths/);
  command("git", ["add", "untracked-source.go"], f.root);
  assert.throws(() => createSource(f.root, path.join(f.workspace, "staged-source")), /index-only additions/);
  command("git", ["reset", "-q", "HEAD", "--", "untracked-source.go"], f.root);
  fs.unlinkSync(path.join(f.root, "untracked-source.go"));
  put(f.root, "README.md", "changed after qualification");
  assert.throws(() => finalize(f.root, f.bundle, f.expected, q.recordPath, q.evidence,
    path.join(f.workspace, "bad-release")), /current source differs|HEAD-clean worktree/);
  command("git", ["checkout", "--", "README.md"], f.root);
  command("git", ["-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
    "-c", "commit.gpgsign=false", "commit", "--allow-empty", "-qm", "new HEAD"], f.root);
  assert.throws(() => finalize(f.root, f.bundle, f.expected, q.recordPath, q.evidence,
    path.join(f.workspace, "bad-release")), /current HEAD/);
});

test("self-reported PASS cannot replace complete admitted gates and tested artifact bindings", (t) => {
  const f = fixture(t);
  const q = qualification(f);
  const mutations = [
    (inner) => { inner.outer_provenance.source_tree_digest = "0".repeat(64); },
    (inner) => { inner.gates.find((g) => g.gate_id === "nemo-runtime-e2e").tests_executed = 0; },
    (inner) => { inner.gates.find((g) => g.gate_id === "nemo-runtime-e2e").tests_skipped = 1; },
    (inner) => { inner.gates[0].evidence.sha256 = "0".repeat(64); },
    (inner) => { inner.outer_provenance.artifact_bindings.plugin_host.sha256 = "0".repeat(64); },
    (inner) => { inner.gate_summary.passed = 0; },
    (inner, record) => {
      inner.gates = inner.gates.filter((g) => g.gate_id !== "nemo-plugin-host");
      record.checks = record.checks.filter((g) => g.gate_id !== "nemo-plugin-host");
    },
    (inner, record) => { delete record.artifact_bindings.crabedence; },
  ];
  mutations.forEach((mutate, i) => {
    const inner = structuredClone(q.inner), record = structuredClone(q.record);
    mutate(inner, record);
    put(q.evidence, "qualification.json", JSON.stringify(inner));
    record.qualification_bundle_digest = evidenceDigest(q.evidence);
    fs.writeFileSync(q.recordPath, JSON.stringify(record));
    assert.throws(() => finalize(f.root, f.bundle, f.expected, q.recordPath, q.evidence,
      path.join(f.workspace, `rejected-${i}`)));
    assert.equal(fs.existsSync(path.join(f.workspace, `rejected-${i}`)), false);
  });
});

test("archive independently carries whole outer root and real frozen reference without Git or Go", (t) => {
  const f = fixture(t);
  const q = qualification(f);
  const release = path.join(f.workspace, "release");
  finalize(f.root, f.bundle, f.expected, q.recordPath, q.evidence, release);
  const expectedRelease = sha256(fs.readFileSync(path.join(release, "release-manifest.json")));
  const tarball = path.join(f.workspace, "outer.tar.gz");
  archive(release, f.expected, tarball, expectedRelease);
  fs.rmSync(f.root, { recursive: true });
  fs.rmSync(f.bundle, { recursive: true });
  fs.rmSync(release, { recursive: true });
  const extracted = path.join(f.workspace, "independent");
  extract(tarball, extracted, f.expected, expectedRelease);
  assert.equal(fs.existsSync(path.join(extracted, "root/.git")), false);
  assert.equal(fs.lstatSync(path.join(extracted, "root", FROZEN)).isDirectory(), true);
  assert.equal(fs.lstatSync(path.join(extracted, "root", FROZEN)).isSymbolicLink(), false);
  assert.equal(fs.readFileSync(path.join(extracted, "root/README.md"), "utf8"), "outer source\n");
  const bin = path.join(f.workspace, "verification-only-bin");
  fs.mkdirSync(bin);
  for (const name of ["python3", "bash", "jq", "shasum", "awk", "seq", "dirname", "grep"]) {
    fs.symlinkSync(command("sh", ["-c", `command -v ${name}`], f.workspace).trim(), path.join(bin, name));
  }
  const cli = path.join(scripts, "outer-release-manifest.mjs");
  const result = execFileSync(process.execPath, [cli, "verify", "--bundle", extracted,
    "--expected-manifest-sha256", f.expected, "--expected-release-manifest-sha256", expectedRelease], {
    encoding: "utf8", env: { ...process.env, PATH: bin, PYTHONDONTWRITEBYTECODE: "1" },
  });
  assert.equal(JSON.parse(result).source_tree_digest, f.manifest.source_tree_digest);
});

test("archive extraction rejects traversal, symlink ancestors, collisions and special objects before writing", (t) => {
  const f = fixture(t);
  const attacks = [
    [{ name: "../outside", kind: "file" }],
    [{ name: "link", kind: "symlink", target: "../outside" }],
    [{ name: "root", kind: "symlink", target: "other" }, { name: "root/file", kind: "file" }],
    [{ name: "duplicate", kind: "file" }, { name: "duplicate", kind: "file" }],
    [{ name: "Case", kind: "file" }, { name: "case", kind: "file" }],
    [{ name: "fifo", kind: "fifo" }],
    [{ name: "hard", kind: "hardlink", target: "outside" }],
  ];
  attacks.forEach((members, i) => {
    const tarball = path.join(f.workspace, `attack-${i}.tar.gz`);
    command("python3", ["-B", "-c", `
import tarfile,io,json,sys
with tarfile.open(sys.argv[1],"w:gz") as t:
 for m in json.loads(sys.argv[2]):
  x=tarfile.TarInfo(m["name"]);x.mode=0o644
  if m["kind"]=="file":x.size=1;t.addfile(x,io.BytesIO(b"x"))
  else:
   x.type={"symlink":tarfile.SYMTYPE,"hardlink":tarfile.LNKTYPE,"fifo":tarfile.FIFOTYPE}[m["kind"]];x.linkname=m.get("target","");t.addfile(x)
`, tarball, JSON.stringify(members)], f.workspace);
    const output = path.join(f.workspace, `attack-${i}`);
    assert.throws(() => extract(tarball, output, f.expected));
    assert.equal(fs.existsSync(output), false);
    assert.equal(fs.existsSync(path.join(f.workspace, "outside")), false);
  });
});
