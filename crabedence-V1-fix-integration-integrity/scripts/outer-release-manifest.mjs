#!/usr/bin/env node
// Source identity is not qualification. Finalization consumes, but never invents,
// a qualification record from the operator's actual build/qualification run.
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import { pathToFileURL } from "node:url";

const CRAB = "crabedence-V1-fix-integration-integrity";
const RUNTIME = `${CRAB}/runtimes/nemo-relay`;
const FROZEN = "NEMO-feat-native-plugin-isolation";
const TRANSFER = `${CRAB}/runtimes/nemo-transfer-manifest.json`;
const VERIFIER = `${CRAB}/scripts/verify-nemo-transfer.py`;
const POLICY = `${CRAB}/runtimes/nemo-provenance-policy.json`;
const FORMAT = "nemo-outer-source-v1";
const RELEASE = "nemo-outer-release-v1";
const DIGEST = /^[a-f0-9]{64}$/;
const COMMIT = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/;
const semantics = {
  source_tree_digest: "sha256 of canonical JSON ordered WORKTREE entry inventory; all HEAD paths union both policy canonical runtime inventories",
  nemo_runtime_digest: "source: existing Python format-2 shipped runtime canonical digest",
  crabedence_digest: "source: canonical outer entry inventory below Crabedence root (including vendored runtime)",
  plugin_host_digest: "source: shipped crates/plugin-host and crates/native-loader entry inventory; NOT a binary digest",
  capability_registry_digest: "policy: authoritative go run ./cmd/registry-digest -envelope canonical_payload sha256, executed in frozen source copy",
  abi_digest: "source: shipped crates/native-abi and crates/worker-proto entry inventory",
  build_recipe_digest: "source: scripts, workflows, Makefiles, build.rs and project build configuration entry inventory",
  qualification_bundle_digest: "artifact: exact evidence entry inventory; null in source manifest; excludes qualification record and release manifest",
  toolchain_lock_digest: "source: tracked/union dependency locks, module manifests and toolchain selectors entry inventory",
};
const fail = (message) => { throw new Error(message); };
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
export const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
export function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}
const digest = (value) => sha256(canonical(value));
const ordered = (values) => [...values].sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
const run = (command, args, cwd) => execFileSync(command, args, {
  cwd, encoding: "utf8", maxBuffer: 64 * 1024 * 1024, stdio: ["ignore", "pipe", "pipe"],
  env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1", LC_ALL: "C", GIT_OPTIONAL_LOCKS: "0" },
});

export function safePath(p) {
  if (typeof p !== "string" || !p || p.includes("\\") || /[\x00-\x1f\x7f]/.test(p)
      || p.includes("\ufffd") || p.startsWith("/") || /^[A-Za-z]:/.test(p)
      || p.split("/").some((s) => !s || s === "." || s === ".." || s === ".git")
      || /(^|\/)\.github\/agents(\/|$)/.test(p)) fail(`unsafe path: ${p}`);
  return p;
}
function absolute(p) {
  if (!path.isAbsolute(p)) fail(`absolute path required: ${p}`);
  const resolved = path.resolve(p);
  if (/(^|\/)\.github\/agents(\/|$)/.test(resolved)) fail(`unsafe path: ${resolved}`);
  let current = path.parse(resolved).root;
  for (const part of resolved.slice(current.length).split("/").filter(Boolean)) {
    current = path.join(current, part);
    if (fs.existsSync(current) && fs.lstatSync(current).isSymbolicLink()) fail(`symlink ancestor: ${current}`);
  }
  return resolved;
}
function ancestors(root, relative) {
  safePath(relative);
  const stamps = [];
  let current = absolute(root);
  const rootStat = fs.lstatSync(current, { bigint: true });
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) fail(`unsafe root: ${current}`);
  stamps.push([current, rootStat.dev, rootStat.ino]);
  for (const part of relative.split("/").slice(0, -1)) {
    current = path.join(current, part);
    const s = fs.lstatSync(current, { bigint: true });
    if (!s.isDirectory() || s.isSymbolicLink()) fail(`unsafe ancestor: ${current}`);
    stamps.push([current, s.dev, s.ino]);
  }
  return () => {
    absolute(root);
    for (const [p, dev, ino] of stamps) {
      const s = fs.lstatSync(p, { bigint: true });
      if (!s.isDirectory() || s.dev !== dev || s.ino !== ino) fail(`ancestor changed during read: ${p}`);
    }
  };
}
function linkTarget(p, target) {
  if (!target || path.posix.isAbsolute(target) || target.includes("\\")
      || /[\x00-\x1f\x7f]/.test(target) || /^[A-Za-z]:/.test(target)) fail(`unsafe symlink: ${p}`);
  const resolved = path.posix.normalize(path.posix.join(path.posix.dirname(p), target));
  safePath(resolved);
}
function stamp(s) {
  return [s.dev, s.ino, s.size, s.mode, s.mtimeNs, s.ctimeNs].map(String);
}
function readEntry(root, p, copyTo, withBytes = false) {
  const check = ancestors(root, p);
  const full = path.join(root, p);
  const before = fs.lstatSync(full, { bigint: true });
  let entry;
  let bytes;
  if (before.isSymbolicLink()) {
    const target = fs.readlinkSync(full);
    linkTarget(p, target);
    entry = { path: p, kind: "symlink", target };
  } else if (before.isFile()) {
    const fd = fs.openSync(full, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    try {
      if (!same(stamp(before), stamp(fs.fstatSync(fd, { bigint: true })))) fail(`changed before read: ${p}`);
      bytes = fs.readFileSync(fd);
      if (!same(stamp(before), stamp(fs.fstatSync(fd, { bigint: true })))) fail(`changed during read: ${p}`);
    } finally { fs.closeSync(fd); }
    entry = { path: p, kind: "file", executable: Boolean(before.mode & 0o111n), sha256: sha256(bytes) };
  } else fail(`unsupported source object: ${p}`);
  if (!same(stamp(before), stamp(fs.lstatSync(full, { bigint: true })))) fail(`changed after read: ${p}`);
  check();
  if (copyTo) {
    const dest = path.join(copyTo, p);
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    if (entry.kind === "symlink") fs.symlinkSync(entry.target, dest);
    else fs.writeFileSync(dest, bytes, { flag: "wx", mode: entry.executable ? 0o755 : 0o644 });
  }
  return withBytes ? { entry, bytes } : entry;
}
function validatePaths(paths) {
  const seen = new Set();
  const collision = new Set();
  const namespace = new Map();
  for (const p of paths) {
    safePath(p);
    const folded = p.normalize("NFC").toLowerCase();
    if (seen.has(p) || collision.has(folded)) fail(`duplicate/colliding path: ${p}`);
    seen.add(p);
    collision.add(folded);
    let name = p;
    while (name !== ".") {
      const key = name.normalize("NFC").toLowerCase();
      if (namespace.has(key) && namespace.get(key) !== name) fail(`duplicate/colliding path component: ${name}`);
      namespace.set(key, name);
      name = path.posix.dirname(name);
    }
  }
  for (const p of paths) {
    let parent = path.posix.dirname(p);
    while (parent !== ".") {
      if (seen.has(parent)) fail(`source path is also an ancestor: ${parent}`);
      parent = path.posix.dirname(parent);
    }
  }
}
function inventory(root) {
  const files = [];
  const directories = [];
  function walk(dir, prefix) {
    for (const name of fs.readdirSync(dir)) {
      const p = prefix ? `${prefix}/${name}` : name;
      safePath(p);
      const s = fs.lstatSync(path.join(root, p));
      if (s.isDirectory() && !s.isSymbolicLink()) {
        directories.push(p);
        walk(path.join(root, p), p);
      } else files.push(p);
    }
  }
  walk(absolute(root), "");
  validatePaths(files);
  return { files: ordered(files), directories: ordered(directories) };
}
function expectedDirs(entries) {
  const dirs = new Set();
  for (const { path: p } of entries) {
    let d = path.posix.dirname(p);
    while (d !== ".") { dirs.add(d); d = path.posix.dirname(d); }
  }
  return ordered(dirs);
}
function verifyEntries(root, entries) {
  if (!Array.isArray(entries) || entries.length === 0) fail("empty inventory");
  validatePaths(entries.map((e) => e.path));
  if (!same(entries.map((e) => e.path), ordered(entries.map((e) => e.path)))) fail("inventory not ordered");
  const actual = inventory(root);
  if (!same(actual.files, entries.map((e) => e.path)) || !same(actual.directories, expectedDirs(entries))) {
    fail("missing/extra tree paths");
  }
  for (const e of entries) if (canonical(readEntry(root, e.path)) !== canonical(e)) fail(`tampered path: ${e.path}`);
}
function head(root) {
  if (path.resolve(run("git", ["rev-parse", "--show-toplevel"], root).trim()) !== root) fail("root is not outer Git root");
  const commit = run("git", ["rev-parse", "HEAD"], root).trim();
  if (!COMMIT.test(commit)) fail("invalid HEAD");
  const records = run("git", ["ls-tree", "-rz", "--full-tree", commit], root).split("\0").filter(Boolean);
  const entries = records.map((r) => {
    const match = /^([0-9]+) (blob|commit) ([a-f0-9]+)\t([\s\S]+)$/.exec(r);
    if (!match || match[2] !== "blob" || !["100644", "100755", "120000"].includes(match[1])) fail("unsupported Git entry");
    return { path: safePath(match[4]), mode: match[1], oid: match[3] };
  }).sort((a, b) => Buffer.compare(Buffer.from(a.path), Buffer.from(b.path)));
  validatePaths(entries.map((e) => e.path));
  const objectFormat = run("git", ["rev-parse", "--show-object-format"], root).trim();
  if (!["sha1", "sha256"].includes(objectFormat)) fail("unsupported Git hash format");
  return { commit, entries, objectFormat };
}
function gitBlob(entry) {
  return entry.kind === "symlink" ? Buffer.from(entry.target) : null;
}
function dirtyPaths(root, headEntries, entries, format) {
  const byPath = new Map(headEntries.map((e) => [e.path, e]));
  return entries.filter((e) => {
    const h = byPath.get(e.path);
    if (!h) return true;
    const bytes = gitBlob(e) ?? readEntry(root, e.path, undefined, true).bytes;
    const oid = crypto.createHash(format).update(`blob ${bytes.length}\0`).update(bytes).digest("hex");
    const mode = e.kind === "symlink" ? "120000" : e.executable ? "100755" : "100644";
    return oid !== h.oid || mode !== h.mode;
  }).map((e) => e.path);
}
function gitDirtyPaths(root, headEntries, entries) {
  const tracked = new Set(headEntries.map((e) => e.path));
  const changed = run("git", ["diff", "--name-only", "-z", "--no-ext-diff", "--no-textconv", "HEAD"], root)
    .split("\0").filter(Boolean);
  for (const p of changed) safePath(p);
  return ordered(new Set([...changed, ...entries.filter((e) => !tracked.has(e.path)).map((e) => e.path)]));
}
function untrackedOuter(root, paths) {
  const allowed = new Set(paths);
  const extra = run("git", ["ls-files", "--cached", "--others", "--exclude-standard", "-z"], root)
    .split("\0").filter(Boolean).filter((p) => !allowed.has(p));
  if (extra.length) fail(`untracked outer paths or index-only additions not in source inventory (commit source or ignore output): ${extra[0]}`);
}
const PYTHON_INVENTORY = `
import importlib.util,json,os,sys,contextlib
root=sys.argv[1]
spec=importlib.util.spec_from_file_location("outer_transfer",os.path.join(root,${JSON.stringify(VERIFIER)}))
v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
os.chdir(os.path.join(root,${JSON.stringify(CRAB)}))
with open("runtimes/nemo-transfer-manifest.json") as f:m=json.load(f)
if m.get("provenance_format_version") != 2:raise ValueError("format 2 required")
if m.get("tree") != "runtimes/nemo-relay" or m.get("source",{}).get("path") != "../NEMO-feat-native-plugin-isolation":raise ValueError("outer runtime roots required")
if m.get("policy",{}).get("path") != "runtimes/nemo-provenance-policy.json":raise ValueError("outer policy required")
for tree in (m["tree"],m["source"]["path"]):
 for d,ds,files in os.walk(tree,followlinks=False):
  if os.path.basename(d)==".github" and "agents" in ds:raise ValueError("forbidden agent directory")
with contextlib.redirect_stdout(sys.stderr):v.verify_manifest("runtimes/nemo-transfer-manifest.json",True)
policy=v.read_policy(m["policy"]["path"])
paths=[]
for tree in (m["tree"],m["source"]["path"]):
 for e in v.canonical_entries(tree,policy):
  paths.append(os.path.relpath(os.path.join(os.getcwd(),tree,e[0][2:]),root).replace(os.sep,"/"))
print(json.dumps({"paths":paths,"runtime_digest":m["shipped_tree_sha256"],"frozen_digest":m["source"]["sha256"]}))
`;
function runtimes(root) {
  // Validate roots before invoking the verifier, which otherwise follows roots.
  for (const p of [TRANSFER, VERIFIER, POLICY, `${RUNTIME}/Cargo.toml`, `${FROZEN}/Cargo.toml`]) {
    if (readEntry(root, p).kind !== "file") fail(`regular provenance input required: ${p}`);
  }
  const result = JSON.parse(run("python3", ["-B", "-c", PYTHON_INVENTORY, root], root));
  for (const p of result.paths) safePath(p);
  return result;
}
function componentDigests(entries, runtimeDigest) {
  const subset = (predicate) => {
    const selected = entries.filter((e) => predicate(e.path));
    if (!selected.length) fail("required source component inventory is empty");
    return digest(selected);
  };
  const below = (p, prefix) => p.startsWith(`${prefix}/`);
  return {
    nemo_runtime_digest: runtimeDigest,
    crabedence_digest: subset((p) => below(p, CRAB)),
    plugin_host_digest: subset((p) => below(p, `${RUNTIME}/crates/plugin-host`) || below(p, `${RUNTIME}/crates/native-loader`)),
    abi_digest: subset((p) => below(p, `${RUNTIME}/crates/native-abi`) || below(p, `${RUNTIME}/crates/worker-proto`)),
    build_recipe_digest: subset((p) => /(^|\/)(scripts|\.github\/(?:workflows|actions))\//.test(p)
      || /(^|\/)(Makefile|GNUmakefile|[^/]+\.mk|build\.rs|Cargo\.toml|go\.mod|go\.work|pyproject\.toml|setup\.py|setup\.cfg|package\.json|CMakeLists\.txt|\.goreleaser[^/]*)$/.test(p)
      || /(^|\/)\.cargo\/config(?:\.toml)?$/.test(p)),
    toolchain_lock_digest: subset((p) => /(^|\/)(Cargo\.lock|go\.mod|go\.sum|go\.work(?:\.sum)?|package-lock\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lockb?|uv\.lock|poetry\.lock|rust-toolchain(?:\.toml)?|\.tool-versions|\.(?:python|node|go)-version|\.nvmrc|requirements[^/]*\.txt)$/.test(p)),
  };
}
function envelope(value) {
  if (!value || !DIGEST.test(value.registry_sha256) || typeof value.canonical_payload !== "string") fail("invalid registry envelope");
  const bytes = Buffer.from(value.canonical_payload, "base64");
  if (bytes.toString("base64") !== value.canonical_payload || sha256(bytes) !== value.registry_sha256
      || !Array.isArray(JSON.parse(bytes.toString("utf8")))) fail("registry envelope payload mismatch");
  return value.registry_sha256;
}
function writeJSON(p, value) {
  fs.writeFileSync(p, `${canonical(value)}\n`, { flag: "wx", mode: 0o644 });
}
function jsonBytes(p) {
  const root = path.dirname(absolute(p));
  const { entry, bytes } = readEntry(root, path.basename(p), undefined, true);
  if (entry.kind !== "file") fail(`regular JSON required: ${p}`);
  return bytes;
}
function jsonFile(p) { return JSON.parse(jsonBytes(p).toString("utf8")); }
function newDirectory(p, sourceRoot) {
  p = absolute(p);
  if (p === sourceRoot || (sourceRoot && sourceRoot.startsWith(`${p}/`))) fail("output cannot contain source root");
  if (fs.existsSync(p)) fail(`output must not exist: ${p}`);
  fs.mkdirSync(p, { recursive: true });
  return p;
}
export function createSource(root, out) {
  root = absolute(root);
  const initial = head(root);
  const runtime = runtimes(root);
  const paths = ordered(new Set([...initial.entries.map((e) => e.path), ...runtime.paths]));
  validatePaths(paths);
  for (const p of paths) ancestors(root, p);
  untrackedOuter(root, paths);
  out = absolute(out);
  if (paths.some((p) => path.join(root, p) === out || path.join(root, p).startsWith(`${out}/`))) fail("output overlaps source inventory");
  newDirectory(out, root);
  const frozen = path.join(out, "root");
  fs.mkdirSync(frozen);
  try {
    const entries = paths.map((p) => readEntry(root, p, frozen));
    verifyEntries(frozen, entries);
    const frozenRuntime = runtimes(frozen);
    if (canonical(frozenRuntime) !== canonical(runtime)) fail("runtime changed while freezing");
    const registry = JSON.parse(run("go", ["run", "./cmd/registry-digest", "-envelope"], path.join(frozen, CRAB)));
    const capabilityRegistryDigest = envelope(registry);
    verifyEntries(frozen, entries);
    const headDifferences = dirtyPaths(frozen, initial.entries, entries, initial.objectFormat);
    const dirty = gitDirtyPaths(root, initial.entries, entries);
    const manifest = {
      format: FORMAT, source_commit: initial.commit, source_tree_digest: digest(entries),
      ...componentDigests(entries, runtime.runtime_digest),
      capability_registry_digest: capabilityRegistryDigest,
      qualification_bundle_digest: null, digest_semantics: semantics,
      registry_envelope: registry, head_inventory: initial.entries, entries,
      source_object_format: initial.objectFormat,
      runtime_inventory: ordered(runtime.paths), frozen_runtime_digest: runtime.frozen_digest,
      dirty_paths: dirty,
      head_byte_differences: headDifferences,
    };
    const currentRuntime = runtimes(root);
    if (canonical(currentRuntime) !== canonical(runtime) || canonical(head(root)) !== canonical(initial)) fail("source/HEAD changed during generation");
    untrackedOuter(root, paths);
    if (!same(gitDirtyPaths(root, initial.entries, entries), dirty)) fail("Git worktree status changed during generation");
    for (const e of entries) if (canonical(readEntry(root, e.path)) !== canonical(e)) fail(`source changed during generation: ${e.path}`);
    writeJSON(path.join(out, "source-manifest.json"), manifest);
    return manifest;
  } catch (error) {
    fs.rmSync(out, { recursive: true, force: true });
    throw error;
  }
}
function sourceManifest(bundle, expected) {
  if (!DIGEST.test(expected ?? "")) fail("trusted --expected-manifest-sha256 is required");
  const p = path.join(bundle, "source-manifest.json");
  const bytes = jsonBytes(p);
  if (sha256(bytes) !== expected) fail("source manifest does not match trusted SHA-256");
  const m = JSON.parse(bytes.toString("utf8"));
  if (m.format !== FORMAT || !COMMIT.test(m.source_commit) || m.qualification_bundle_digest !== null
      || canonical(m.digest_semantics) !== canonical(semantics)) fail("invalid source manifest");
  if (digest(m.entries) !== m.source_tree_digest) fail("source digest mismatch");
  if (!["sha1", "sha256"].includes(m.source_object_format)) fail("invalid Git object format");
  validatePaths(m.head_inventory.map((e) => e.path));
  for (const h of m.head_inventory) if (!m.entries.some((e) => e.path === h.path)) fail("missing HEAD path");
  if (envelope(m.registry_envelope) !== m.capability_registry_digest) fail("registry digest mismatch");
  verifyEntries(path.join(bundle, "root"), m.entries);
  if (!same(dirtyPaths(path.join(bundle, "root"), m.head_inventory, m.entries, m.source_object_format), m.head_byte_differences)) fail("HEAD byte-difference inventory mismatch");
  if (!Array.isArray(m.dirty_paths) || !same(m.dirty_paths, ordered(new Set(m.dirty_paths)))
      || m.dirty_paths.some((p) => !m.entries.some((e) => e.path === p))) fail("invalid Git dirty-path declaration");
  const runtime = runtimes(path.join(bundle, "root"));
  if (!same(ordered(runtime.paths), m.runtime_inventory) || runtime.frozen_digest !== m.frozen_runtime_digest) fail("runtime inventory mismatch");
  if (!same(ordered(new Set([...m.head_inventory.map((e) => e.path), ...runtime.paths])), m.entries.map((e) => e.path))) fail("source union mismatch");
  for (const [key, value] of Object.entries(componentDigests(m.entries, runtime.runtime_digest))) {
    if (m[key] !== value) fail(`component digest mismatch: ${key}`);
  }
  return m;
}
function evidenceEntries(root) {
  return inventory(root).files.map((p) => {
    const e = readEntry(root, p);
    if (e.kind !== "file") fail("qualification evidence must contain only regular files");
    return e;
  });
}
export function evidenceDigest(root) { return digest(evidenceEntries(absolute(root))); }
export const OUTER_REQUIRED_GATES = {
  "outer-source-archive": "PROVENANCE",
  "authority-boundary": "STATIC_ANALYSIS",
  "credential-isolation": "STATIC_ANALYSIS",
  "crabedence-build": "BUILD",
  "nemo-runtime-build": "BUILD",
  "nemo-plugin-host-build": "BUILD",
  "nemo-runtime-e2e": "INTEGRATION",
  "nemo-critical-path": "INTEGRATION",
  "nemo-expired-authority": "INTEGRATION",
  "nemo-restart-idempotency": "INTEGRATION",
  "nemo-plugin-host": "INTEGRATION",
  "nemo-installed-distribution": "INTEGRATION",
};
export function requiredQualificationGates(sourceRoot) {
  const p = `${CRAB}/scripts/generate-release-evidence.sh`;
  const { entry, bytes } = readEntry(sourceRoot, p, undefined, true);
  if (entry.kind !== "file") fail("regular qualification producer required");
  const required = { ...OUTER_REQUIRED_GATES };
  const calls = [...bytes.toString("utf8").matchAll(/^\s*(run_gate|run_live_postgres_gate|run_required_live_go_gate)\s+([a-z][a-z0-9-]*)\s+([A-Z_]+|[^\s]+)/gm)];
  if (!calls.length) fail("qualification producer declares no discoverable gates");
  for (const [, runner, id, type] of calls) {
    const gateType = runner === "run_live_postgres_gate" ? "INTEGRATION" : type;
    if (Object.hasOwn(required, id)) fail(`duplicate required qualification gate: ${id}`);
    required[id] = gateType;
  }
  return required;
}
function qualification(record, m, bundleDigest) {
  if (record.format !== "nemo-outer-qualification-v1" || record.status !== "passed"
      || record.source_commit !== m.source_commit || record.source_tree_digest !== m.source_tree_digest
      || record.qualification_bundle_digest !== bundleDigest
      || record.capability_registry_digest !== m.capability_registry_digest) fail("qualification record identity/evidence mismatch");
  if (!Array.isArray(record.checks) || !record.checks.length) fail("qualification checks required");
  safePath(record.inner_qualification);
  const seen = new Set();
  for (const check of record.checks) {
    if (!check || typeof check.gate_id !== "string" || !check.gate_id || seen.has(check.gate_id)
        || typeof check.command !== "string" || !check.command.trim() || check.exit_code !== 0
        || !Array.isArray(check.evidence_paths) || !check.evidence_paths.length) fail("passed checks with evidence required");
    seen.add(check.gate_id);
    for (const p of check.evidence_paths) safePath(p);
  }
}
function qualificationAdmission(sourceRoot, evidenceRoot, record, m, entries) {
  const files = new Map(entries.map((e) => [e.path, e]));
  const boundFile = (ref) => {
    if (!ref || !DIGEST.test(ref.sha256 ?? "")) fail("qualification evidence/artifact digest required");
    safePath(ref.file);
    const e = files.get(ref.file);
    if (!e || e.kind !== "file" || e.sha256 !== ref.sha256) fail(`qualification evidence/artifact binding mismatch: ${ref.file}`);
    return e;
  };
  if (!files.has(record.inner_qualification)) fail("inner qualification record missing from evidence bundle");
  const inner = jsonFile(path.join(evidenceRoot, record.inner_qualification));
  if (!inner.outer_provenance || inner.outer_provenance.source_commit !== m.source_commit
      || inner.outer_provenance.source_tree_digest !== m.source_tree_digest
      || inner.outer_provenance.capability_registry_digest !== m.capability_registry_digest) fail("inner qualification outer-source binding mismatch");
  if (!Array.isArray(inner.gates) || !inner.gates.length) fail("inner qualification gates required");
  const required = requiredQualificationGates(sourceRoot);
  const gates = new Map();
  const innerPrefix = path.posix.dirname(record.inner_qualification);
  for (const gate of inner.gates) {
    if (!gate || typeof gate.gate_id !== "string" || gates.has(gate.gate_id)) fail("duplicate/malformed qualification gate");
    gates.set(gate.gate_id, gate);
    if (!gate.evidence) fail("gate evidence binding required");
    safePath(gate.evidence.file);
    const file = innerPrefix === "." ? gate.evidence.file : `${innerPrefix}/${gate.evidence.file}`;
    boundFile({ file, sha256: gate.evidence.sha256 });
    if (gate.mandatory !== true || gate.status !== "PASS" || gate.exit_code !== 0) fail(`qualification gate not executed/passed: ${gate.gate_id}`);
    const check = record.checks.find((c) => c.gate_id === gate.gate_id);
    if (!check || !check.evidence_paths.includes(file)) fail(`qualification check/gate evidence mismatch: ${gate.gate_id}`);
    if (["TEST", "INTEGRATION", "SECURITY", "FAULT_INJECTION"].includes(gate.gate_type)
        && (!Number.isSafeInteger(gate.tests_executed) || gate.tests_executed < 1
          || gate.tests_failed !== 0 || gate.tests_skipped !== 0)) fail(`qualification test gate counts/skips invalid: ${gate.gate_id}`);
  }
  if (record.checks.length !== gates.size) fail("qualification checks must exactly cover admitted gates");
  for (const [id, type] of Object.entries(required)) {
    const gate = gates.get(id);
    if (!gate || gate.gate_type !== type) fail(`required qualification gate missing/wrong type: ${id}`);
  }
  for (const role of ["nemo_runtime", "crabedence", "plugin_host"]) {
    const ref = record.artifact_bindings?.[role];
    const e = boundFile(ref);
    if (!e.executable || fs.statSync(path.join(evidenceRoot, ref.file)).size === 0) fail(`nonempty executable qualification artifact required: ${role}`);
    if (canonical(inner.outer_provenance.artifact_bindings?.[role]) !== canonical(ref)) fail(`inner tested artifact binding mismatch: ${role}`);
  }
  // Reuse the existing schema/gate semantics, summaries, invariants and evidence
  // verifier instead of treating the outer record's status string as admission.
  const checker = `${CRAB}/scripts/check-release-admission.sh`;
  const shared = `${CRAB}/scripts/lib/qualification-gates.sh`;
  for (const p of [checker, shared]) if (readEntry(sourceRoot, p).kind !== "file") fail("regular admission verifier required");
  run("bash", [path.join(sourceRoot, checker), path.join(evidenceRoot, record.inner_qualification)], sourceRoot);
}
export function finalize(root, source, expected, recordPath, evidence, out) {
  root = absolute(root); source = absolute(source); evidence = absolute(evidence);
  recordPath = absolute(recordPath);
  if (recordPath.startsWith(`${source}/`) || recordPath.startsWith(`${evidence}/`)) fail("qualification record must be outside source bundle and evidence (no circular hashes)");
  const m = verifyBundle(source, expected);
  if (m.format !== FORMAT || m.dirty_paths.length) fail("finalization requires HEAD-clean source");
  if (m.entries.some((e) => path.join(root, e.path) === recordPath)) fail("qualification record cannot be a tracked source input (no circular hashes)");
  const initial = head(root);
  if (initial.commit !== m.source_commit || canonical(initial.entries) !== canonical(m.head_inventory)) fail("qualification is not for current HEAD");
  untrackedOuter(root, m.entries.map((e) => e.path));
  if (gitDirtyPaths(root, initial.entries, m.entries).length) fail("finalization requires HEAD-clean worktree");
  for (const e of m.entries) if (canonical(readEntry(root, e.path)) !== canonical(e)) fail(`current source differs: ${e.path}`);
  const currentRuntime = runtimes(root);
  if (!same(ordered(currentRuntime.paths), m.runtime_inventory) || currentRuntime.runtime_digest !== m.nemo_runtime_digest
      || currentRuntime.frozen_digest !== m.frozen_runtime_digest) fail("current runtime union differs");
  const record = jsonFile(recordPath);
  const evidenceBefore = evidenceEntries(evidence);
  if (!evidenceBefore.length) fail("empty qualification bundle");
  const bundleDigest = digest(evidenceBefore);
  qualification(record, m, bundleDigest);
  const evidencePaths = new Set(evidenceBefore.map((e) => e.path));
  for (const c of record.checks) for (const p of c.evidence_paths) if (!evidencePaths.has(p)) fail(`missing check evidence: ${p}`);
  qualificationAdmission(path.join(source, "root"), evidence, record, m, evidenceBefore);
  out = absolute(out);
  if (out === source || out.startsWith(`${source}/`) || source.startsWith(`${out}/`)
      || out === evidence || out.startsWith(`${evidence}/`) || evidence.startsWith(`${out}/`)) fail("output overlaps release inputs");
  newDirectory(out, root);
  try {
    fs.cpSync(source, out, { recursive: true, dereference: false, verbatimSymlinks: true });
    fs.mkdirSync(path.join(out, "evidence"));
    for (const e of evidenceBefore) readEntry(evidence, e.path, path.join(out, "evidence"));
    writeJSON(path.join(out, "qualification-record.json"), record);
    const release = {
      ...Object.fromEntries(["source_commit", "source_tree_digest", ...Object.keys(semantics)].map((k) => [k, m[k]])),
      format: RELEASE, source_manifest_sha256: expected,
      qualification_bundle_digest: bundleDigest,
      qualification_record_sha256: sha256(fs.readFileSync(path.join(out, "qualification-record.json"))),
      evidence_entries: evidenceBefore,
      qualification_statement: "Complete required gate coverage, existing admission semantics and source/evidence/tested-artifact bindings validated. This tool did not execute builds or qualification; execution authenticity requires an independently trusted qualification runner.",
    };
    writeJSON(path.join(out, "release-manifest.json"), release);
    verifyBundle(out, expected, sha256(jsonBytes(path.join(out, "release-manifest.json"))));
    if (!same(evidenceEntries(evidence), evidenceBefore) || canonical(jsonFile(recordPath)) !== canonical(record)
        || canonical(head(root)) !== canonical(initial)) fail("release input changed during finalization");
    untrackedOuter(root, m.entries.map((e) => e.path));
    if (gitDirtyPaths(root, initial.entries, m.entries).length) fail("Git source changed during finalization");
    for (const e of m.entries) if (canonical(readEntry(root, e.path)) !== canonical(e)) fail("source changed during finalization");
    return release;
  } catch (error) { fs.rmSync(out, { recursive: true, force: true }); throw error; }
}
export function verifyBundle(bundle, expected, expectedRelease) {
  bundle = absolute(bundle);
  const m = sourceManifest(bundle, expected);
  const names = ordered(fs.readdirSync(bundle));
  const isRelease = names.includes("release-manifest.json");
  const allowed = ordered(isRelease
    ? ["root", "source-manifest.json", "release-manifest.json", "qualification-record.json", "evidence"]
    : ["root", "source-manifest.json"]);
  if (!same(names, allowed)) fail("missing/extra bundle paths");
  if (!isRelease) return m;
  if (!DIGEST.test(expectedRelease ?? "")) fail("trusted --expected-release-manifest-sha256 is required for finalized release");
  const releaseBytes = jsonBytes(path.join(bundle, "release-manifest.json"));
  if (sha256(releaseBytes) !== expectedRelease) fail("release manifest does not match trusted SHA-256");
  const release = JSON.parse(releaseBytes.toString("utf8"));
  if (release.format !== RELEASE || release.source_manifest_sha256 !== expected || m.dirty_paths.length) fail("invalid finalized release");
  for (const key of ["source_commit", ...Object.keys(semantics).filter((k) => k !== "qualification_bundle_digest")]) {
    if (release[key] !== m[key]) fail(`release identity mismatch: ${key}`);
  }
  verifyEntries(path.join(bundle, "evidence"), release.evidence_entries);
  if (digest(release.evidence_entries) !== release.qualification_bundle_digest) fail("qualification bundle mismatch");
  const recordPath = path.join(bundle, "qualification-record.json");
  const recordBytes = jsonBytes(recordPath);
  if (sha256(recordBytes) !== release.qualification_record_sha256) fail("qualification record mismatch");
  const record = JSON.parse(recordBytes.toString("utf8"));
  qualification(record, m, release.qualification_bundle_digest);
  for (const c of record.checks) for (const p of c.evidence_paths) {
    if (!release.evidence_entries.some((e) => e.path === p)) fail(`missing check evidence: ${p}`);
  }
  qualificationAdmission(path.join(bundle, "root"), path.join(bundle, "evidence"), record, m, release.evidence_entries);
  return release;
}
export function archive(bundle, expected, output, expectedRelease) {
  bundle = absolute(bundle); output = absolute(output);
  verifyBundle(bundle, expected, expectedRelease);
  if (fs.existsSync(output) || output.startsWith(`${bundle}/`)) fail("archive output must be new and outside bundle");
  const check = `${output}.verification`;
  if (fs.existsSync(check)) fail("archive verification directory already exists");
  try {
    run("tar", ["--format=posix", "-czf", output, "-C", bundle, ...ordered(fs.readdirSync(bundle))], bundle);
    verifyBundle(bundle, expected, expectedRelease);
    extract(output, check, expected, expectedRelease);
  } catch (error) { fs.rmSync(output, { force: true }); throw error; }
  finally { fs.rmSync(check, { recursive: true, force: true }); }
}
const EXTRACT = `
import tarfile,sys,os,posixpath
archive,out=sys.argv[1:]
with tarfile.open(archive,"r:gz") as t:
 members=t.getmembers();seen={};folded=set()
 for m in members:
  p=m.name.rstrip("/") if m.isdir() else m.name
  if not p or p.startswith("/") or "\\\\" in p or any(ord(c)<32 or ord(c)==127 for c in p) or any(s in ("",".","..",".git") for s in p.split("/")):raise ValueError("unsafe archive path")
  if "/.github/agents/" in "/"+p+"/":raise ValueError("forbidden archive path")
  key=__import__("unicodedata").normalize("NFC",p).lower()
  if p in seen or key in folded:raise ValueError("duplicate/colliding archive path")
  if not (m.isdir() or m.isfile() or m.issym()) or m.islnk():raise ValueError("unsupported archive object")
  if m.mode & 0o7000:raise ValueError("special archive mode")
  if m.issym():
   target=m.linkname
   resolved=posixpath.normpath(posixpath.join(posixpath.dirname(p),target))
   if not target or target.startswith("/") or "\\\\" in target or any(ord(c)<32 for c in target) or resolved==".." or resolved.startswith("../") or ".git" in resolved.split("/"):raise ValueError("unsafe archive symlink")
  seen[p]=m;folded.add(key)
 for p in seen:
  parent=posixpath.dirname(p)
  while parent:
   if parent not in seen or not seen[parent].isdir():raise ValueError("missing or symlink archive ancestor")
   parent=posixpath.dirname(parent)
 for p,m in sorted(seen.items(),key=lambda x:(x[0].count("/"),x[0])):
  if m.isdir():os.mkdir(os.path.join(out,p),0o755)
 # Reopen in streaming mode: random extractfile seeks on gzip otherwise
 # re-decompress the archive thousands of times on a complete outer tree.
 with tarfile.open(archive,"r|gz") as stream:
  written=set()
  for m in stream:
   p=m.name.rstrip("/") if m.isdir() else m.name
   expected=seen.get(p)
   if p in written or expected is None or (m.type,m.mode,m.size,m.linkname)!=(expected.type,expected.mode,expected.size,expected.linkname):raise ValueError("archive changed after preflight")
   written.add(p);dest=os.path.join(out,p)
   if m.isdir():continue
   if m.issym():os.symlink(m.linkname,dest)
   else:
    with stream.extractfile(m) as src,open(dest,"xb") as dst:
     __import__("shutil").copyfileobj(src,dst)
    os.chmod(dest,0o755 if m.mode & 0o111 else 0o644)
  if written!=set(seen):raise ValueError("archive changed after preflight")
`;
export function extract(archivePath, out, expected, expectedRelease) {
  archivePath = absolute(archivePath);
  if (!DIGEST.test(expected ?? "")) fail("trusted manifest hash required before extraction");
  const st = readEntry(path.dirname(archivePath), path.basename(archivePath));
  if (st.kind !== "file") fail("regular archive required");
  out = newDirectory(out);
  try {
    run("python3", ["-B", "-c", EXTRACT, archivePath, out], path.dirname(out));
    if (canonical(readEntry(path.dirname(archivePath), path.basename(archivePath))) !== canonical(st)) fail("archive changed during extraction");
    verifyBundle(out, expected, expectedRelease);
  } catch (error) { fs.rmSync(out, { recursive: true, force: true }); throw error; }
}
export const HELP = `Outer source/release provenance (Node, Python 3, Git, Go, tar; no new dependencies).
All paths must be absolute. Outputs must not exist. Keep output outside tracked source.
  source --root ROOT --out BUNDLE
  evidence-digest --evidence DIRECTORY
  finalize --root ROOT --source BUNDLE --expected-manifest-sha256 SHA256 --record RECORD.json --evidence DIRECTORY --out RELEASE
  verify --bundle BUNDLE --expected-manifest-sha256 SHA256 [--expected-release-manifest-sha256 SHA256]
  archive --bundle BUNDLE --expected-manifest-sha256 SHA256 [--expected-release-manifest-sha256 SHA256] --out ARCHIVE.tar.gz
  extract --archive ARCHIVE.tar.gz --expected-manifest-sha256 SHA256 [--expected-release-manifest-sha256 SHA256] --out DIRECTORY
Compute SHA256 with sha256sum BUNDLE/source-manifest.json; retain it through a trusted
channel. Finalized bundles additionally REQUIRE SHA256 of release-manifest.json
through that channel. verify/extract need no Git or Go. Source embeds the authoritative registry
envelope; verification checks its bytes, not a fabricated identity or a new registry.
Source may bind dirty WORKTREE bytes; finalization refuses dirty source or a changed
HEAD/inventory/byte/mode or untracked nonignored outer source. It does not build or
qualify. Run qualification against BUNDLE/root, never against an implicit live
checkout. After real qualification,
supply {"format":"nemo-outer-qualification-v1","status":"passed","source_commit":...,
"source_tree_digest":...,"capability_registry_digest":...,
"qualification_bundle_digest":<evidence-digest output>,
"inner_qualification":"qualification.json",
"artifact_bindings":{ "nemo_runtime":{"file":"artifacts/runtime","sha256":...},
"crabedence":{"file":"artifacts/crabbox","sha256":...},
"plugin_host":{"file":"artifacts/plugin-host","sha256":...}},
"checks":[{"gate_id":...,"command":<actual command>,"exit_code":0,
"evidence_paths":["gate-results/log.txt"]}]}.
qualification.json must pass the EXISTING check-release-admission.sh (requires
bash/jq), bind outer_provenance {source_commit,source_tree_digest,
capability_registry_digest,artifact_bindings}, and include ALL static gate call
sites in the frozen generate-release-evidence.sh (including conditional live
sites), plus these outer gates and types:
${canonical(OUTER_REQUIRED_GATES)}
Every gate must be mandatory/PASS/exit 0, with intact evidence and a matching
check. Test-bearing gates must execute >0 tests, fail 0 and explicitly skip 0.
Artifact bindings must refer to nonempty executable bytes inside evidence; they
must match the inner record's tested artifact bindings, not source component
digests. Gate coverage extraction supports the producer's three current runner
forms; changing its gate declaration language requires updating this verifier.
Record and evidence are separate from source identity: no circular tracked output.
dirty_paths records Git's HEAD/worktree comparison (checkout attributes honored);
head_byte_differences independently records raw Git-blob versus WORKTREE bytes and
modes, including expected CRLF checkout transformations. Offline verification
recomputes the latter; Git's clean-status declaration is bound by the trusted
source manifest, and finalization rechecks it with Git on the exact live source.
Real rebuilds/full qualification and independent authenticated-runner provenance
remain prerequisites. Well-formed evidence cannot cryptographically prove that
commands were executed: retain both manifest hashes through a trusted channel.
This CLI does not generate qualification records or claim it ran these gates.
Use a quiescent source/evidence tree: reads are no-follow and mutation-checked,
snapshots reverified, but this tool is not an OS transaction against hostile writers.
`;
function cli(argv) {
  const command = argv.shift();
  if (command === "--help" || command === "help" || !command) { console.log(HELP); return; }
  const options = {};
  while (argv.length) {
    const key = argv.shift();
    if (!key.startsWith("--") || !argv.length || Object.hasOwn(options, key.slice(2))) fail(`invalid argument: ${key}`);
    options[key.slice(2)] = argv.shift();
  }
  const required = {
    source: ["root", "out"], "evidence-digest": ["evidence"],
    finalize: ["root", "source", "expected-manifest-sha256", "record", "evidence", "out"],
    verify: ["bundle", "expected-manifest-sha256"],
    archive: ["bundle", "expected-manifest-sha256", "out"],
    extract: ["archive", "expected-manifest-sha256", "out"],
  }[command];
  if (["verify", "archive", "extract"].includes(command) && Object.hasOwn(options, "expected-release-manifest-sha256")) {
    required.push("expected-release-manifest-sha256");
  }
  if (!required || !same(ordered(Object.keys(options)), ordered(required))) fail("invalid options; use --help");
  const a = options, expected = a["expected-manifest-sha256"];
  const expectedRelease = a["expected-release-manifest-sha256"];
  switch (command) {
    case "source": console.log(canonical(createSource(a.root, a.out))); break;
    case "evidence-digest": console.log(evidenceDigest(a.evidence)); break;
    case "finalize": console.log(canonical(finalize(a.root, a.source, expected, a.record, a.evidence, a.out))); break;
    case "verify": console.log(canonical(verifyBundle(a.bundle, expected, expectedRelease))); break;
    case "archive": archive(a.bundle, expected, a.out, expectedRelease); console.log(a.out); break;
    case "extract": extract(a.archive, a.out, expected, expectedRelease); console.log(a.out); break;
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { cli(process.argv.slice(2)); } catch (error) { console.error(`outer-release-manifest: ${error.message}`); process.exitCode = 1; }
}
