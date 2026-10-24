#!/usr/bin/env node
// Generate the deterministic source inventory for qualification.
//
// Enumerates every Git-tracked regular file and symlink at HEAD — the same
// set `git archive HEAD` packages and `generate-source-manifest.sh` hashes —
// and emits a machine-readable inventory with path, type, mode, size, the
// SHA-256 of the exact blob bytes (or the symlink target), component owner,
// and provenance class.
//
//   - mode/type/size come from `git ls-tree -r --long HEAD`, never from the
//     filesystem, so dirty worktree bytes cannot leak into the inventory.
//   - blob bytes are read through one `git cat-file --batch` stream; sha256
//     is computed over those bytes, identical to hashing the blob directly.
//   - For symlinks the recorded link_target is the literal blob content —
//     never the dereferenced file.
//   - provenance_class is `vendored-runtime` beneath runtimes/nemo-relay/
//     and `crabedence` everywhere else; component is the top-level directory.
//
// Output is sorted by path (byte order) and pretty-printed deterministically.
//
// Usage: node scripts/generate-source-inventory.mjs [output-file]
//   output-file: default qualification/source-inventory.json

import { execFileSync, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

const out = resolve(process.argv[2] ?? "qualification/source-inventory.json");

const raw = execFileSync(
  "git",
  ["ls-tree", "-r", "--long", "-z", "HEAD"],
  { encoding: "buffer", maxBuffer: 512 * 1024 * 1024 },
);

// -z output: "<mode> <type> <object> <size>\t<path>\0" per record.
const parsed = [];
for (const record of raw.toString("utf8").split("\0")) {
  if (!record) continue;
  const tab = record.indexOf("\t");
  const meta = record.slice(0, tab).split(" ");
  const path = record.slice(tab + 1);
  const [mode, type, object, size] = meta;
  parsed.push({ mode, type, object, size, path });
}

// Stream all blobs through one `git cat-file --batch`: feed each object on
// stdin, read back "<oid> blob <size>\n<bytes>\n" replies in order.
const blobs = await new Promise((resolveBlobs, reject) => {
  const proc = spawn("git", ["cat-file", "--batch"], {
    stdio: ["pipe", "pipe", "inherit"],
  });
  const chunks = [];
  proc.stdout.on("data", (c) => chunks.push(c));
  proc.on("close", (code) => {
    if (code !== 0) return reject(new Error(`cat-file --batch exited ${code}`));
    resolveBlobs(Buffer.concat(chunks));
  });
  proc.on("error", reject);
  for (const e of parsed) proc.stdin.write(`${e.object}\n`);
  proc.stdin.end();
});

const entries = [];
let off = 0;
for (const e of parsed) {
  const nl = blobs.indexOf("\n", off);
  const header = blobs.slice(off, nl).toString("utf8");
  const size = Number(header.split(" ").pop());
  const blob = blobs.slice(nl + 1, nl + 1 + size);
  off = nl + 1 + size + 1; // trailing newline after each blob
  const entry = {
    path: e.path,
    type: e.mode === "120000" ? "symlink" : "file",
    mode: e.mode,
    size,
    component: e.path.split("/")[0],
    provenance_class: e.path.startsWith("runtimes/nemo-relay/")
      ? "vendored-runtime"
      : "crabedence",
    sha256: createHash("sha256").update(blob).digest("hex"),
  };
  if (entry.type === "symlink") entry.link_target = blob.toString("utf8");
  entries.push(entry);
}

entries.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));

const head = execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim();
const inventory = {
  format: "nemo-control-source-inventory/1",
  source_commit: head,
  enumeration: "git ls-tree -r --long HEAD (tracked entries only; generated/ignored paths excluded)",
  entries,
};

mkdirSync(dirname(out), { recursive: true });
writeFileSync(out, JSON.stringify(inventory, null, 2) + "\n");
const symlinks = entries.filter((e) => e.type === "symlink").length;
console.log(
  `wrote ${out}: ${entries.length} entries (${symlinks} symlinks) @ ${head.slice(0, 12)}`,
);
