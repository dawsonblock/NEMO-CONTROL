#!/usr/bin/env node

// Cross-language differential harness for the invocation-ABI parsers.
//
// Runs every case through the Go verdict CLI (cmd/abi-verdict) and the Rust
// bridge example (bridges/nemo-crabedence/examples/abi_verdict.rs) and
// compares verdicts input-for-input. A verdict divergence — one parser
// accepting what the other refuses — is an authority-boundary defect: the
// same bytes must mean the same thing on both sides of the ABI.
//
//   node scripts/abi-differential.mjs [--random N] [--seed S] [--corpus-only]
//
// The corpus mode replays the shared conformance vectors; --random adds N
// seeded generated cases (mutations of corpus wires, structured random
// invocations, and raw junk). Rejections additionally compare the error
// text — the implementations are built to produce identical phrases.

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { fileURLToPath, pathToFileURL } from "node:url";

const corpusPath = "internal/execution/testdata/invocation-abi-conformance/vectors.json";
const runtimeManifest = "runtimes/nemo-relay/Cargo.toml";

export function mulberry32(seed) {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const knownRoot = ["capability", "arguments", "authority", "execution_class", "idempotency_key", "deadline", "mediation", "session"];
const authorityKeys = ["principal", "authority_ref", "grant_id", "authority_generation", "authority_digest"];
const mediationKeys = ["middleware_set_digest", "original_args_digest", "release_root_digest", "plugin_manifest_sha256", "plugin_library_sha256", "activation_config_sha256"];
const scalarPool = [true, false, null, 0, 1, -1, 3.14, "", "x", "alice@example.com", "MUTATION", "2026-09-24T00:00:00Z"];
const numberLiterals = ["9223372036854775807", "-9223372036854775808", "9223372036854775808", "-9223372036854775809", "0", "-0", "01", "1e5", "1.5", "9007199254740993"];

function pick(rng, list) {
  return list[Math.floor(rng() * list.length)];
}

function randomScalar(rng) {
  return pick(rng, scalarPool);
}

function hexDigest(rng) {
  let out = "";
  for (let i = 0; i < 64; i++) out += Math.floor(rng() * 16).toString(16);
  return out;
}

function randomValue(rng, depth) {
  const roll = rng();
  if (depth >= 4 || roll < 0.5) return randomScalar(rng);
  if (roll < 0.75) {
    const n = Math.floor(rng() * 4);
    return Array.from({ length: n }, () => randomValue(rng, depth + 1));
  }
  const obj = {};
  const n = Math.floor(rng() * 4);
  for (let i = 0; i < n; i++) obj[`k${Math.floor(rng() * 10)}`] = randomValue(rng, depth + 1);
  return obj;
}

function randomInvocation(rng) {
  const req = {};
  const keys = [...knownRoot].sort(() => rng() - 0.5).slice(0, 1 + Math.floor(rng() * 6));
  for (const key of keys) {
    switch (key) {
      case "arguments": {
        const value = randomValue(rng, 0);
        req[key] = value !== null && typeof value === "object" && !Array.isArray(value) ? value : {};
        break;
      }
      case "authority": {
        const auth = {};
        for (const k of [...authorityKeys].sort(() => rng() - 0.5).slice(0, Math.floor(rng() * 5))) {
          auth[k] = k === "authority_generation" && rng() < 0.7 ? pick(rng, numberLiterals) : randomScalar(rng);
        }
        req[key] = auth;
        break;
      }
      case "mediation": {
        const med = {};
        for (const k of [...mediationKeys].sort(() => rng() - 0.5).slice(0, Math.floor(rng() * 7))) {
          med[k] = rng() < 0.6 ? hexDigest(rng) : randomScalar(rng);
        }
        req[key] = med;
        break;
      }
      case "session":
        req[key] = { id: randomScalar(rng), proof: randomScalar(rng), ...(rng() < 0.3 ? { extra: 1 } : {}) };
        break;
      case "capability":
        req[key] = rng() < 0.7 ? "system.echo" : `cap.${Math.floor(rng() * 100)}`;
        break;
      default:
        req[key] = randomScalar(rng);
    }
  }
  if (rng() < 0.35) req[`unknown_${Math.floor(rng() * 1000)}`] = randomScalar(rng);
  return req;
}

// serializeRaw emits JSON with control over things JSON.stringify cannot
// express: the generator also splices raw number literals and structural
// breaks into the text so both parsers see non-canonical wire forms.
function serializeRaw(rng, value) {
  let text = JSON.stringify(value);
  if (rng() < 0.3) {
    // swap a quoted integer-typed value for a raw literal of interest
    text = text.replace(/"authority_generation":\s*("[^"]*"|null|true|false|[0-9.eE+-]+)/, `"authority_generation":${pick(rng, numberLiterals)}`);
  }
  return text;
}

function mutateWire(rng, wire) {
  const mutations = [
    (w) => w.slice(0, Math.floor(rng() * w.length)),
    (w) => w + " ",
    (w) => w + "{}",
    (w) => w + ",",
    (w) => w.replace(/"capability"/, '"capability","capability"'),
    (w) => w.replace(/:\s*/, ":null,"),
    (w) => w.replace(/[,:]/, ";"),
    (w) => w.replace(/"principal":"[^"]*"/, `"principal":"${"a".repeat(2000)}"`),
    // splice a raw byte: a lone UTF-8 continuation (0x80-0xFE) is never
    // valid UTF-8, unlike a JS char which encodes to a legal sequence —
    // this is the generated coverage for the valid-UTF-8 rule
    (w) => {
      const bytes = Buffer.from(w, "utf8");
      const i = Math.floor(rng() * (bytes.length + 1));
      return Buffer.concat([bytes.subarray(0, i), Buffer.from([0x80 + Math.floor(rng() * 0x7f)]), bytes.subarray(i)]);
    },
    (w) => w + w.slice(0, Math.floor(rng() * w.length)),
  ];
  return pick(rng, mutations)(wire);
}

export function generateCases(rng, count, baseWires) {
  const cases = [];
  for (let i = 0; i < count; i++) {
    const roll = rng();
    let wire;
    let name;
    if (roll < 0.45 && baseWires.length > 0) {
      name = `mut-${i}`;
      wire = mutateWire(rng, pick(rng, baseWires));
    } else if (roll < 0.8) {
      name = `gen-${i}`;
      wire = serializeRaw(rng, randomInvocation(rng));
    } else if (roll < 0.9) {
      name = `depth-${i}`;
      const depth = 60 + Math.floor(rng() * 10);
      wire = `{"capability":"system.echo","authority":{"principal":"p"},"arguments":{"n":${"[".repeat(depth)}${"]".repeat(depth)}}}`;
    } else {
      name = `junk-${i}`;
      wire = String.fromCharCode(...Array.from({ length: 1 + Math.floor(rng() * 24) }, () => 0x20 + Math.floor(rng() * 0x60)));
    }
    cases.push({ name, wire });
  }
  return cases;
}

export function corpusCases(root) {
  const doc = JSON.parse(fs.readFileSync(path.join(root, corpusPath), "utf8"));
  return doc.vectors.map((v) => {
    const wire = v.wire ?? (v.wire_b64 === undefined ? undefined : Buffer.from(v.wire_b64, "base64"));
    if (wire === undefined) throw new Error(`corpus vector ${v.name} has neither wire nor wire_b64`);
    return { name: v.name, wire, expected: v.expected, errorContains: v.error_contains };
  });
}

export function encodeCases(cases) {
  return cases.map((c) => Buffer.from(c.wire).toString("base64"));
}

export function runVerdictCli(bin, encoded) {
  const result = spawnSync(bin, [], {
    input: encoded.join("\n") + "\n",
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`${bin} exited ${result.status}: ${result.stderr}`);
  }
  const lines = result.stdout.split("\n");
  if (lines[lines.length - 1] === "") lines.pop();
  return lines;
}

export function compareVerdicts(cases, goVerdicts, rustVerdicts) {
  const divergences = [];
  const textDrift = [];
  const expectationFailures = [];
  if (goVerdicts.length !== cases.length || rustVerdicts.length !== cases.length) {
    divergences.push({
      name: "<stream>",
      go: `${goVerdicts.length} verdicts`,
      rust: `${rustVerdicts.length} verdicts`,
      wire: `${cases.length} cases`,
    });
    return { divergences, textDrift, expectationFailures };
  }
  for (let i = 0; i < cases.length; i++) {
    const g = goVerdicts[i];
    const r = rustVerdicts[i];
    const gVerdict = g.split("\t")[0];
    const rVerdict = r.split("\t")[0];
    if (gVerdict !== rVerdict) {
      divergences.push({ name: cases[i].name, wire: cases[i].wire, go: g, rust: r });
    } else if (g !== r) {
      textDrift.push({ name: cases[i].name, wire: cases[i].wire, go: g, rust: r });
    }
    // Corpus vectors additionally bind each side to the declared
    // expectation — verdict equivalence alone cannot see both parsers
    // drifting away from the corpus in the same direction.
    const c = cases[i];
    if (c.expected !== undefined) {
      if (gVerdict !== c.expected || rVerdict !== c.expected) {
        expectationFailures.push({ name: c.name, wire: c.wire, go: g, rust: r, expected: c.expected });
      } else if (
        c.expected === "reject" &&
        c.errorContains !== undefined &&
        (!g.includes(c.errorContains) || !r.includes(c.errorContains))
      ) {
        expectationFailures.push({ name: c.name, wire: c.wire, go: g, rust: r, expected: `error containing "${c.errorContains}"` });
      }
    }
  }
  return { divergences, textDrift, expectationFailures };
}

function buildVerdictClis(root) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "abi-diff-"));
  const goBin = path.join(tmp, "abi-verdict");
  const goBuild = spawnSync("go", ["build", "-o", goBin, "./cmd/abi-verdict"], { cwd: root, encoding: "utf8" });
  if (goBuild.error) throw new Error(`go build abi-verdict failed to start (is Go on PATH?): ${goBuild.error.message}`);
  if (goBuild.status !== 0) throw new Error(`go build abi-verdict failed: ${goBuild.stderr}`);
  const cargo = spawnSync(
    "cargo",
    ["build", "--quiet", "-p", "nemo-crabedence-bridge", "--example", "abi_verdict", "--manifest-path", runtimeManifest],
    { cwd: root, encoding: "utf8" },
  );
  if (cargo.error) throw new Error(`cargo build abi_verdict failed to start (is cargo on PATH?): ${cargo.error.message}`);
  if (cargo.status !== 0) throw new Error(`cargo build abi_verdict failed: ${cargo.stderr}`);
  const rustBin = path.join(root, "runtimes/nemo-relay/target/debug/examples/abi_verdict");
  if (!fs.existsSync(rustBin)) throw new Error(`expected verdict binary at ${rustBin}`);
  return { goBin, rustBin };
}

function report(label, items, limit = 10) {
  for (const item of items.slice(0, limit)) {
    const wireText = (typeof item.wire === "string" ? item.wire : item.wire?.toString("base64") ?? "")
      .replace(/[\x00-\x1f\x7f-\x9f]/g, (c) => `\\x${c.codePointAt(0).toString(16).padStart(2, "0")}`);
    console.error(`${label} ${item.name}: wire=${wireText.slice(0, 160)}`);
    console.error(`  go:   ${item.go}`);
    console.error(`  rust: ${item.rust}`);
  }
  if (items.length > limit) console.error(`${label}: …and ${items.length - limit} more`);
}

function main() {
  const args = process.argv.slice(2);
  const flag = (name) => {
    const i = args.indexOf(name);
    return i >= 0 ? args[i + 1] : null;
  };
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const seed = Number(flag("--seed") ?? "20261023");
  const randomCount = args.includes("--corpus-only") ? 0 : Number(flag("--random") ?? "2000");

  const corpus = corpusCases(root);
  const baseWires = corpus.map((c) => (typeof c.wire === "string" ? c.wire : c.wire.toString("utf8")));
  const generated = randomCount > 0 ? generateCases(mulberry32(seed), randomCount, baseWires) : [];
  const cases = [...corpus, ...generated];
  console.error(`abi-differential: ${corpus.length} corpus + ${generated.length} generated (seed ${seed})`);

  const { goBin, rustBin } = buildVerdictClis(root);
  const encoded = encodeCases(cases);
  const goVerdicts = runVerdictCli(goBin, encoded);
  const rustVerdicts = runVerdictCli(rustBin, encoded);
  const { divergences, textDrift, expectationFailures } = compareVerdicts(cases, goVerdicts, rustVerdicts);

  report("VERDICT-DIVERGENCE", divergences);
  report("EXPECTATION-FAILURE", expectationFailures);
  report("TEXT-DRIFT", textDrift);
  const failures = divergences.length + expectationFailures.length;
  if (failures > 0) {
    console.error(`abi-differential: ${divergences.length} verdict divergences, ${expectationFailures.length} corpus expectation failures`);
    process.exitCode = 1;
    return;
  }
  const accepted = goVerdicts.filter((v) => v === "accept").length;
  // Text drift is reported, not gated: the corpus binds phrase-level
  // equality per vector, but malformed-input messages legitimately differ
  // (encoding/json's scanner phrasing vs the Rust structural phrases, and
  // %q vs serde quoting of exotic keys). The enforced invariant is verdict
  // equivalence — identical accept/reject on identical bytes.
  console.log(`abi-differential: ${cases.length} cases, verdicts identical (${accepted} accepted, ${cases.length - accepted} rejected), ${textDrift.length} informational error-text drift`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
