import assert from "node:assert/strict";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  compareVerdicts,
  corpusCases,
  encodeCases,
  generateCases,
  mulberry32,
} from "./abi-differential.mjs";

const root = fileURLToPath(new URL("..", import.meta.url));

test("the generator is deterministic for a seed", () => {
  const a = generateCases(mulberry32(42), 50, ['{"capability":"x"}']);
  const b = generateCases(mulberry32(42), 50, ['{"capability":"x"}']);
  assert.deepEqual(a, b);
});

test("the generator varies with seed", () => {
  const a = generateCases(mulberry32(1), 20, []);
  const b = generateCases(mulberry32(2), 20, []);
  assert.notDeepEqual(a, b);
});

test("generated cases carry names and wire content", () => {
  const cases = generateCases(mulberry32(7), 100, ['{"capability":"system.echo"}']);
  assert.equal(cases.length, 100);
  for (const c of cases) {
    assert.ok(c.name.length > 0);
    assert.ok(c.wire.length > 0);
  }
});

test("corpusCases loads the shared vectors", () => {
  const cases = corpusCases(root);
  assert.ok(cases.length > 0);
  assert.ok(cases.every((c) => c.name && c.wire !== undefined && c.expected !== undefined));
});

test("encodeCases emits base64 per case including empty wires", () => {
  const encoded = encodeCases([{ name: "a", wire: "{}" }, { name: "b", wire: "" }]);
  assert.equal(encoded.length, 2);
  assert.equal(Buffer.from(encoded[0], "base64").toString(), "{}");
  assert.equal(encoded[1], "");
});

test("compareVerdicts separates verdict divergence from text drift", () => {
  const cases = [{ name: "c1", wire: "{}" }, { name: "c2", wire: "x" }, { name: "c3", wire: "y" }];
  const go = ["accept", "reject\tgo phrase", "reject\tsame"];
  const rust = ["reject\trust phrase", "reject\trust phrase", "reject\tsame"];
  const { divergences, textDrift, expectationFailures } = compareVerdicts(cases, go, rust);
  assert.equal(divergences.length, 1);
  assert.equal(divergences[0].name, "c1");
  assert.equal(textDrift.length, 1);
  assert.equal(textDrift[0].name, "c2");
  assert.equal(expectationFailures.length, 0);
});

test("compareVerdicts flags verdict streams shorter than the case list", () => {
  const cases = [{ name: "a", wire: "{}" }, { name: "b", wire: "{}" }];
  const { divergences } = compareVerdicts(cases, ["accept"], ["accept"]);
  assert.equal(divergences.length, 1);
});

test("compareVerdicts enforces corpus expectations on both parsers", () => {
  const cases = [
    { name: "want-accept", wire: "{}", expected: "accept" },
    { name: "want-reject", wire: "x", expected: "reject", errorContains: "invalid JSON" },
  ];
  const { divergences, expectationFailures } = compareVerdicts(
    cases,
    ["reject\tanything", "reject\tunexpected end"],
    ["reject\tanything", "reject\tinvalid JSON: expected an object key"],
  );
  assert.equal(divergences.length, 0);
  assert.equal(expectationFailures.length, 2);
  assert.equal(expectationFailures[0].name, "want-accept");
  assert.equal(expectationFailures[1].name, "want-reject");
});
