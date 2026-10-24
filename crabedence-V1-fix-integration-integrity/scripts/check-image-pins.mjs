#!/usr/bin/env node

// Verifies qualification/msb-lane-image-pins.json against the tree it describes:
// every declared reference must appear at its declared sources, every
// execution-plane image default found by mechanical scan must be declared, and
// non-digest pin classes must carry a finding. Declared findings are reported;
// undeclared drift fails.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath, pathToFileURL } from "node:url";

const inventoryPath = "qualification/msb-lane-image-pins.json";
const pinnedClasses = new Set(["registry-digest", "oci-manifest-bound", "immutable-url-sha256"]);
const declaredClasses = new Set(["provider-catalog-name", "local-operator-image", "mutable-tag"]);
const skipDirs = new Set(["node_modules", "target", ".git", "dist", "build"]);

// Same pin rule as check-docker-base-images.mjs: FROM must end @sha256:<64 hex>.
export function unpinnedDockerfileRefs(source) {
  const refs = [];
  for (const line of source.split(/\r?\n/)) {
    const match = /^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)/i.exec(line);
    if (match && !/@sha256:[0-9a-f]{64}$/i.test(match[1])) refs.push(match[1]);
  }
  return refs;
}

export function loadInventory(root) {
  const file = path.join(root, inventoryPath);
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

export function sourceNeedle(image) {
  if (image.reference.startsWith("workflow-input:")) return image.reference.slice("workflow-input:".length);
  return image.reference;
}

export function imageLiterals(source) {
  const literals = [];
  const re = /\bImage:\s*"([^"]+)"/g;
  for (const match of source.matchAll(re)) literals.push(match[1]);
  return literals;
}

export function workflowImageRefs(source) {
  const refs = [];
  const re = /^\s*image:\s*(\S+)\s*$/gm;
  for (const match of source.matchAll(re)) refs.push(match[1]);
  return refs;
}

export function dockerfilePaths(root) {
  const found = [];
  const walk = (dir) => {
    for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
      if (skipDirs.has(ent.name)) continue;
      const full = path.join(dir, ent.name);
      if (ent.isDirectory()) walk(full);
      else if (ent.name.includes("Dockerfile")) found.push(full);
    }
  };
  walk(root);
  return found;
}

export function workflowPaths(root) {
  const dir = path.join(root, ".github", "workflows");
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir).filter((f) => f.endsWith(".yml") || f.endsWith(".yaml")).map((f) => path.join(dir, f));
}

export function checkInventoryConsistency(inventory) {
  const errors = [];
  const findingIds = new Set((inventory.findings ?? []).map((f) => f.id));
  const ids = new Set();
  for (const image of inventory.images ?? []) {
    if (ids.has(image.id)) errors.push(`duplicate image id: ${image.id}`);
    ids.add(image.id);
    if (!pinnedClasses.has(image.pin_class) && !declaredClasses.has(image.pin_class) && image.pin_class !== "development") {
      errors.push(`${image.id}: unknown pin_class ${image.pin_class}`);
    }
    if (image.status === "pinned" && !pinnedClasses.has(image.pin_class)) {
      errors.push(`${image.id}: status 'pinned' requires a digest-bound pin_class, got ${image.pin_class}`);
    }
    if (image.status === "finding" && !findingIds.has(image.finding)) {
      errors.push(`${image.id}: references missing finding ${image.finding}`);
    }
    if ((image.pin_class === "mutable-tag" || image.pin_class === "provider-catalog-name") && image.status !== "finding") {
      errors.push(`${image.id}: ${image.pin_class} must be declared as a finding`);
    }
    if (image.status === "out-of-scope" && image.pin_class !== "development") {
      errors.push(`${image.id}: out-of-scope status is only valid for the development class`);
    }
  }
  const seen = new Set();
  for (const finding of inventory.findings ?? []) {
    if (seen.has(finding.id)) errors.push(`duplicate finding id: ${finding.id}`);
    seen.add(finding.id);
  }
  return errors;
}

export function checkDeclaredSources(root, inventory) {
  const errors = [];
  for (const image of inventory.images ?? []) {
    const needle = sourceNeedle(image);
    for (const src of image.sources ?? []) {
      const file = path.join(root, src);
      if (!fs.existsSync(file)) {
        errors.push(`${image.id}: declared source missing: ${src}`);
        continue;
      }
      const content = fs.readFileSync(file, "utf8");
      if (!content.includes(needle)) {
        errors.push(`${image.id}: ${src} does not contain declared reference ${needle}`);
      }
      if (image.digest && !content.includes(image.digest) && !content.includes(image.digest.replace(/^sha256:/, ""))) {
        errors.push(`${image.id}: ${src} does not contain declared digest ${image.digest}`);
      }
    }
    for (const artifact of image.bound_artifacts ?? []) {
      if (!fs.existsSync(path.join(root, artifact))) {
        errors.push(`${image.id}: bound artifact missing: ${artifact}`);
      }
    }
  }
  return errors;
}

export function checkTartManifestBinding(root, inventory) {
  const errors = [];
  const tart = (inventory.images ?? []).find((i) => i.pin_class === "oci-manifest-bound");
  if (!tart) return errors;
  const manifest = path.join(root, "internal/providers/tart/images/sequoia.manifest.json");
  if (!fs.existsSync(manifest)) {
    errors.push(`${tart.id}: embedded manifest missing`);
    return errors;
  }
  const manifestDigest = "sha256:" + crypto.createHash("sha256").update(fs.readFileSync(manifest)).digest("hex");
  if (manifestDigest !== tart.digest) {
    errors.push(`${tart.id}: embedded manifest digest ${manifestDigest} != declared ${tart.digest}`);
  }
  return errors;
}

export function checkUndeclaredDefaults(root, inventory) {
  const errors = [];
  const declared = new Set((inventory.images ?? []).map((i) => i.reference));
  const configFile = path.join(root, "internal/cli/config.go");
  if (fs.existsSync(configFile)) {
    const src = fs.readFileSync(configFile, "utf8");
    for (const literal of new Set(imageLiterals(src))) {
      if (!declared.has(literal)) {
        errors.push(`internal/cli/config.go: undeclared image default ${literal}`);
      }
    }
  }
  for (const file of dockerfilePaths(root)) {
    const rel = path.relative(root, file);
    for (const ref of unpinnedDockerfileRefs(fs.readFileSync(file, "utf8"))) {
      if (!declared.has(ref)) {
        errors.push(`${rel}: unpinned base image not declared in ${inventoryPath}: ${ref}`);
      }
    }
  }
  for (const file of workflowPaths(root)) {
    const rel = path.relative(root, file);
    for (const ref of workflowImageRefs(fs.readFileSync(file, "utf8"))) {
      if (/@sha256:[0-9a-f]{64}$/i.test(ref)) continue;
      if (ref.startsWith("${{")) continue;
      if (!declared.has(ref)) {
        errors.push(`${rel}: unpinned workflow image not declared in ${inventoryPath}: ${ref}`);
      }
    }
  }
  return errors;
}

export function scanImagePins(root) {
  const inventory = loadInventory(root);
  const errors = [
    ...checkInventoryConsistency(inventory),
    ...checkDeclaredSources(root, inventory),
    ...checkTartManifestBinding(root, inventory),
    ...checkUndeclaredDefaults(root, inventory),
  ];
  const open = (inventory.findings ?? []).filter((f) => f.status === "open");
  return { errors, open };
}

function main() {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const { errors, open } = scanImagePins(root);
  for (const finding of open) console.error(`open finding ${finding.id}: ${finding.summary}`);
  if (errors.length > 0) {
    console.error(errors.join("\n"));
    process.exitCode = 1;
    return;
  }
  const inventory = loadInventory(root);
  console.log(`image-pin inventory verified: ${inventory.images.length} images, ${open.length} open findings`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
