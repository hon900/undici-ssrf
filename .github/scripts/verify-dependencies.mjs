import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const root = new URL("../../", import.meta.url);
const readJson = async (name) => JSON.parse(await readFile(new URL(name, root), "utf8"));
const sortEntries = (value = {}) => Object.entries(value).sort(([a], [b]) => a.localeCompare(b));

try {
  const manifest = await readJson("package.json");
  const lock = await readJson("package-lock.json");
  const lockedRoot = lock.packages?.[""];
  assert.ok(lockedRoot, "package-lock.json must contain a root package record");
  for (const field of ["name", "version"]) {
    assert.equal(lock[field], manifest[field], `lockfile ${field} does not match package.json`);
    assert.equal(lockedRoot[field], manifest[field], `lockfile root ${field} does not match package.json`);
  }
  for (const field of ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]) {
    assert.deepEqual(sortEntries(lockedRoot[field]), sortEntries(manifest[field]),
      `lockfile root ${field} does not match package.json`);
  }
  const expected = /^github:hon900\/hostfence#v(\d+\.\d+\.\d+)$/.exec(manifest.dependencies?.hostfence);
  assert.ok(expected, "hostfence must use an explicit release tag");
  const lockedCore = lock.packages["node_modules/hostfence"];
  assert.equal(lockedCore?.version, expected[1], "locked hostfence version differs from the requested release tag");
  assert.match(lockedCore?.resolved ?? "",
    /^git\+(?:ssh:\/\/git@github\.com\/|https:\/\/github\.com\/)hon900\/hostfence\.git#[a-f0-9]{40}$/,
    "hostfence lock must resolve to an immutable GitHub commit");

  if (!process.argv.includes("--lockfile-only")) {
    const installed = await readJson("node_modules/hostfence/package.json");
    assert.equal(installed.version, expected[1], "installed hostfence does not match the requested release");
    const core = await import("hostfence");
    assert.equal(typeof core.Hostfence?.prototype.assertPin, "function", "installed hostfence lacks assertPin");
    assert.equal(typeof core.pinLookup, "function", "installed hostfence lacks pinLookup");
  }
  console.log(`Dependency contract verified: ${manifest.name}@${manifest.version} -> hostfence@${expected[1]}`);
} catch (error) {
  console.error("Dependency contract failed:", error.message);
  console.error("Regenerate package-lock.json against the declared release in a clean checkout, then run npm ci.");
  process.exitCode = 1;
}
