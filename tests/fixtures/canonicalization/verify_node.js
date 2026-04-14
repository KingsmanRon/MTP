#!/usr/bin/env node
/**
 * Canonicalization fixture runner — Node.js.
 *
 * Mirrors verify_python.py: same vectors.json, same contract,
 * must produce identical hashes. Exits 0 on success, 1 on failure.
 *
 * Usage: node tests/fixtures/canonicalization/verify_node.js
 */
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const vectorsPath = path.join(__dirname, "vectors.json");
const { vectors } = JSON.parse(fs.readFileSync(vectorsPath, "utf-8"));

function canonicalFingerprint(payload) {
  // Mirror Python: json.dumps(sort_keys=True, separators=(",",":"))
  const sorted = sortKeysDeep(payload);
  const canonical = JSON.stringify(sorted);
  return crypto.createHash("sha256").update(canonical, "utf-8").digest("hex");
}

function sortKeysDeep(obj) {
  if (obj === null || typeof obj !== "object" || Array.isArray(obj)) return obj;
  return Object.keys(obj)
    .sort()
    .reduce((acc, k) => {
      acc[k] = sortKeysDeep(obj[k]);
      return acc;
    }, {});
}

let failures = [];

for (const v of vectors) {
  const actual = canonicalFingerprint(v.input);
  const expected = v.expected_sha256;

  if (expected.startsWith("__COMPUTED__")) {
    continue;
  }

  if (expected.startsWith("__MUST_NOT_EQUAL__")) {
    const mustNot = expected.replace("__MUST_NOT_EQUAL__", "");
    if (actual === mustNot) {
      failures.push(`FAIL ${v.name}: hash should differ from ${mustNot} but matched`);
    } else {
      console.log(`  OK  ${v.name}: correctly differs from reference hash`);
    }
    continue;
  }

  if (actual === expected) {
    console.log(`  OK  ${v.name}`);
  } else {
    failures.push(
      `FAIL ${v.name}:\n     expected: ${expected}\n     actual:   ${actual}`
    );
  }
}

if (failures.length > 0) {
  console.log("\nFAILURES:");
  failures.forEach((f) => console.log(`  ${f}`));
  process.exit(1);
}

console.log("\nAll vectors passed.");
process.exit(0);
