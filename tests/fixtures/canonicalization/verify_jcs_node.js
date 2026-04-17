#!/usr/bin/env node
/**
 * RFC 8785 JCS fixture runner — Node.js reference.
 *
 * Validates that a Node JCS implementation produces byte-identical
 * canonical output and SHA-256 for every vector in jcs_vectors.json.
 *
 * This file intentionally ships a minimal JCS implementation inline
 * rather than pulling in a dependency — it is the *reference* any SDK
 * author can copy into their own code to verify interop with the
 * Inntris server under sig_version=3.
 *
 * Exits 0 on success, 1 on failure.
 *
 * Usage: node tests/fixtures/canonicalization/verify_jcs_node.js
 */
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const vectorsPath = path.join(__dirname, "jcs_vectors.json");
const { vectors } = JSON.parse(fs.readFileSync(vectorsPath, "utf-8"));

// -------- JCS implementation --------

const SHORT_ESCAPES = {
  0x08: "\\b",
  0x09: "\\t",
  0x0a: "\\n",
  0x0c: "\\f",
  0x0d: "\\r",
  0x22: '\\"',
  0x5c: "\\\\",
};

function encodeString(s) {
  let out = '"';
  for (const ch of s) {
    const cp = ch.codePointAt(0);
    const short = SHORT_ESCAPES[cp];
    if (short !== undefined) {
      out += short;
    } else if (cp < 0x20) {
      out += "\\u" + cp.toString(16).padStart(4, "0");
    } else {
      out += ch;
    }
  }
  out += '"';
  return out;
}

function encodeNumber(n) {
  if (typeof n !== "number" || !Number.isFinite(n)) {
    throw new Error("JCS forbids NaN and Infinity");
  }
  // ECMA-262 Number.prototype.toString handles integer-valued floats and
  // negative zero correctly. JavaScript's stringifier matches JCS for the
  // subset of numbers we care about; this is the whole point of RFC 8785.
  if (Object.is(n, -0)) return "0";
  return String(n);
}

function canonicalize(obj) {
  if (obj === null) return "null";
  if (obj === true) return "true";
  if (obj === false) return "false";
  if (typeof obj === "string") return encodeString(obj);
  if (typeof obj === "number") return encodeNumber(obj);
  if (Array.isArray(obj)) {
    return "[" + obj.map(canonicalize).join(",") + "]";
  }
  if (typeof obj === "object") {
    // JCS: sort keys by UTF-16 code units. JavaScript strings are UTF-16
    // and String#localeCompare is locale-sensitive, so use a plain
    // comparison on the code-unit sequence — that's what < does on strings.
    const keys = Object.keys(obj).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    return (
      "{" +
      keys.map((k) => encodeString(k) + ":" + canonicalize(obj[k])).join(",") +
      "}"
    );
  }
  throw new Error(`unsupported type for JCS: ${typeof obj}`);
}

function sha256Hex(obj) {
  return crypto
    .createHash("sha256")
    .update(canonicalize(obj), "utf-8")
    .digest("hex");
}

// -------- Runner --------

const failures = [];

for (const v of vectors) {
  const canonical = canonicalize(v.input);
  const digest = sha256Hex(v.input);

  if (canonical !== v.canonical) {
    failures.push(
      `FAIL ${v.name} (canonical):\n     expected: ${JSON.stringify(v.canonical)}\n     actual:   ${JSON.stringify(canonical)}`,
    );
    continue;
  }

  if (digest !== v.sha256) {
    failures.push(
      `FAIL ${v.name} (sha256):\n     expected: ${v.sha256}\n     actual:   ${digest}`,
    );
    continue;
  }

  console.log(`  OK  ${v.name}`);
}

if (failures.length > 0) {
  console.log("\nFAILURES:");
  failures.forEach((f) => console.log(`  ${f}`));
  process.exit(1);
}

console.log(`\nAll ${vectors.length} JCS vectors passed.`);
process.exit(0);
