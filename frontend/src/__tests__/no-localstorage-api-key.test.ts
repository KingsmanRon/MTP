import { readdirSync, readFileSync, statSync } from "fs";
import { join, resolve } from "path";

/**
 * Security invariant: the raw admin/portal API key must never be persisted in
 * the browser. Phase 0.1 moved credentials into an AES-256-GCM HTTP-only
 * session cookie — this test prevents regressions by scanning the frontend
 * source tree for forbidden references.
 */

const FORBIDDEN_KEY_NAME = "inntris_api_key";
const SRC_ROOT = resolve(__dirname, "..");
const SKIP_DIRS = new Set(["node_modules", ".next", "__tests__"]);
const SKIP_FILES = new Set([__filename]);
const EXTENSIONS = [".ts", ".tsx", ".js", ".jsx"];

function walk(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const st = statSync(full);
    if (st.isDirectory()) {
      if (SKIP_DIRS.has(entry)) continue;
      walk(full, out);
    } else if (EXTENSIONS.some((e) => entry.endsWith(e))) {
      if (SKIP_FILES.has(full)) continue;
      out.push(full);
    }
  }
  return out;
}

describe("Phase 0.1 — API key is never stored in the browser", () => {
  const files = walk(SRC_ROOT);

  it("finds no references to the forbidden localStorage key name", () => {
    const offenders: string[] = [];
    for (const f of files) {
      const text = readFileSync(f, "utf8");
      if (text.includes(FORBIDDEN_KEY_NAME)) {
        offenders.push(f);
      }
    }
    expect(offenders).toEqual([]);
  });

  it("never calls localStorage.*Item with an API-key-like argument", () => {
    const offenders: { file: string; line: string }[] = [];
    const pattern =
      /localStorage\.(?:setItem|getItem|removeItem)\s*\(\s*["'`][^"'`]*(api[_-]?key|apikey)[^"'`]*["'`]/i;
    for (const f of files) {
      const text = readFileSync(f, "utf8");
      for (const line of text.split("\n")) {
        if (pattern.test(line)) {
          offenders.push({ file: f, line: line.trim() });
        }
      }
    }
    expect(offenders).toEqual([]);
  });
});
