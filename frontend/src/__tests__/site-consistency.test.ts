import * as fs from "fs";
import * as path from "path";

import { PRIMARY_NAV, FOOTER_NAV, BRAND_NAME, BRAND_TAGLINE } from "../lib/brand";

/**
 * Source-level guards for the design-audit findings.
 *
 * Each of these encodes an acceptance criterion that a rendered-DOM test
 * cannot reach — they are properties of the source tree (one owner for a
 * string, no second copy of a label) rather than of any single component. A
 * grep in CI is the only thing that stops the second copy coming back.
 */

const SRC = path.join(__dirname, "..");

function walk(dir: string, out: string[] = []): string[] {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === "__tests__" || entry.name === "node_modules") continue;
      walk(full, out);
    } else if (/\.tsx?$/.test(entry.name)) {
      out.push(full);
    }
  }
  return out;
}

const FILES = walk(SRC);
const TSX = FILES.filter((f) => f.endsWith(".tsx"));

function read(f: string) {
  return fs.readFileSync(f, "utf8");
}

/**
 * Source with comments removed. Every check below is about what the site
 * renders, and an explanatory comment naming the string it replaced must not
 * count as a reoccurrence of it.
 */
function code(f: string) {
  return read(f)
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/^\s*\/\/.*$/gm, "");
}

function rel(f: string) {
  return path.relative(SRC, f);
}

describe("brand consistency (P1-1)", () => {
  it("no surface carries the retired 'Inntris Core' product name", () => {
    const offenders = TSX.filter((f) => code(f).includes("Inntris Core"));
    expect(offenders.map(rel)).toEqual([]);
  });

  it("the tagline is defined once and never inlined at a call site", () => {
    const offenders = TSX.filter((f) => code(f).includes(BRAND_TAGLINE));
    expect(offenders.map(rel)).toEqual([]);
  });

  it("every public page renders the shared footer rather than its own", () => {
    const pages = [
      "app/page.tsx",
      "app/security/page.tsx",
      "app/pilot/page.tsx",
      "app/verify/page.tsx",
      "app/verify/[id]/verify-record-client.tsx",
      "app/docs/page.tsx",
      "app/audit/page.tsx",
      "app/portal/page.tsx",
    ];
    for (const page of pages) {
      const source = read(path.join(SRC, page));
      expect({ page, usesShared: source.includes("<SiteFooter") }).toEqual({
        page,
        usesShared: true,
      });
      expect({ page, hasOwnFooter: source.includes("<footer") }).toEqual({
        page,
        hasOwnFooter: false,
      });
    }
  });

  it("exports a brand name the footer actually uses", () => {
    expect(BRAND_NAME).toBe("Inntris");
    expect(read(path.join(SRC, "components/site-footer.tsx"))).toContain("BRAND_NAME");
  });
});

describe("navigation labels (P2-2, P2-3, P2-4)", () => {
  it("no label maps to two destinations across nav and footer", () => {
    const byLabel = new Map<string, Set<string>>();
    for (const { href, label } of [...PRIMARY_NAV, ...FOOTER_NAV]) {
      if (!byLabel.has(label)) byLabel.set(label, new Set());
      byLabel.get(label)!.add(href);
    }
    const ambiguous = [...byLabel.entries()]
      .filter(([, hrefs]) => hrefs.size > 1)
      .map(([label, hrefs]) => `${label} -> ${[...hrefs].join(", ")}`);
    expect(ambiguous).toEqual([]);
  });

  it("every in-page nav anchor resolves to a section id that exists", () => {
    const ids = new Set<string>();
    for (const f of TSX) {
      for (const m of read(f).matchAll(/\bid="([a-z0-9-]+)"/g)) ids.add(m[1]);
    }
    const missing = [...PRIMARY_NAV, ...FOOTER_NAV]
      .map((l) => l.href)
      .filter((h) => h.startsWith("/#"))
      .filter((h) => !ids.has(h.slice(2)));
    expect(missing).toEqual([]);
  });

  it("the header does not offer two adjacent links to /pilot", () => {
    expect(PRIMARY_NAV.filter((l) => l.href === "/pilot")).toEqual([]);
  });

  it("no pilot call to action hardcodes its own wording", () => {
    const stale = ["Scope a payment pilot", "Scope a 14-day payment pilot", "14-day pilot"];
    const offenders: string[] = [];
    for (const f of TSX) {
      const source = code(f);
      for (const s of stale) {
        if (source.includes(`>${s}<`) || source.includes(`"${s}"`)) {
          offenders.push(`${rel(f)}: ${s}`);
        }
      }
    }
    expect(offenders).toEqual([]);
  });
});

describe("verdict vocabulary (P0-1)", () => {
  it("exactly one module owns verdict display strings", () => {
    // The tokens may still be *named* in prose that explains the mapping —
    // the protocol section and the docs page each do so deliberately, once.
    const allowed = new Set([
      "components/landing/protocol-section.tsx",
      "app/docs/page.tsx",
    ]);
    const offenders: string[] = [];
    for (const f of TSX) {
      if (allowed.has(rel(f))) continue;
      const source = code(f);
      for (const token of ["PASS", "BLOCK", "ESCALATE", "ALLOW", "REQUIRE_APPROVAL"]) {
        if (new RegExp(`["'>]${token}["'<]`).test(source)) {
          offenders.push(`${rel(f)}: ${token}`);
        }
      }
    }
    expect(offenders).toEqual([]);
  });

  it("the homepage does not claim receipt verdicts are envelope verdicts", () => {
    const source = read(path.join(SRC, "components/landing/protocol-section.tsx"));
    expect(source).not.toContain(
      "These are the literal values\n              in the signed artifact",
    );
    // The attribution the reader needs: which artifact emits which vocabulary.
    expect(source).toContain("x402 policy adapter");
    expect(source).toContain("platform receipts");
  });
});

describe("freshness claims (P1-3)", () => {
  it("no rendered copy calls the demo receipts 'live'", () => {
    const stale = ["Live verification receipts", "receipts are live", "live policy path"];
    const offenders: string[] = [];
    for (const f of TSX) {
      const source = code(f);
      for (const s of stale) if (source.includes(s)) offenders.push(`${rel(f)}: ${s}`);
    }
    expect(offenders).toEqual([]);
  });

  it("receipt timestamps do not render a relative form that decays", () => {
    const source = code(path.join(SRC, "components/landing/live-proof-section.tsx"));
    expect(source).not.toMatch(/\bago\b/);
    expect(source).toContain("formatUtcTimestamp");
  });
});

describe("locale (P2-7)", () => {
  it("no UI label uses the American spelling of organisation", () => {
    // Only user-visible text counts. Wire field names (`organization_name`),
    // hook and variable identifiers and the schema.org `@type` are not UI copy
    // and must not be anglicised — they are part of the API contract.
    const offenders: string[] = [];
    for (const f of TSX) {
      const source = code(f);
      const visible = [
        ...source.matchAll(/>([^<>{}]*\borganization\b[^<>{}]*)</gi),
        ...source.matchAll(/"([^"\n]*\borganization\b[^"\n]*)"/gi),
      ].map((m) => m[1]);
      for (const text of visible) {
        if (/^organization_name$/i.test(text.trim())) continue;
        if (/^Organization$/.test(text.trim()) && /"@type"/.test(source)) continue;
        offenders.push(`${rel(f)}: ${text.trim()}`);
      }
    }
    expect(offenders).toEqual([]);
  });
});

describe("empty states (P2-5)", () => {
  it("the receipt page renders no bare em-dash placeholders", () => {
    const source = read(path.join(SRC, "app/verify/[id]/verify-record-client.tsx"));
    expect(source).not.toMatch(/[>{]\s*"?—"?\s*[<}]/);
  });
});

describe("terminal CTA (P1-2)", () => {
  it("a payment receipt is not sold CI/CD protection", () => {
    const source = read(path.join(SRC, "app/verify/[id]/verify-record-client.tsx"));
    expect(source).not.toContain("Want PR protection for AI agent changes?");
    expect(source).toContain("Verify this receipt yourself");
    expect(source).toContain("CI_ACTION_TYPES");
  });
});
