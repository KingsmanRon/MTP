const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const {
  parseYaml,
  globToRegExp,
  matchFilesToActionTypes,
  plannedCalls,
  computeRiskFlags,
  resolveFailClosed,
  decidePlan,
} = require("./index.js");

const POLICY_PATH = path.join(__dirname, "..", ".inntris.yml");
const policy = parseYaml(fs.readFileSync(POLICY_PATH, "utf8"));

// ---------------------------------------------------------------------------
// YAML subset parser
// ---------------------------------------------------------------------------
test("parseYaml reads the enforcement block", () => {
  assert.ok(policy.enforcement);
  assert.equal(policy.enforcement.fail_closed, "true");
});

test("parseYaml reads scalars, sequences, and nested mapping", () => {
  assert.equal(policy.version, "1");
  assert.ok(Array.isArray(policy.protected_paths));
  assert.ok(policy.protected_paths.includes("src/auth/**"));
  // Quoted sequence item is unquoted.
  assert.ok(policy.protected_paths.includes("**/.env*"));
  assert.ok(Array.isArray(policy.low_risk_paths));
  assert.deepEqual(policy.mapping.ci_workflow_change, [".github/workflows/**"]);
  assert.ok(policy.mapping.production_deployment.includes("infra/**"));
  assert.ok(policy.mapping.protected_branch_merge.includes("src/middleware.ts"));
  assert.deepEqual(policy.mapping.repo_change, ["docs/**", "README.md", "src/components/**"]);
});

test("parseYaml ignores comments and blank lines", () => {
  const parsed = parseYaml(`# header comment
version: 2

list:  # trailing comment
  - a
  - b   # inline
`);
  assert.equal(parsed.version, "2");
  assert.deepEqual(parsed.list, ["a", "b"]);
});

// ---------------------------------------------------------------------------
// Glob matching
// ---------------------------------------------------------------------------
test("globToRegExp handles **, *, exact, and **/.env*", () => {
  assert.match("src/auth/session.ts", globToRegExp("src/auth/**"));
  assert.match("src/auth/nested/dir/file.ts", globToRegExp("src/auth/**"));
  assert.doesNotMatch("src/authentication.ts", globToRegExp("src/auth/**"));

  assert.match(".github/workflows/deploy.yml", globToRegExp(".github/workflows/**"));

  assert.match("src/middleware.ts", globToRegExp("src/middleware.ts"));
  assert.doesNotMatch("src/middleware.tsx", globToRegExp("src/middleware.ts"));

  // **/.env* matches at root and at depth.
  assert.match(".env", globToRegExp("**/.env*"));
  assert.match(".env.local", globToRegExp("**/.env*"));
  assert.match("config/.env.production", globToRegExp("**/.env*"));

  // single star does not cross a slash
  assert.doesNotMatch("a/b.ts", globToRegExp("a*"));
  assert.match("ab.ts", globToRegExp("a*"));
});

// ---------------------------------------------------------------------------
// File -> action type mapping
// ---------------------------------------------------------------------------
test("docs + workflow change maps to ci_workflow_change only (drops repo_change)", () => {
  const files = ["docs/setup.md", ".github/workflows/deploy.yml"];
  const { byType } = matchFilesToActionTypes(files, policy.mapping);
  assert.ok(byType.ci_workflow_change);
  assert.ok(byType.repo_change); // docs still matched repo_change in byType...
  // ...but the planned calls drop repo_change because a high-risk category is present.
  assert.deepEqual(plannedCalls(byType), ["ci_workflow_change"]);
});

test("mixed high-risk PR fans out to one call per category, strongest first", () => {
  const files = [
    ".github/workflows/deploy.yml",
    "supabase/migrations/0012_rls.sql",
    "infra/main.tf",
  ];
  const { byType } = matchFilesToActionTypes(files, policy.mapping);
  assert.deepEqual(plannedCalls(byType), [
    "production_deployment",
    "protected_branch_merge",
    "ci_workflow_change",
  ]);
});

test("low-risk-only PR makes a single repo_change attestation", () => {
  const files = ["docs/readme-notes.md", "src/components/Button.tsx", "README.md"];
  const { byType } = matchFilesToActionTypes(files, policy.mapping);
  assert.deepEqual(plannedCalls(byType), ["repo_change"]);
});

test("unmatched files degrade to repo_change", () => {
  const files = ["some/unmapped/file.txt"];
  const { byType } = matchFilesToActionTypes(files, policy.mapping);
  assert.deepEqual(plannedCalls(byType), ["repo_change"]);
});

test("matched_rules carry path, action_type, glob, and reason", () => {
  const { matchedRules } = matchFilesToActionTypes(["src/auth/session.ts"], policy.mapping);
  const rule = matchedRules.find((r) => r.action_type === "protected_branch_merge");
  assert.ok(rule);
  assert.equal(rule.path, "src/auth/session.ts");
  assert.equal(rule.glob, "src/auth/**");
  assert.match(rule.reason, /protected_branch_merge/);
});

// ---------------------------------------------------------------------------
// Risk flags
// ---------------------------------------------------------------------------
test("computeRiskFlags reflects matched categories and protected paths", () => {
  const files = ["src/auth/session.ts", ".github/workflows/deploy.yml"];
  const { byType } = matchFilesToActionTypes(files, policy.mapping);
  const flags = computeRiskFlags(byType, files, policy);
  assert.ok(flags.includes("protected_branch_merge_path_changed"));
  assert.ok(flags.includes("ci_workflow_changed"));
  assert.ok(flags.includes("protected_path_changed"));
  assert.ok(!flags.includes("low_risk_only"));
});

test("computeRiskFlags marks low_risk_only when nothing high-risk changed", () => {
  const files = ["docs/x.md"];
  const { byType } = matchFilesToActionTypes(files, policy.mapping);
  const flags = computeRiskFlags(byType, files, policy);
  assert.ok(flags.includes("low_risk_only"));
});

// ---------------------------------------------------------------------------
// Fail-closed enforcement
// ---------------------------------------------------------------------------
test("resolveFailClosed: input override beats policy, default is closed", () => {
  // Input override wins over a permissive policy.
  assert.equal(resolveFailClosed({ enforcement: { fail_closed: "false" } }, "true"), true);
  // Input override wins over a strict policy.
  assert.equal(resolveFailClosed({ enforcement: { fail_closed: "true" } }, "false"), false);
  // No input -> policy value is honoured.
  assert.equal(resolveFailClosed({ enforcement: { fail_closed: "false" } }, ""), false);
  assert.equal(resolveFailClosed({ enforcement: { fail_closed: "true" } }, ""), true);
  // No input and no enforcement block -> secure default.
  assert.equal(resolveFailClosed({}, ""), true);
  assert.equal(resolveFailClosed(null, ""), true);
  // The shipped policy is fail-closed.
  assert.equal(resolveFailClosed(policy, ""), true);
});

test("decidePlan blocks when it cannot classify and fail-closed is on", () => {
  // No policy -> block (do not silently attest).
  assert.equal(
    decidePlan({ hasPolicy: false, reliable: false, fileCount: 0, failClosed: true }),
    "block",
  );
  // Unreliable detection on a real change -> block, NOT a repo_change downgrade.
  assert.equal(
    decidePlan({ hasPolicy: true, reliable: false, fileCount: 7, failClosed: true }),
    "block",
  );
});

test("decidePlan attests on a reliable empty change set or an explicit opt-out", () => {
  // Reliable + zero files = genuinely low-risk.
  assert.equal(
    decidePlan({ hasPolicy: true, reliable: true, fileCount: 0, failClosed: true }),
    "attest",
  );
  // Opt-out: unclassifiable but fail-closed disabled.
  assert.equal(
    decidePlan({ hasPolicy: false, reliable: false, fileCount: 0, failClosed: false }),
    "attest",
  );
  assert.equal(
    decidePlan({ hasPolicy: true, reliable: false, fileCount: 4, failClosed: false }),
    "attest",
  );
});

test("decidePlan classifies a reliable, non-empty change set", () => {
  assert.equal(
    decidePlan({ hasPolicy: true, reliable: true, fileCount: 3, failClosed: true }),
    "classify",
  );
});
