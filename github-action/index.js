const crypto = require("crypto");
const fs = require("fs");
const { execFileSync } = require("child_process");
const yaml = require("js-yaml");

// ===========================================================================
// Inntris CI Guard — AI PR Guard
// ===========================================================================
// This action does NOT trust a hand-picked `action-type`. In `ai-pr-guard`
// mode it:
//   1. detects the files a PR (or push) changed,
//   2. maps them to Inntris action types via .inntris.yml,
//   3. reduces to the strongest risk category (dropping repo_change when any
//      high-risk category is present), verifying EACH high-risk category
//      separately, and
//   4. fails the GitHub check unless every Inntris verification approves.
//
// The policy file maps glob path patterns to action types. Mapping precedence
// (strongest wins): production_deployment > protected_branch_merge >
// ci_workflow_change > repo_change. repo_change is attestation-only on the
// backend; the other three gate on trust score (>= 80), so they BLOCK an
// un-vetted agent. That is the whole point — the required check is the
// enforcement point, and it must carry the right action type to be meaningful.

// ---------------------------------------------------------------------------
// Input + small primitives
// ---------------------------------------------------------------------------
function input(name, options = {}) {
  const envName = `INPUT_${name.replace(/ /g, "_").replace(/-/g, "_").toUpperCase()}`;
  const value = process.env[envName] || "";
  if (options.required && !value.trim()) {
    throw new Error(`Missing required input: ${name}`);
  }
  return value.trim();
}

function normalise(value) {
  if (value === null || typeof value !== "object") {
    if (typeof value === "number" && !Number.isFinite(value)) {
      throw new Error("Payload contains a non finite number");
    }
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => normalise(item));
  }
  return Object.keys(value)
    .filter((key) => value[key] !== undefined)
    .sort()
    .reduce((acc, key) => {
      acc[key] = normalise(value[key]);
      return acc;
    }, {});
}

function stableStringify(value) {
  return JSON.stringify(normalise(value));
}

function sha256Hex(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

// ---------------------------------------------------------------------------
// Policy file parsing (js-yaml)
// ---------------------------------------------------------------------------
// .inntris.yml is parsed with js-yaml's safe loader (default schema, no code
// execution). A real YAML parser -- rather than a hand-rolled one -- means a
// partner's policy with quoting, flow style, anchors, or other valid YAML is
// read correctly instead of silently mis-parsed, which would be a fail-open
// risk in a security gate. Only the documented keys are consumed downstream
// (enforcement, protected_paths, low_risk_paths, protected_branches, mapping).

function parseYaml(text) {
  const parsed = yaml.load(String(text || ""));
  return parsed && typeof parsed === "object" ? parsed : {};
}

// ---------------------------------------------------------------------------
// Glob matching
// ---------------------------------------------------------------------------
// Translates a .gitignore/minimatch-style glob into an anchored RegExp.
//   **    matches any characters including "/"
//   *     matches any characters except "/"
//   ?     matches a single character except "/"
//   **/   matches zero or more leading path segments (so `**/.env*` also
//         matches `.env` at the repo root)
function globToRegExp(glob) {
  let re = "";
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === "*") {
      if (glob[i + 1] === "*") {
        if (glob[i + 2] === "/") {
          re += "(?:.*/)?";
          i += 2;
        } else {
          re += ".*";
          i += 1;
        }
      } else {
        re += "[^/]*";
      }
    } else if (c === "?") {
      re += "[^/]";
    } else if (".+^${}()|[]\\/".includes(c)) {
      re += "\\" + c;
    } else {
      re += c;
    }
  }
  return new RegExp("^" + re + "$");
}

// ---------------------------------------------------------------------------
// Risk classification
// ---------------------------------------------------------------------------
// Strongest first. repo_change is attestation-only; the three high-risk
// categories gate on trust score on the backend.
const ACTION_PRIORITY = [
  "production_deployment",
  "protected_branch_merge",
  "ci_workflow_change",
  "repo_change",
];
const HIGH_RISK_ACTIONS = new Set([
  "production_deployment",
  "protected_branch_merge",
  "ci_workflow_change",
]);

function compileMapping(mapping) {
  const compiled = {};
  for (const [type, globs] of Object.entries(mapping || {})) {
    if (!Array.isArray(globs)) {
      continue;
    }
    compiled[type] = globs.map((g) => ({ glob: g, re: globToRegExp(g) }));
  }
  return compiled;
}

// Returns:
//   matchedRules: [{ path, action_type, glob, reason }]
//   byType:       { action_type: [paths...] }
function matchFilesToActionTypes(files, mapping) {
  const compiled = compileMapping(mapping);
  const matchedRules = [];
  const byType = {};
  for (const file of files) {
    for (const type of Object.keys(compiled)) {
      for (const { glob, re } of compiled[type]) {
        if (re.test(file)) {
          matchedRules.push({
            path: file,
            action_type: type,
            glob,
            reason: `Path '${file}' matched '${glob}' (${type})`,
          });
          (byType[type] = byType[type] || []).push(file);
          break;
        }
      }
    }
  }
  return { matchedRules, byType };
}

// The branch a change targets: a PR's base branch, or the pushed branch.
function targetBranch(event) {
  if (event.prNumber) {
    return event.baseRef || null;
  }
  const ref = process.env.GITHUB_REF || "";
  if (ref.startsWith("refs/heads/")) {
    return ref.slice("refs/heads/".length);
  }
  return process.env.GITHUB_REF_NAME || null;
}

// Returns the matching protected-branch pattern (e.g. "release/*"), or null.
function matchProtectedBranch(branch, patterns) {
  if (!branch || !Array.isArray(patterns)) {
    return null;
  }
  for (const pattern of patterns) {
    if (globToRegExp(pattern).test(branch)) {
      return pattern;
    }
  }
  return null;
}

// Combines path-based and branch-based classification. protected_branch_merge
// is added when the target branch is protected -- a branch condition, not a
// file condition -- so the asserted action type is truthful. The two
// dimensions are orthogonal and both flow through the same multi-verify.
function classifyChange({ files, mapping, branch, protectedBranches }) {
  const { matchedRules, byType } = matchFilesToActionTypes(files, mapping);
  const protectedPattern = matchProtectedBranch(branch, protectedBranches);
  if (protectedPattern) {
    // Branch-triggered: no specific files own this category; changed_files in
    // the payload carries what is being merged.
    byType.protected_branch_merge = byType.protected_branch_merge || [];
    matchedRules.push({
      path: `base:${branch}`,
      action_type: "protected_branch_merge",
      glob: protectedPattern,
      reason: `Target branch '${branch}' matches protected branch '${protectedPattern}'`,
    });
  }
  return { matchedRules, byType, branch: branch || null, protectedBranch: protectedPattern };
}

// Reduces the set of matched action types to the list of /verify calls to make.
// If any high-risk category matched, verify each high-risk category separately
// (strongest first) and DROP repo_change. Otherwise make a single low-risk
// repo_change attestation. An empty match also degrades to repo_change.
function plannedCalls(byType) {
  const present = new Set(Object.keys(byType));
  const highRisk = ACTION_PRIORITY.filter((t) => HIGH_RISK_ACTIONS.has(t) && present.has(t));
  if (highRisk.length > 0) {
    return highRisk;
  }
  return ["repo_change"];
}

function computeRiskFlags(byType, files, policy) {
  const flags = [];
  if (byType.production_deployment) {
    flags.push("production_deployment_changed");
  }
  if (byType.protected_branch_merge) {
    flags.push("protected_branch_target");
  }
  if (byType.ci_workflow_change) {
    flags.push("ci_workflow_changed");
  }
  const protectedGlobs = (policy.protected_paths || []).map(globToRegExp);
  if (files.some((f) => protectedGlobs.some((re) => re.test(f)))) {
    flags.push("protected_path_changed");
  }
  const highRiskPresent = [...HIGH_RISK_ACTIONS].some((t) => byType[t]);
  if (!highRiskPresent) {
    flags.push("low_risk_only");
  }
  return flags;
}

// Whether to fail closed when a change cannot be classified. Precedence:
// the `fail-closed` action input (true/false), then `enforcement.fail_closed`
// in the policy file, then the secure default (true).
function resolveFailClosed(policy, inputValue) {
  if (inputValue === "true") {
    return true;
  }
  if (inputValue === "false") {
    return false;
  }
  const enforcement = policy && typeof policy.enforcement === "object" ? policy.enforcement : null;
  if (enforcement && enforcement.fail_closed != null) {
    return String(enforcement.fail_closed).toLowerCase() !== "false";
  }
  return true;
}

// Decide the outcome once detection has been attempted:
//   "block"    -- cannot classify safely (no policy, or unreliable detection)
//                 and fail-closed is on. Does NOT downgrade to attestation.
//   "attest"   -- genuinely low-risk: a reliable, empty change set, or an
//                 unclassifiable change with fail-closed explicitly disabled.
//   "classify" -- a policy is present and the change set is reliable + non-empty.
function decidePlan({ hasPolicy, reliable, fileCount, failClosed }) {
  if (!hasPolicy || !reliable) {
    return failClosed ? "block" : "attest";
  }
  if (fileCount === 0) {
    return "attest";
  }
  return "classify";
}

// ---------------------------------------------------------------------------
// GitHub event + changed-file detection
// ---------------------------------------------------------------------------
function readEventPayload() {
  const eventPath = process.env.GITHUB_EVENT_PATH;
  if (!eventPath || !fs.existsSync(eventPath)) {
    return {};
  }
  try {
    return JSON.parse(fs.readFileSync(eventPath, "utf8"));
  } catch (error) {
    return { parse_error: String(error.message || error) };
  }
}

async function githubApi(token, path) {
  const apiBase = (process.env.GITHUB_API_URL || "https://api.github.com").replace(/\/+$/, "");
  const headers = {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "inntris-verify",
  };
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  const response = await fetch(`${apiBase}${path}`, { headers });
  if (!response.ok) {
    throw new Error(`GitHub API ${path} -> HTTP ${response.status}`);
  }
  return response;
}

async function changedFilesForPullRequest(token, repo, prNumber) {
  const files = [];
  let page = 1;
  // GitHub caps PR file listings at 3000 files / 30 pages of 100.
  for (let i = 0; i < 30; i++) {
    const response = await githubApi(
      token,
      `/repos/${repo}/pulls/${prNumber}/files?per_page=100&page=${page}`,
    );
    const batch = await response.json();
    if (!Array.isArray(batch) || batch.length === 0) {
      break;
    }
    for (const file of batch) {
      if (file && file.filename) {
        files.push(file.filename);
      }
    }
    if (batch.length < 100) {
      break;
    }
    page++;
  }
  return files;
}

function isNullSha(sha) {
  return !sha || /^0+$/.test(sha);
}

function localGitDiff(baseSha, headSha) {
  try {
    const head = headSha || "HEAD";
    const args = !isNullSha(baseSha)
      ? ["diff", "--name-only", `${baseSha}...${head}`]
      : ["diff", "--name-only", "HEAD~1", "HEAD"];
    const out = execFileSync("git", args, { encoding: "utf8" });
    return out
      .split(/\r?\n/)
      .map((s) => s.trim())
      .filter(Boolean);
  } catch (error) {
    return [];
  }
}

// Detection returns { files, reliable, method, error }. `reliable` is the
// pivot for fail-closed enforcement: the GitHub APIs (PR files / compare) are
// authoritative, while a local `git diff` is NOT trusted because CI clones are
// frequently shallow and silently truncate the diff -- the exact fail-open
// condition we are closing. An unreliable result blocks (by default) rather
// than downgrading a high-risk change to an ungated attestation.
async function changedFilesForPush(token, repo, baseSha, headSha) {
  if (token && !isNullSha(baseSha) && headSha) {
    try {
      const response = await githubApi(token, `/repos/${repo}/compare/${baseSha}...${headSha}`);
      const data = await response.json();
      const files = (data.files || []).map((f) => f.filename).filter(Boolean);
      return { files, reliable: true, method: "compare" };
    } catch (error) {
      return {
        files: localGitDiff(baseSha, headSha),
        reliable: false,
        method: "local_git_diff",
        error: String(error.message || error),
      };
    }
  }
  return {
    files: localGitDiff(baseSha, headSha),
    reliable: false,
    method: "local_git_diff",
    error: token ? "missing base sha" : "missing github-token",
  };
}

async function detectChangedFiles(token, event) {
  const { eventName, repo, prNumber, baseSha, headSha } = event;
  if (prNumber) {
    try {
      const files = await changedFilesForPullRequest(token, repo, prNumber);
      return { files, reliable: true, method: "pull_request_files" };
    } catch (error) {
      return {
        files: [],
        reliable: false,
        method: "pull_request_files",
        error: String(error.message || error),
      };
    }
  }
  if (eventName === "push" || baseSha || headSha) {
    return changedFilesForPush(token, repo, baseSha, headSha);
  }
  return {
    files: localGitDiff(baseSha, headSha),
    reliable: false,
    method: "local_git_diff",
    error: "no pull request or push context",
  };
}

function resolveEventContext() {
  const eventPayload = readEventPayload();
  const pullRequest = eventPayload.pull_request || {};
  const prNumber = pullRequest.number || eventPayload.number || null;
  return {
    eventName: process.env.GITHUB_EVENT_NAME || null,
    repo: process.env.GITHUB_REPOSITORY || "unknown",
    actor: process.env.GITHUB_ACTOR || null,
    prNumber,
    baseRef: process.env.GITHUB_BASE_REF || pullRequest.base?.ref || null,
    headRef: process.env.GITHUB_HEAD_REF || pullRequest.head?.ref || null,
    baseSha: pullRequest.base?.sha || eventPayload.before || null,
    headSha: pullRequest.head?.sha || eventPayload.after || process.env.GITHUB_SHA || null,
  };
}

// ---------------------------------------------------------------------------
// Signing + /verify
// ---------------------------------------------------------------------------
function privateKeyFromRawBase64(privateKeyB64) {
  const raw = Buffer.from(privateKeyB64, "base64");
  if (raw.length !== 32 && raw.length !== 64) {
    throw new Error("private-key-b64 must decode to a 32 byte seed or 64 byte Ed25519 secret key");
  }
  const seed = raw.subarray(0, 32);
  const pkcs8Prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  return crypto.createPrivateKey({
    key: Buffer.concat([pkcs8Prefix, seed]),
    format: "der",
    type: "pkcs8",
  });
}

function signActionHash(privateKeyB64, actionHash) {
  const key = privateKeyFromRawBase64(privateKeyB64);
  const signature = crypto.sign(null, Buffer.from(actionHash, "hex"), key);
  return signature.toString("base64");
}

function newNonce() {
  return [
    process.env.GITHUB_RUN_ID || "local",
    process.env.GITHUB_RUN_ATTEMPT || "1",
    process.env.GITHUB_JOB || "job",
    crypto.randomUUID(),
  ].join(":");
}

async function verifyOne({ apiUrl, agentId, privateKeyB64, actionType, payload, policyHashHex, receiptBase }) {
  const timestamp = new Date().toISOString();
  const nonce = newNonce();
  const payloadHash = sha256Hex(stableStringify(payload));
  const signingData = {
    agent_id: agentId,
    action_type: actionType,
    payload_hash: payloadHash,
    nonce,
    timestamp,
  };
  const actionHash = sha256Hex(stableStringify(signingData));
  const signature = signActionHash(privateKeyB64, actionHash);

  const body = {
    agent_id: agentId,
    action_type: actionType,
    payload,
    signature,
    nonce,
    timestamp,
    sig_version: 2,
    policy_hash: policyHashHex,
  };

  const response = await fetch(`${apiUrl}/verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const text = await response.text();
  let result;
  try {
    result = text ? JSON.parse(text) : {};
  } catch (error) {
    result = { detail: text };
  }
  const verdict = result.verdict || "error";
  const auditId = result.audit_id || "";
  const receiptUrl = auditId ? `${receiptBase}/${auditId}` : "";
  return {
    actionType,
    verdict,
    auditId,
    receiptUrl,
    ok: response.ok,
    status: response.status,
    reason: result.verdict_reason || result.detail || "",
  };
}

function policyHash(policyPath) {
  if (!policyPath || !fs.existsSync(policyPath)) {
    return null;
  }
  return crypto.createHash("sha256").update(fs.readFileSync(policyPath)).digest("hex");
}

// Canonical, formatting-independent hash of the policy's *enforced* content:
// the path mapping plus protected branches. The server registers and re-derives
// from exactly these two fields, so hashing only them means a comment or
// whitespace change (or a CRLF checkout) in .inntris.yml does not flip the hash
// and trigger a spurious POLICY_HASH_MISMATCH. Must match
// canonical_policy_hash() in api/policy.py.
function canonicalPolicyHash(policy) {
  if (!policy) {
    return null;
  }
  return sha256Hex(
    stableStringify({
      mapping: policy.mapping || {},
      protected_branches: policy.protected_branches || [],
    }),
  );
}

function loadExtraPayload(raw) {
  if (!raw) {
    return {};
  }
  const parsed = JSON.parse(raw);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("payload input must be a JSON object");
  }
  return parsed;
}

function setOutput(name, value) {
  const outputPath = process.env.GITHUB_OUTPUT;
  if (!outputPath || value === undefined || value === null) {
    return;
  }
  fs.appendFileSync(outputPath, `${name}=${String(value)}\n`);
}

// ---------------------------------------------------------------------------
// Legacy single-call payload (mode != ai-pr-guard)
// ---------------------------------------------------------------------------
function buildLegacyPayload(actionType, extraPayload) {
  const event = resolveEventContext();
  const base = {
    platform: "github_actions",
    resource: "repository",
    resource_id: event.repo,
    operation: actionType,
    repository: event.repo,
    ref: process.env.GITHUB_REF || null,
    sha: event.headSha,
    actor: event.actor,
    workflow: process.env.GITHUB_WORKFLOW || null,
    job: process.env.GITHUB_JOB || null,
    event_name: event.eventName,
    run_id: process.env.GITHUB_RUN_ID || null,
    run_attempt: process.env.GITHUB_RUN_ATTEMPT || null,
    base_branch: event.baseRef,
    head_branch: event.headRef,
    pull_request_number: event.prNumber,
    risk_flags: [],
  };
  return { ...base, ...extraPayload };
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------
function reportResults(results) {
  for (const r of results) {
    if (r.receiptUrl) {
      console.log(`Inntris receipt (${r.actionType}): ${r.receiptUrl}`);
    }
    console.log(`Inntris verdict (${r.actionType}): ${r.verdict}`);
    if (r.reason) {
      console.log(`Inntris reason (${r.actionType}): ${r.reason}`);
    }
  }
}

function aggregate(results) {
  const allApproved = results.every((r) => r.ok && r.verdict === "approved");
  // Surface the blocking receipt first; otherwise the strongest category.
  const blocking = results.find((r) => !(r.ok && r.verdict === "approved"));
  const primary = blocking || results[0] || {};
  return {
    verdict: allApproved ? "approved" : "blocked",
    allApproved,
    primary,
  };
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
async function main() {
  const apiUrl = input("api-url", { required: true }).replace(/\/+$/, "");
  const agentId = input("agent-id", { required: true });
  const privateKeyB64 = input("private-key-b64", { required: true });
  const mode = (input("mode") || "ai-pr-guard").toLowerCase();
  const fallbackActionType = input("action-type") || "repo_change";
  const failOnBlock = (input("fail-on-block") || "true").toLowerCase() !== "false";
  const githubToken = input("github-token") || process.env.GITHUB_TOKEN || "";
  const policyFile = input("policy-file") || input("policy-path") || ".inntris.yml";
  const extraPayload = loadExtraPayload(input("payload"));
  // Legacy/attestation paths keep the raw-file hash. The ai-pr-guard classify
  // path uses the canonical hash (computed once the policy is parsed) so it
  // matches what the server registered.
  const rawPolicyHashHex = policyHash(policyFile);
  const receiptBase = (input("receipt-url-base") || `${apiUrl}/public/verify`).replace(/\/+$/, "");

  const sharedVerifyArgs = {
    apiUrl,
    agentId,
    privateKeyB64,
    policyHashHex: rawPolicyHashHex,
    receiptBase,
  };

  // --- Legacy single-call mode -------------------------------------------
  if (mode !== "ai-pr-guard") {
    const payload = buildLegacyPayload(fallbackActionType, extraPayload);
    const result = await verifyOne({ ...sharedVerifyArgs, actionType: fallbackActionType, payload });
    finishSingle(result, failOnBlock);
    return;
  }

  // --- AI PR Guard mode ---------------------------------------------------
  const event = resolveEventContext();
  const policy = fs.existsSync(policyFile)
    ? parseYaml(fs.readFileSync(policyFile, "utf8"))
    : null;
  const hasPolicy = !!(policy && policy.mapping);
  const failClosed = resolveFailClosed(policy, input("fail-closed").toLowerCase());

  const detection = hasPolicy
    ? await detectChangedFiles(githubToken, event)
    : { files: [], reliable: false, method: "no_policy" };
  if (hasPolicy) {
    console.log(
      `Inntris: detection method=${detection.method} reliable=${detection.reliable} ` +
        `files=${detection.files.length} fail_closed=${failClosed}.`,
    );
  }

  const plan = decidePlan({
    hasPolicy,
    reliable: detection.reliable,
    fileCount: detection.files.length,
    failClosed,
  });

  if (plan === "block") {
    const reason = !hasPolicy
      ? `no usable policy at '${policyFile}' (need a 'mapping:' block)`
      : `could not reliably determine changed files (method=${detection.method}` +
        `${detection.error ? `: ${detection.error}` : ""}). Ensure 'permissions: pull-requests: read' ` +
        `and a github-token are set, or set enforcement.fail_closed=false to attest instead`;
    finishFailClosed(reason, failOnBlock);
    return;
  }

  if (plan === "attest") {
    console.log(
      `Inntris: ${hasPolicy ? "reliable empty change set" : "no policy and fail-closed disabled"}; ` +
        `recording a single '${fallbackActionType}' attestation.`,
    );
    const payload = buildLegacyPayload(fallbackActionType, extraPayload);
    const result = await verifyOne({ ...sharedVerifyArgs, actionType: fallbackActionType, payload });
    finishSingle(result, failOnBlock);
    return;
  }

  // plan === "classify"
  const files = detection.files;
  const branch = targetBranch(event);
  const { matchedRules, byType, protectedBranch } = classifyChange({
    files,
    mapping: policy.mapping,
    branch,
    protectedBranches: policy.protected_branches,
  });
  const riskFlags = computeRiskFlags(byType, files, policy);
  const calls = plannedCalls(byType);

  console.log(
    `Inntris: target branch '${branch || "unknown"}'` +
      `${protectedBranch ? ` (protected: ${protectedBranch})` : ""}; ` +
      `risk flags [${riskFlags.join(", ") || "none"}]; ` +
      `verifying ${calls.length} categor${calls.length === 1 ? "y" : "ies"}: ${calls.join(", ")}.`,
  );

  // The hash the server registered is canonical over {mapping, protected_branches}.
  const policyHashHex = canonicalPolicyHash(policy);

  const basePayload = {
    platform: "github_actions",
    resource: "repository",
    resource_id: event.repo,
    repo: event.repo,
    event: event.eventName,
    pull_request: event.prNumber,
    base_ref: event.baseRef,
    head_ref: event.headRef,
    base_sha: event.baseSha,
    head_sha: event.headSha,
    actor: event.actor,
    workflow: process.env.GITHUB_WORKFLOW || null,
    run_id: process.env.GITHUB_RUN_ID || null,
    changed_files: files,
    protected_branch: protectedBranch || null,
    risk_flags: riskFlags,
    policy_file: policyFile,
    policy_hash: policyHashHex,
  };

  const results = [];
  for (const actionType of calls) {
    const rulesForType = matchedRules.filter((r) => r.action_type === actionType);
    const payload = {
      ...basePayload,
      operation: actionType,
      matched_files: byType[actionType] || [],
      matched_rules: rulesForType.length > 0 ? rulesForType : matchedRules,
      ...extraPayload,
    };
    results.push(await verifyOne({ ...sharedVerifyArgs, policyHashHex, actionType, payload }));
  }

  reportResults(results);
  const { verdict, allApproved, primary } = aggregate(results);
  setOutput("verdict", verdict);
  setOutput("audit-id", primary.auditId || "");
  setOutput("receipt-url", primary.receiptUrl || "");
  setOutput("action-types", calls.join(","));
  setOutput(
    "verdicts",
    JSON.stringify(
      results.map((r) => ({
        action_type: r.actionType,
        verdict: r.verdict,
        audit_id: r.auditId,
        receipt_url: r.receiptUrl,
      })),
    ),
  );

  if (failOnBlock && !allApproved) {
    const blocked = results
      .filter((r) => !(r.ok && r.verdict === "approved"))
      .map((r) => `${r.actionType}: ${r.verdict}${r.reason ? ` (${r.reason})` : ""}`)
      .join("; ");
    throw new Error(`Inntris CI Guard blocked this workflow: ${blocked}`);
  }
}

// Records a fail-closed block: no /verify call (there is nothing trustworthy
// to verify), an explicit "blocked" verdict on the outputs, and -- unless
// fail-on-block is disabled -- a non-zero exit so the required check fails.
function finishFailClosed(reason, failOnBlock) {
  console.error(`Inntris CI Guard failing closed: ${reason}`);
  setOutput("verdict", "blocked");
  setOutput("audit-id", "");
  setOutput("receipt-url", "");
  setOutput("action-types", "");
  setOutput("verdicts", JSON.stringify([{ action_type: null, verdict: "blocked", reason }]));
  if (failOnBlock) {
    throw new Error(`Inntris CI Guard failed closed: ${reason}`);
  }
}

function finishSingle(result, failOnBlock) {
  reportResults([result]);
  setOutput("verdict", result.verdict);
  setOutput("audit-id", result.auditId || "");
  setOutput("receipt-url", result.receiptUrl || "");
  setOutput("action-types", result.actionType);
  setOutput(
    "verdicts",
    JSON.stringify([
      {
        action_type: result.actionType,
        verdict: result.verdict,
        audit_id: result.auditId,
        receipt_url: result.receiptUrl,
      },
    ]),
  );
  if (failOnBlock && !(result.ok && result.verdict === "approved")) {
    const detail = result.reason || `HTTP ${result.status}`;
    throw new Error(`Inntris CI Guard blocked this workflow: ${detail}`);
  }
}

if (require.main === module) {
  main().catch((error) => {
    console.error(error.message || error);
    process.exitCode = 1;
  });
}

module.exports = {
  parseYaml,
  globToRegExp,
  canonicalPolicyHash,
  matchFilesToActionTypes,
  matchProtectedBranch,
  classifyChange,
  plannedCalls,
  computeRiskFlags,
  resolveFailClosed,
  decidePlan,
  compileMapping,
  normalise,
  stableStringify,
  sha256Hex,
  ACTION_PRIORITY,
  HIGH_RISK_ACTIONS,
};
