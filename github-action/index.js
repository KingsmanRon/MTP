const crypto = require("crypto");
const fs = require("fs");
const { execFileSync } = require("child_process");

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
// Minimal YAML reader for .inntris.yml
// ---------------------------------------------------------------------------
// Supports exactly the documented .inntris.yml subset: top-level scalars
// (`version: 1`), block sequences (`- pattern`), and one level of nested
// mapping (`mapping:` -> action_type -> sequence). Comments (`#`) and blank
// lines are ignored; sequence items may be single- or double-quoted. This is
// not a general YAML parser — keep .inntris.yml within the documented shape.
function stripComment(line) {
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === "'" && !inDouble) {
      inSingle = !inSingle;
    } else if (c === '"' && !inSingle) {
      inDouble = !inDouble;
    } else if (c === "#" && !inSingle && !inDouble) {
      if (i === 0 || /\s/.test(line[i - 1])) {
        return line.slice(0, i);
      }
    }
  }
  return line;
}

function unquote(raw) {
  const s = raw.trim();
  if (
    s.length >= 2 &&
    ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'")))
  ) {
    return s.slice(1, -1);
  }
  return s;
}

function indentOf(line) {
  return line.length - line.replace(/^ +/, "").length;
}

function parseYaml(text) {
  const lines = [];
  for (const raw of String(text).split(/\r?\n/)) {
    const noComment = stripComment(raw).replace(/\s+$/, "");
    if (noComment.trim() === "") {
      continue;
    }
    lines.push(noComment);
  }

  let pos = 0;

  function parseSequence(parentIndent) {
    const arr = [];
    while (pos < lines.length) {
      const ind = indentOf(lines[pos]);
      if (ind <= parentIndent) {
        break;
      }
      const content = lines[pos].slice(ind);
      if (!content.startsWith("-")) {
        break;
      }
      arr.push(unquote(content.slice(1).trim()));
      pos++;
    }
    return arr;
  }

  function parseMap(minIndent) {
    const obj = {};
    if (pos >= lines.length || indentOf(lines[pos]) < minIndent) {
      return obj;
    }
    const entryIndent = indentOf(lines[pos]);
    while (pos < lines.length) {
      const ind = indentOf(lines[pos]);
      if (ind < entryIndent) {
        break;
      }
      if (ind > entryIndent) {
        // Defensive: an unexpected deeper line with no owning key.
        pos++;
        continue;
      }
      const content = lines[pos].slice(entryIndent);
      const colon = content.indexOf(":");
      if (colon === -1) {
        break;
      }
      const key = content.slice(0, colon).trim();
      const after = content.slice(colon + 1).trim();
      pos++;
      if (after !== "") {
        obj[key] = unquote(after);
        continue;
      }
      if (pos < lines.length && indentOf(lines[pos]) > entryIndent) {
        const childIndent = indentOf(lines[pos]);
        const childContent = lines[pos].slice(childIndent);
        obj[key] = childContent.startsWith("-")
          ? parseSequence(entryIndent)
          : parseMap(entryIndent + 1);
      } else {
        obj[key] = null;
      }
    }
    return obj;
  }

  return parseMap(0);
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
    flags.push("protected_branch_merge_path_changed");
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

async function changedFilesForPush(token, repo, baseSha, headSha) {
  if (token && !isNullSha(baseSha) && headSha) {
    try {
      const response = await githubApi(token, `/repos/${repo}/compare/${baseSha}...${headSha}`);
      const data = await response.json();
      return (data.files || []).map((f) => f.filename).filter(Boolean);
    } catch (error) {
      // Fall through to a local diff (e.g. forks without compare access).
    }
  }
  return localGitDiff(baseSha, headSha);
}

async function detectChangedFiles(token, event) {
  const { eventName, repo, prNumber, baseSha, headSha } = event;
  if (prNumber) {
    return changedFilesForPullRequest(token, repo, prNumber);
  }
  if (eventName === "push" || baseSha || headSha) {
    return changedFilesForPush(token, repo, baseSha, headSha);
  }
  return localGitDiff(baseSha, headSha);
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
  const policyHashHex = policyHash(policyFile);
  const receiptBase = (input("receipt-url-base") || `${apiUrl}/public/verify`).replace(/\/+$/, "");

  const sharedVerifyArgs = { apiUrl, agentId, privateKeyB64, policyHashHex, receiptBase };

  // --- Legacy single-call mode -------------------------------------------
  if (mode !== "ai-pr-guard") {
    const payload = buildLegacyPayload(fallbackActionType, extraPayload);
    const result = await verifyOne({ ...sharedVerifyArgs, actionType: fallbackActionType, payload });
    finishSingle(result, failOnBlock);
    return;
  }

  // --- AI PR Guard mode ---------------------------------------------------
  const event = resolveEventContext();
  const policy = policyHashHex && fs.existsSync(policyFile)
    ? parseYaml(fs.readFileSync(policyFile, "utf8"))
    : null;

  if (!policy || !policy.mapping) {
    console.log(
      `Inntris: no usable policy at '${policyFile}' (need a 'mapping:' block); ` +
        `falling back to a single '${fallbackActionType}' attestation.`,
    );
    const payload = buildLegacyPayload(fallbackActionType, extraPayload);
    const result = await verifyOne({ ...sharedVerifyArgs, actionType: fallbackActionType, payload });
    finishSingle(result, failOnBlock);
    return;
  }

  const files = await detectChangedFiles(githubToken, event);
  console.log(`Inntris: ${files.length} changed file(s) detected for ${event.eventName || "event"}.`);

  if (files.length === 0) {
    console.log(
      `Inntris: no changed files resolved (missing token or history?); ` +
        `falling back to a single '${fallbackActionType}' attestation.`,
    );
    const payload = buildLegacyPayload(fallbackActionType, extraPayload);
    const result = await verifyOne({ ...sharedVerifyArgs, actionType: fallbackActionType, payload });
    finishSingle(result, failOnBlock);
    return;
  }

  const { matchedRules, byType } = matchFilesToActionTypes(files, policy.mapping);
  const riskFlags = computeRiskFlags(byType, files, policy);
  const calls = plannedCalls(byType);

  console.log(
    `Inntris: risk flags [${riskFlags.join(", ") || "none"}]; ` +
      `verifying ${calls.length} categor${calls.length === 1 ? "y" : "ies"}: ${calls.join(", ")}.`,
  );

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
    results.push(await verifyOne({ ...sharedVerifyArgs, actionType, payload }));
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
  matchFilesToActionTypes,
  plannedCalls,
  computeRiskFlags,
  compileMapping,
  normalise,
  stableStringify,
  sha256Hex,
  ACTION_PRIORITY,
  HIGH_RISK_ACTIONS,
};
