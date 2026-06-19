const crypto = require("crypto");
const fs = require("fs");

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

function buildPayload(extraPayload) {
  const eventPayload = readEventPayload();
  const pullRequest = eventPayload.pull_request || {};
  const base = {
    platform: "github_actions",
    resource: "repository",
    resource_id: process.env.GITHUB_REPOSITORY || "unknown",
    operation: input("action-type") || "repo_change",
    repository: process.env.GITHUB_REPOSITORY || null,
    ref: process.env.GITHUB_REF || null,
    sha: process.env.GITHUB_SHA || null,
    actor: process.env.GITHUB_ACTOR || null,
    workflow: process.env.GITHUB_WORKFLOW || null,
    job: process.env.GITHUB_JOB || null,
    event_name: process.env.GITHUB_EVENT_NAME || null,
    run_id: process.env.GITHUB_RUN_ID || null,
    run_attempt: process.env.GITHUB_RUN_ATTEMPT || null,
    base_branch: process.env.GITHUB_BASE_REF || pullRequest.base?.ref || null,
    head_branch: process.env.GITHUB_HEAD_REF || pullRequest.head?.ref || null,
    pull_request_number: pullRequest.number || eventPayload.number || null,
    risk_flags: [],
  };
  return { ...base, ...extraPayload };
}

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

function setOutput(name, value) {
  const outputPath = process.env.GITHUB_OUTPUT;
  if (!outputPath || value === undefined || value === null) {
    return;
  }
  fs.appendFileSync(outputPath, `${name}=${String(value)}\n`);
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

function policyHash(policyPath) {
  if (!policyPath || !fs.existsSync(policyPath)) {
    return null;
  }
  return crypto.createHash("sha256").update(fs.readFileSync(policyPath)).digest("hex");
}

async function main() {
  const apiUrl = input("api-url", { required: true }).replace(/\/+$/, "");
  const agentId = input("agent-id", { required: true });
  const privateKeyB64 = input("private-key-b64", { required: true });
  const actionType = input("action-type") || "repo_change";
  const failOnBlock = (input("fail-on-block") || "true").toLowerCase() !== "false";
  const timestamp = new Date().toISOString();
  const nonce = [
    process.env.GITHUB_RUN_ID || "local",
    process.env.GITHUB_RUN_ATTEMPT || "1",
    process.env.GITHUB_JOB || "job",
    crypto.randomUUID(),
  ].join(":");

  const payload = buildPayload(loadExtraPayload(input("payload")));
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
  const clientPolicyHash = policyHash(input("policy-path"));

  const body = {
    agent_id: agentId,
    action_type: actionType,
    payload,
    signature,
    nonce,
    timestamp,
    sig_version: 2,
    policy_hash: clientPolicyHash,
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
  const receiptBase = (input("receipt-url-base") || `${apiUrl}/public/verify`).replace(/\/+$/, "");
  const receiptUrl = auditId ? `${receiptBase}/${auditId}` : "";

  setOutput("verdict", verdict);
  setOutput("audit-id", auditId);
  setOutput("receipt-url", receiptUrl);

  if (receiptUrl) {
    console.log(`Inntris receipt: ${receiptUrl}`);
  }
  console.log(`Inntris verdict: ${verdict}`);
  if (result.verdict_reason) {
    console.log(`Inntris reason: ${result.verdict_reason}`);
  }

  if (!response.ok || (failOnBlock && verdict !== "approved")) {
    const detail = result.detail || result.verdict_reason || `HTTP ${response.status}`;
    throw new Error(`Inntris CI Guard blocked this workflow: ${detail}`);
  }
}

main().catch((error) => {
  console.error(error.message || error);
  process.exitCode = 1;
});
