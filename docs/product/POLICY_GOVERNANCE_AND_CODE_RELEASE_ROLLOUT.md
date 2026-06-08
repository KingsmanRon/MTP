# Policy Governance And Code Release Rollout

## Current Rollout

Inntris currently stores the active agent controls directly on the `agents`
row. An admin save updates the live allowlist, blocklist, spend limits, and
rate limit immediately.

The verifier can allow or block an entire action type. The admin UI exposes:

- runtime actions such as tool calls, API calls, spend, and data export;
- repository changes;
- CI/CD workflow changes;
- protected-branch merges; and
- production deployments.

`repo_change` remains an attestation action. It is useful for recording a
commit or pull-request change, but it should not authorize a merge.
`protected_branch_merge`, `ci_workflow_change`, and `production_deployment`
are high-risk runtime actions with explicit trust-score thresholds.

## What A Merge Block Requires

An Inntris BLOCK only prevents a merge when GitHub is configured to enforce
the Inntris result.

```text
Pull request update
  -> required Inntris GitHub check
  -> signed /verify request for protected_branch_merge
  -> PASS creates successful required check
  -> BLOCK creates failed required check
  -> GitHub ruleset prevents merge
```

The check payload should bind the decision to the exact proposed merge:

```json
{
  "repository": "owner/repository",
  "pull_request": 42,
  "base_branch": "master",
  "head_sha": "exact-commit-sha",
  "changed_paths": ["api/policy.py", ".github/workflows/ci.yml"],
  "actor": "agent-or-github-identity",
  "promptfoo_evidence": {
    "result": "pass",
    "artifact_hash": "optional-hash"
  }
}
```

The repository ruleset must:

- require the Inntris check before merge;
- require checks to be current for the latest head SHA;
- restrict or audit bypass permissions; and
- apply to the configured production branch. Inntris itself currently deploys
  from `master`; customer repositories may use `main` or another branch.

## Current Enforcement Limit

The current policy engine evaluates action type, status, trust score, rate
limit, and spend. It does not yet evaluate conditional payload rules.

This means the current rollout can express:

- block every protected-branch merge for an agent; or
- allow protected-branch merges for an agent that satisfies the runtime
  checks.

It cannot yet express:

- allow ordinary code changes but block database migrations;
- require approval only when `.github/workflows/**` changes;
- allow merge only when Promptfoo evidence passes; or
- allow deployment only during a maintenance window.

The existing `policy_rules` table models conditions and `require_approval`,
but it is not currently connected to `PolicyEngine.evaluate`.

## Policy Change History And Hash Diff

Policy history requires immutable policy versions rather than editing the
active agent row without a record.

Each version should record:

- canonical policy JSON;
- a server-computed SHA-256 policy hash;
- prior and new policy hashes;
- a structured field-level diff;
- creator identity and reason;
- status: `draft`, `pending_approval`, `active`, `rejected`, or `superseded`;
- approver identity and decision; and
- activation timestamp.

A rollback should create and promote a new version based on an older policy.
It should never rewrite history.

## Approval-Backed Promotion

Approval-backed promotion separates editing from activation:

```text
Edit controls
  -> create draft version
  -> review hash diff
  -> submit for approval
  -> authorized approver approves
  -> version becomes active atomically
  -> new verification receipts bind the active policy hash
```

This requires:

1. Named admin identities or API-key identities with enforced roles.
2. A policy-version store and immutable approval events.
3. Server-owned canonicalization and policy hashing.
4. Promotion APIs with separation-of-duties checks.
5. Verification that loads the active server policy and binds its hash to the
   receipt.
6. Admin history, diff, approval, and rollback screens.

The current admin session authenticates an organization API key and does not
identify a human approver. The current `/verify` request also accepts an
adapter-supplied policy hash. Both must change before Inntris can claim
approval-backed policy governance.

### Current Policy-Hash Boundary

The current policy hash is stored on the immutable audit row and included in
the canonical public-receipt fingerprint for v2 receipts. It is not currently
included in the agent's Ed25519-signed action envelope.

This means Inntris can prove that a receipt record containing a policy hash was
preserved and anchored, but should not claim that the agent signature itself
covered that policy hash.

Approval-backed policy governance therefore also requires:

- a new signing-envelope version that includes the active policy hash;
- adapter and SDK support for that envelope; and
- server verification that the signed hash equals the active promoted policy
  hash.

## Recommended Delivery Order

1. Ship the required GitHub check adapter for `protected_branch_merge`.
2. Add conditional path and evidence rules to the policy engine.
3. Add server-owned policy versions, hashes, and history.
4. Add a signing-envelope version that binds the active policy hash.
5. Add named admin identities and policy roles.
6. Add approval-backed promotion and rollback.
7. Add deployment-environment enforcement for `production_deployment`.

## Recommended Demo

Use one repository and one protected branch:

1. The coding agent may create a pull request and record `repo_change`.
2. The admin blocks `protected_branch_merge`.
3. The required Inntris check returns BLOCK and GitHub prevents merge.
4. The admin allows the action and saves the live policy.
5. The check reruns against the exact head SHA and returns PASS.
6. The Inntris audit page shows both decisions and their receipts.

Until policy promotion approvals ship, state clearly that the admin save
activates the policy immediately.
