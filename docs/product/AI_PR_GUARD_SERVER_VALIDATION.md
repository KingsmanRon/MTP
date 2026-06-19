# AI PR Guard — Server-Side Policy Validation (design sketch)

> Status: **proposed, not implemented.** This sketches the `/verify` contract
> change for review before any backend work. It is the production backbone for
> running the AI PR Guard across many partners.

## Problem

The CI Guard action runs in the *partner's* CI and signs whichever
`action_type` it computed from the changed files. The backend currently trusts
that string at face value (`api/policy.py :: PolicyEngine.evaluate`). Two ways
that fails in production:

1. **Compromised CI key.** Whoever holds the agent's Ed25519 seed can mint a
   signed `repo_change` (attestation, ungated) for a change that is really a
   `production_deployment`, and the gate is bypassed.
2. **Direct call.** Nothing forces a caller to use our action at all. A script
   can `POST /verify` with `action_type: repo_change` and any payload.

The action's fail-closed change (shipped) stops *accidental* downgrades from
detection failures. It does **not** stop a caller who deliberately asserts a
weak action type. The action is a convenience classifier; it cannot be the
security boundary. The server must be.

## Goal

Defense in depth: the server independently establishes the **minimum** action
type a change requires and refuses to honor a weaker assertion, and it binds
each agent to a **registered policy** so an unknown/altered policy is rejected.

## Two assurance tiers

### Tier A — Validate the client-supplied evidence (cheaper, ship first)

`/verify` already receives `payload.changed_files`, `payload.policy_hash`, and
the top-level `policy_hash`. The server:

1. **Enforces a registered policy.** Each agent (or org) registers its
   `.inntris.yml` mapping. `/verify` rejects a request whose `policy_hash` does
   not match the registered policy → new verdict `BLOCKED` /
   violation `POLICY_HASH_MISMATCH`.
2. **Re-derives the minimum action type** from `payload.changed_files` using
   the *registered* mapping (same strongest-wins reduction the action uses).
   If the submitted `action_type` is weaker than the derived minimum →
   `BLOCKED` / `ACTION_TYPE_DOWNGRADE`. (Equal or stronger is allowed.)

Catches: misconfiguration, naive direct calls, and any client that mislabels a
change while honestly reporting `changed_files`.

Does **not** catch: a fully compromised key that crafts a *consistent* lie
(asserts `repo_change` *and* omits the workflow file from `changed_files`),
because the evidence itself is attacker-controlled.

### Tier B — Server fetches the diff itself (assurance ceiling)

For regulated tiers, the server does not trust client-supplied `changed_files`.
Via a **GitHub App installation token**, the backend fetches the PR/commit file
list for `repo` + `pull_request`/`head_sha` in the payload and classifies
authoritatively. The client payload becomes untrusted input used only for
display. This closes the compromised-key downgrade entirely (the key can still
*propose*, but cannot *lower the risk class* of a real change).

Recommendation: **build Tier A now** (small, no new infra), **gate the
regulated tier on Tier B** (GitHub App is the larger lift).

## Contract changes (Tier A)

### Request
No new fields required — `changed_files` and `policy_hash` already exist in the
payload the action sends. (We may promote `changed_files` to a typed, validated
field rather than freeform `payload`.)

### Response
`verdict_reason` carries the new cases. New `PolicyViolation` members:
`POLICY_HASH_MISMATCH`, `ACTION_TYPE_DOWNGRADE`.

### Policy engine (`api/policy.py`)
Add a step between `_check_action_allowed` and `_check_trust_score`:

```
_check_policy_binding(agent, action_type, payload):
    registered = load_registered_policy(agent)        # None in legacy/advisory mode
    if registered is None:
        return APPROVED  # advisory: log, do not block (until rollout completes)
    if payload.policy_hash != registered.hash:
        return BLOCKED(POLICY_HASH_MISMATCH)
    derived = strongest_action_type(payload.changed_files, registered.mapping)
    if RISK_RANK[action_type] < RISK_RANK[derived]:
        return BLOCKED(ACTION_TYPE_DOWNGRADE,
                       reason=f"change requires {derived}, asserted {action_type}")
    return APPROVED
```

`RISK_RANK`: `repo_change < ci_workflow_change < protected_branch_merge <
production_deployment`. `strongest_action_type` mirrors the action's
`plannedCalls`/priority so client and server agree.

### Storage
New `agent_policies` (or columns on `agents`):

| column        | type        | note                                  |
|---------------|-------------|---------------------------------------|
| agent_id      | uuid FK     | owner                                 |
| policy_hash   | varchar(64) | SHA-256 of the canonical `.inntris.yml` |
| mapping       | jsonb       | `{action_type: [globs]}` for re-derivation |
| version       | int         | bump on each registration             |
| active        | bool        |                                       |

RLS: same org-scoping as `agents`. Registration is an admin/API action
(reuses the existing agent-control write path).

### Rollout safety
- **Advisory first:** with no registered policy, `_check_policy_binding`
  returns APPROVED and emits an audit annotation (`policy_binding: unregistered`).
  Lets us deploy without breaking partners mid-onboarding.
- **Enforce per agent/tier:** once a policy is registered (and for the
  regulated tier), mismatches and downgrades block.

## Where the action meets this
- The action already sends `changed_files`, `matched_rules`, `policy_hash` —
  Tier A needs no action change.
- The admin "AI PR Guard" tab becomes the registration surface: the same
  `.inntris.yml` it generates is what gets registered (hash + mapping), so the
  repo file and the server's expectation are derived from one source.

## Open questions for review
1. Registration trigger — explicit admin action, or auto-register the first
   `policy_hash` the agent presents (TOFU) with admin confirmation?
2. Re-derivation parity — share one canonical mapping spec so the JS action and
   the Python server cannot drift (golden test vectors in
   `tests/fixtures`)?
3. Tier B timing — is the GitHub App in scope for the regulated tier launch, or
   a fast-follow?
4. Equal-or-stronger policy — do we ever *block* an over-assertion (client
   claims `production_deployment` for a docs change)? Proposed: allow it
   (stronger gate is safe), but flag it as a risk_flag for audit.
