# Runbook: AI PR Guard end-to-end go-live

Validates the whole gate against a live Core API and a real GitHub repo: detect
changed files -> classify by risk -> verify server-side -> enforce the required
check -> read the receipt. Run it once before exposing the gate to a partner.

## 0. Prerequisites

- A deployed Core API (`INNTRIS_API_URL`) with Redis (nonce replay protection is
  fail-closed; `/verify` returns 503 without it).
- An **admin-scoped** API key and your `org_id`.
- A target GitHub repository you can add Secrets + workflows to.

## 1. Apply migrations

Bring the schema up to date (run Alembic with the **privileged** DSN, not the
RLS app role):

```bash
alembic upgrade head
```

This includes:
- `0006_agent_policies` (SQL `010`) — Tier A policy registration + binding.
- `0007_agent_key_rotation` (SQL `011`) — signing-key rotation + history.

Confirm: `\d agent_policies` and `\d agent_key_history` exist, and `agents` has
`key_version` / `key_rotated_at`.

## 2. Provision a demo agent

```bash
export INNTRIS_API_URL=https://core.example.com
export INNTRIS_ADMIN_API_KEY=...        # admin scope
export INNTRIS_ORG_ID=<uuid>            # must match the key's org
python scripts/provision_demo_agent.py --name "demo repo guard" --trust 85
```

The script generates a keypair, creates + activates the agent, applies the
Regulated AI PR Gate controls + trust, and **registers the policy** from
`.inntris.yml`. It prints `agent_id`, the policy hash/version, and the two
GitHub Secrets. Keep `INNTRIS_PRIVATE_KEY_B64` secret — it is shown once.

## 3. Wire up the repo

### Fastest: dogfood this repo (no external action)

This repo already ships `.github/workflows/inntris-ai-pr-guard.yml`, which runs
the **local** action (`uses: ./`) and is **inert until enabled**. To turn it on:

1. Set repo **Secrets**: `INNTRIS_API_URL`, `INNTRIS_PRIVATE_KEY_B64` (from
   step 2).
2. Set repo **Variables**: `INNTRIS_AGENT_ID` (from step 2) and
   `INNTRIS_AI_PR_GUARD=on`.
3. Open a PR and confirm the **Inntris AI PR Guard** check runs.
4. **Then** make it required on the branch (GitHub branch protection / ruleset)
   — a BLOCK only prevents a merge when the check is required, and a required
   check that is *skipped* (variable off) leaves a PR stuck pending, so enable
   and verify before requiring.

> Note: this repo's default branch is `master`, but the demo `.inntris.yml`
> lists `main`/`release/*`/`production` as protected. Path categories
> (`ci_workflow_change`, `production_deployment`) still fire on `master` PRs. To
> also exercise `protected_branch_merge` here, add `master` to
> `protected_branches` in `.inntris.yml` and re-register the policy.

### External repo

In the target repo: commit `.inntris.yml` (must match what was registered) and
the workflow the admin **AI PR Guard** tab generates (its `uses:` comes from
`NEXT_PUBLIC_INNTRIS_ACTION_REF` — see `github-action/RELEASING.md`), set the two
secrets + the agent-id, confirm **Server-side enforcement** shows
**Enforcing · v1**, then make the check required.

## 4. Drive the cases

Open PRs into `main` and watch the required check + read each receipt in the
admin **Audit** detail (the **AI PR Guard** section shows changed files, matched
rules, risk flags, the protected-branch match, and `policy_binding`).

| Case | How | Expected |
|------|-----|----------|
| **PASS** | trust ≥ 80; PR touches `.github/workflows/**` or `infra/**` into `main` | check passes; receipt shows the category + `Enforcing` |
| **BLOCK on trust** | set trust to 50 (admin → Action controls → Trust score, or PATCH), reopen/rerun | check fails: `trust_score_too_low`; receipt shows the blocked category |
| **Fail-closed** | remove `permissions: pull-requests: read` (or the token) from the workflow | check fails: the guard blocks rather than attesting |
| **Truthful branch** | docs-only PR into `main` | category is `protected_branch_merge` (gated), not `repo_change` |

Tier A's anti-downgrade is automatic: the action classifies, and the server
re-derives the minimum action type from the registered policy — a hand-crafted
`/verify` asserting `repo_change` for a workflow change is rejected
(`action_type_downgrade`).

## 5. Leak-response drill (optional)

1. Admin → AI PR Guard → **Signing key** → **Rotate signing key**.
2. Update `INNTRIS_PRIVATE_KEY_B64` with the new seed; rerun a PR → passes.
3. Temporarily restore the OLD secret → the run fails `signature_invalid`,
   proving the old key is dead. Restore the new secret.
4. Scope a leak: query `audit_logs` by `metadata->>'key_fingerprint'`
   (see `agent_key_rotation.md`).

## 6. Cleanup

Suspend or delete the demo agent when done (admin → Action controls → Suspend),
and remove the repo Secrets. Suspending makes every verification fail closed.

## Troubleshooting

- **503 from `/verify`** — Redis unavailable; the nonce check is fail-closed.
- **`agent_not_active`** — the agent wasn't activated (step 2 does this).
- **`action_not_allowed`** — a code/release action is blocked; apply the
  Regulated AI PR Gate preset so blocks reflect trust.
- **`policy_hash_mismatch`** — the committed `.inntris.yml` mapping/protected
  branches differ from what was registered; re-register or recommit.
- **Check passes but doesn't block merges** — the check isn't *required* on the
  branch (step 3.5).
