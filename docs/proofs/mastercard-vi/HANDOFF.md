# Phase 6 handoff

Filled in from the proof run, not from expectation. Every figure here is
reproducible by the command below.

## Branch

`claude/new-session-yuvxz8`, built on `feat/authority-endpoints`
(phases 1–4).

**Phase 5 did not exist.** No `feat/mastercard-vi-provider` branch was
present in the repository, and no VI code of any kind. The brief's
phase-5 dependency — a provider that resolves a VI delegation into
`ResolvedAuthority` — was therefore built as part of this work, in
`api/authority_providers/verifiable_intent/`, before the proof that
verifies against it. See "Deviations" below.

## Pinned VI upstream

| | |
|---|---|
| Repository | <https://github.com/agent-intent/verifiable-intent> |
| Commit | `356c29635f1c44df7de02edb58699ca9f29bece6` |
| Specification | v0.1-draft |

Pinned in `pyproject.toml` under the `vi-proof` extra. The installed
commit is read back from the distribution's `direct_url.json` at runtime,
written into every evidence file, and the proof refuses to run on a
mismatch.

## Exact command

```bash
pip install -e '.[dev,vi-proof]'
alembic upgrade head
python -m scripts.mastercard_vi_proof
```

Requires `DATABASE_URL` on a PostgreSQL migrated to head.

## Evidence directory

`docs/proofs/mastercard-vi/evidence/` — seven files, one per case.

## Organisation violation codes used

| | |
|---|---|
| Recipient (case 2) | `wallet_recipient_not_allowed` |
| Spend (case 3) | `per_action_limit_exceeded` |

Both are the existing deployed `api.policy.PolicyViolation` values. The
brief's placeholder names `recipient_not_allowed` and
`spend_limit_exceeded` do not exist in this codebase and are not used.

Binding refusals use the phase-3 typed equivalents:
`grant_action_mismatch` (the brief's `action_hash_mismatch`),
`grant_executor_mismatch`, `grant_expired`, `execution_ref_conflict`.

## Cases that behaved differently from the expected table

**Case 5's replay reports `execution_ref_conflict`, not
`grant_already_consumed`.** Both codes describe the attempt truthfully.
`CONSUMPTION_REJECTION_PRECEDENCE` ranks the reference conflict higher
because the caller's problem is that their reference does not match, not
that the grant is spent. The brief's "already_consumed/refused" is
satisfied; the more specific code is reported.

Nothing else diverged. All seven cases produced the expected verdicts on
the first complete run.

## What the proof revealed

Two real defects, both in phase 1–4 code, both fixed here:

1. **A principal with a `wallet_policy` could never spend a grant.**
   `_AgentView` handed the policy snapshot builder raw JSONB text for
   `metadata`, and the builder reads it only when it is a mapping. The
   consumption-time re-derivation therefore produced a digest that
   omitted the agent's own chain and recipient allowlists, and every
   consumption failed with `policy_hash_mismatch`. Since the recipient
   allowlist is exactly what cases 1 to 7 depend on, no VI-authorised
   wallet payment could have been executed at all.

2. **A refusal that happened before the domain policy ran recorded a null
   policy digest**, leaving that decision unauditable. The snapshot is
   now captured as soon as there is an act to attach it to, so a BLOCK
   and an ALLOW are equally provable. No decision changed.

Neither was found by the existing 1,453 tests.

## Receipt v3 verification

Every case's evidence file carries a signed decision event, plus a
consumption event where authority was spent, built with
`build_evidence_chain` and verified with the public half only.
`receipt_v3.chain_verified` is `true` in all seven, with no failures. The
verifying public key is published alongside so a reader can repeat the
check.

The forgery case (acceptance case 21) edits the verdict, recomputes an
internally consistent payload hash, and the verifier still refuses on the
signature.

## CI

`.github/workflows/ci.yml` installs `.[dev,vi-proof]`, runs the full
pytest suite, then runs the documented proof command end to end against
the CI PostgreSQL, writing evidence to a scratch directory. A skipped
proof would report green while proving nothing, so the upstream pin is
asserted by a test rather than tolerated.

Local run on PostgreSQL 16: 1,497 passed, 14 skipped. Proof: 7 cases
passed, 44 assertions held.

## Deviations from the brief

- **Branch names.** The brief specifies `feat/mastercard-vi-proof` off
  `feat/mastercard-vi-provider`. Neither existed; this session's
  designated branch is `claude/new-session-yuvxz8`, taken off
  `feat/authority-endpoints`.
- **Phase 5 built here.** Unavoidable: phase 6 verifies against a
  provider that did not exist. It is kept unwired — no endpoint
  constructs it, so no deployed behaviour changes.
- **Two additive service hooks** were needed for the VI path to work end
  to end: the trusted principal binding an `AuthorityProvider` needs to
  answer "is this artefact this principal's", and a payee binding
  resolver, without which a scope restricting payees cannot be enforced
  at all. Both default to absent and change nothing for a deployment that
  configures neither.
- **Byte-level determinism is not claimed.** ES256 nonces and SD-JWT
  salts are random by design; fixing them would mean patching the
  reference implementation's cryptography. Outcomes are deterministic;
  artefact digests are recorded per run.
