# Phase 6 handoff — corrected lineage

Every figure here comes from a run on the corrected branch. Nothing is
carried over on trust from the earlier scratch attempt.

## Lineage

| | |
|---|---|
| Branch | `feat/mastercard-vi-proof-corrected` |
| Base | `7354981366b57831c83b7e9161d819ea268edc4c` (frozen, accepted Phase 5) |
| Phase-5 branch | `claude/new-session-39ui0r`, PR #133, draft/unmerged |
| Merge base with Phase 5 | `7354981366b57831c83b7e9161d819ea268edc4c` |
| Relationship | **ahead only**, not diverged |
| Phase-5 provider exercised | `api/connectors/mastercard_vi` |
| Duplicate provider introduced | none |

### The correction

The first attempt branched from **Phase 4** (`60388ba`) because it
searched for a branch named `feat/mastercard-vi-provider`, did not find
one, and concluded Phase 5 did not exist. Its head is `85932ed`.

`git diff 7354981..85932ed` shows that line **deleting** the entire
Phase-5 connector — the 795-line provider plus `scope`, `keys`,
`binding`, `credential`, `profile`, `reference`, the integration profile
document, and 1,974 lines of Phase-5 tests — and substituting a thinner
re-implementation under `api/authority_providers/verifiable_intent/`.
Cherry-picking any of its commits would have destroyed Phase 5. It is
kept as reference material and nothing more; the classification of what
was ported and what was discarded is in [SALVAGE.md](SALVAGE.md).

## Pinned Verifiable Intent upstream

| | |
|---|---|
| Repository | <https://github.com/agent-intent/verifiable-intent> |
| Commit | `356c29635f1c44df7de02edb58699ca9f29bece6` |
| Package version | `0.1.0` |
| Specification | v0.1-draft, 2026-02-18 |

Pinned by Phase 5 in `pyproject.toml` under the `mastercard-vi` extra —
deliberately outside `dev` so `pip-audit --strict` keeps working — and
recorded in `api/connectors/mastercard_vi/profile.py`. Phase 6 adds no
second pin. The installed commit is read back at runtime, written into
every evidence file, and a mismatch fails the proof and a test.

## Command and evidence

```bash
python -m scripts.mastercard_vi_proof
```

Evidence directory: `docs/proofs/mastercard-vi/evidence/` — seven files,
one per case, **generated and not committed**.

Hosted CI surfaced this. Committing the pack put 104 high-entropy public
values — `signing_key_fingerprint`, `signature_b64`, JWK `x`/`y` — next
to key-shaped JSON field names, and the repository's full-history
gitleaks gate flagged every one as `generic-api-key`. The values are
public by construction and none is a secret, but the gate is right about
the shape, and the honest fix is to stop committing a build artefact
whose contents change on every run rather than to teach the secret
scanner to look away from a directory. CI runs the proof and uploads the
pack as the `mastercard-vi-evidence` artifact.

## Reason codes used

| | |
|---|---|
| Organisation recipient violation (case 2) | `wallet_recipient_not_allowed` |
| Organisation spend violation (case 3) | `per_action_limit_exceeded` |
| Exact-action binding (case 4) | `grant_action_mismatch` |
| Executor binding (case 7) | `grant_executor_mismatch` |
| Expiry (case 6) | `grant_expired` |
| Replay under a different reference (case 5) | `execution_ref_conflict` |

All are existing deployed `api.policy.PolicyViolation` /
`DecisionReason` values. The brief's placeholder names
`recipient_not_allowed` and `spend_limit_exceeded` do not exist in this
codebase and are not used.

`execution_ref_conflict` is reported for case 5's replay because that is
what `CONSUMPTION_REJECTION_PRECEDENCE` actually returns: the caller's
reference, not the grant, is what does not match, and the reference
conflict outranks `grant_already_consumed`. It is not renamed.

## Latent Core defects discovered

Each was reproduced on `7354981` with the production services alone — no
proof harness, and for the first two no Verifiable Intent credential —
with a failing regression test written first. All three are in
`tests/test_authority_core_regressions.py`.

### 1. A principal with a `wallet_policy` could never spend a grant — REPRODUCED

`_AgentView` adapts an `agents` row for the policy snapshot builder, and
the driver returns a JSONB column as text unless a codec is registered.
The builder reads `metadata` only when it is a mapping, so the
consumption-time re-derivation computed a digest as though **no wallet
policy were configured**, while issuance had computed one including the
chain and recipient allowlists. The two could never agree, so every
consumption failed `policy_hash_mismatch`.

The effect is total, and it lands on exactly the population the connector
exists for: no principal with a wallet policy could spend a grant at all.

*Minimal fix:* decode JSON-valued columns in `_AgentView.__getattr__`, so
issuance and consumption read the same record. Unparseable metadata is
returned as-is rather than replaced with `{}` — the snapshot builder
records an unreadable wallet policy as "invalid", and an empty mapping
would instead claim none was configured.

### 2. An early BLOCK persisted no policy digest — REPRODUCED

The policy snapshot was built only on the path reaching the domain
policy. Every refusal before that — a core-stage spend or allowlist
violation, an unresolvable delegation, a required-but-missing one —
persisted a decision row with a null `policy_hash`, so nobody could
establish afterwards which policy had refused the act.

*Minimal fix:* capture the snapshot once, as soon as there is an act to
attach it to, and spread it onto the refusal paths. One capture rather
than two derivations, so the digest a BLOCK records and the digest a
grant is issued under cannot drift. No decision changes.

### 3. A payee-restricted delegation was unenforceable through the service — REPRODUCED (new)

Not one of the two the scratch run reported; visible only on the correct
base, because it needs the Phase-5 mapper's `allowed_payees` output.

`PaymentDomainPolicy` binds an approved payee to a concrete destination
through a `PayeeBindingResolver` and fails closed without one —
correctly. But `AuthorityEvaluationService` constructed the policy
without that argument and exposed no parameter for it, so every
delegation carrying `allowed_payees`, which the connector emits for any
mandate with a payee allowlist, was refused `authority_scope_unsupported`
however valid. Phase 5's own integration tests construct
`PaymentDomainPolicy` directly with a resolver, which is why the gap did
not show there.

*Minimal fix:* an optional `payee_binding_resolver` constructor
parameter, passed through to the domain policy. A deployment that
configures none is unaffected, and a delegation whose payee is not bound
to the proposed destination still fails closed.

## Phase-5 behaviour preserved

Verified by the Phase-5 suites continuing to pass unmodified, and by
Phase-6 tests that would fail if any were relaxed:

- trusted issuer-key verification, `kid` as locator only
- L1/L2 cryptographic chain verification against the pinned upstream
- audience verification, principal binding, delegate thumbprint binding
- rotation and revocation semantics — a revoked key reports
  `AUTHORITY_REVOKED`, distinct from never-bound
- insufficient selective disclosure fails closed
- unsupported constraints fail closed
- `amount_range` is per transaction; budget and recurrence unsupported
- exact currency and minor-unit semantics
- payee identity does not itself prove an execution destination
- Layer 3 refused rather than silently ignored
- no `skip_issuer_verification`
- full L1/L2 effective validity intersection
- `AUTHORITY_UNVERIFIED` protection on first consume, never bypassed

## Determinism

Outcomes are deterministic; byte-level determinism is **not** claimed.
Keys are derived from published labels and SD-JWT salts are made
reproducible per build, but ES256 carries a random nonce, so
serialisations and artefact digests differ between runs. Each evidence
file records the digest of the run that produced it.

## Out of scope, and untouched

No Mastercard network call, no Agent Pay or AP4M, no settlement, no
production issuer discovery, no new production domain or public
endpoint, no x402 change, no website or marketing change, no
publication. PR #134 is not modified. Frontend dependency remediation is
not part of this phase.
