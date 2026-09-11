# Salvage classification: scratch `85932ed` → corrected Phase-6 lineage

The first Phase-6 attempt branched from **Phase 4** (`60388ba`) because it
searched for a branch named `feat/mastercard-vi-provider`, did not find
one, and wrongly concluded Phase 5 did not exist. Phase 5 is
`7354981` on `claude/new-session-39ui0r`, and its provider lives at
`api/connectors/mastercard_vi/`.

`git diff 7354981..85932ed` therefore shows the scratch line **deleting**
the entire Phase-5 connector — 795 lines of provider, plus `scope`,
`keys`, `binding`, `credential`, `profile`, `reference`, the integration
profile document, and 1,974 lines of Phase-5 tests — and substituting a
thinner re-implementation. Cherry-picking any of its five commits would
destroy Phase 5. Everything below is ported **semantically**: read,
understood, rewritten against the real connector.

## DISCARD

| Scratch artefact | Why |
|---|---|
| `api/authority_providers/verifiable_intent/{provider,scope,trust,__init__}.py` | Duplicate provider. `api/connectors/mastercard_vi/` is normative. |
| Its `jwk_thumbprint`, issuer trust store, scope mapper | All exist in Phase 5 (`keys.py`, `scope.py`), better specified. |
| Its L2-only authority window (`not_before`/`not_after` from L2 `iat`/`exp`) | Phase 5 requires `max(L1.iat, L2.iat)` … `min(L1.exp, L2.exp)`. The scratch rule grants authority past L1 expiry. |
| `authority_binding_for` + `AUTHORITY_BINDING_METADATA_KEY` in `authority_service.py` | Phase 5 already ships `_principal_binding_for` + `authority_principal_binding`, namespaced per connector. |
| `vi-proof` extra in `pyproject.toml` | Phase 5 ships `mastercard-vi`, deliberately outside `dev` so `pip-audit --strict` keeps working. |
| Scratch CI install step | Phase 5 already installs `.[mastercard-vi]` as its own step. |
| L3-carrying fixture, `l2_payment` selective presentation, `build_payment_fulfilment` | Phase 5 **refuses** Layer 3 outright. Presenting one would imply a verification Inntris did not perform. |
| Its `vi.`-prefixed unsupported-constraint scope keys | Phase 5 fails closed inside the mapper with typed `AuthorityVerificationFailure` codes. |
| All seven scratch evidence JSON files | Regenerated on the correct base. |

## KEEP — port semantically

| Scratch artefact | Disposition |
|---|---|
| `scripts/mastercard_vi/journal.py` | Port near-verbatim. Durable SQLite execution journal; no Phase-5 coupling. |
| `scripts/mastercard_vi/executor.py` | Port with adaptation. Mock executor, crash switches, outcome-write-failure path. |
| `scripts/mastercard_vi/harness.py` | Rewrite. Must construct the Phase-5 provider, Phase-5 binding/keyset shapes, and the `authority_principal_binding` metadata key. |
| `scripts/mastercard_vi/fixture.py` | Rewrite. L1+L2 only, Phase-5 profile VCTs, Phase-5 deterministic key/salt technique. |
| `scripts/mastercard_vi/evidence.py` | Port with adaptation. Pin read from `connectors.mastercard_vi.profile`; checks-performed from `resolve_detailed`. |
| `scripts/mastercard_vi/cases.py` | Port structure; re-resolution before consume added. |
| `scripts/mastercard_vi_proof.py` | Port with adaptation. |
| `tests/test_mastercard_vi_proof.py` | Port with adaptation. |
| `tests/test_mastercard_vi_acceptance.py` | Port cases 8–22; drop anything testing the duplicate provider. |
| `docs/proofs/mastercard-vi/{README,architecture,HANDOFF}.md` | Rewrite against the real connector. |

## REASSESS — reproduce before porting

Neither fix is carried over on trust. Each is reproduced on `7354981`
with a failing regression test first, or dropped.

1. `_AgentView` handing raw JSONB text to the policy snapshot builder.
2. A pre-domain-policy BLOCK persisting a null `policy_hash`.

## NEW — gap visible only on the correct base

Phase 5's `scope.py` emits `allowed_payees`, and
`PaymentDomainPolicy._check_payee_binding` returns
`AUTHORITY_SCOPE_UNSUPPORTED` when no `PayeeBindingResolver` is
configured. Phase 5's own integration tests construct
`PaymentDomainPolicy` **directly** with one; `AuthorityEvaluationService`
never passes one. To be reproduced and reported like the two above.
