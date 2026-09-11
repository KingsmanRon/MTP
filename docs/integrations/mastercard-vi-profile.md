# Verifiable Intent — Inntris integration profile

Inntris consumes Verifiable Intent (VI) as **one authority provider**: a
source of evidence about what a user delegated to an agent. It is never a
source of permission. Every act still passes the organisation's own policy
afterwards, and that policy can block an act whose VI chain verified
perfectly.

Status: proof implementation, not deployed. No Mastercard partnership,
certification, endorsement or conformance is claimed or implied.

---

## 1. Normative source, pinned

| | |
| --- | --- |
| Project site | <https://verifiableintent.dev/> |
| Repository | <https://github.com/agent-intent/verifiable-intent> |
| **Pinned commit** | `356c29635f1c44df7de02edb58699ca9f29bece6` |
| Commit date | 2026-04-20 |
| Python package version | `verifiable-intent` **0.1.0** (no PyPI release; installed from the pinned commit) |
| Spec revision observed | **0.1-draft**, dated 2026-02-18 |
| Documents read | `spec/README.md`, `spec/credential-format.md`, `spec/constraints.md`, `spec/security-model.md` |

VI is a draft, so "the specification" is a moving repository rather than a
fixed document. The commit above is recorded in three places that must
agree, and a test asserts it:

* `api/connectors/mastercard_vi/profile.py` — the runtime constants;
* `tests/fixtures/mastercard_vi/upstream_pin.json` — the recorded pin;
* `pyproject.toml` — the dependency, pinned to that commit and never to a
  branch.

The connector refuses to verify anything if the installed package version
is not the pinned one. Nothing floats against `main`.

### How it is installed

```
pip install -e '.[mastercard-vi]'
```

It is a **separate extra**, deliberately not folded into `[dev]`. The
project has no PyPI release, so it can only be a URL requirement — and
`pip freeze` emits URL requirements without a version, which
`pip-audit --strict` refuses outright ("URL requirements cannot be pinned
to a specific package version"). Putting it in `[dev]` therefore breaks
the SCA gate, and the alternative — filtering it out of the audited
requirement set — would quietly shrink what that gate covers for every
other dependency too.

So the CI Python job installs this extra as its own step, and the SCA job
keeps auditing exactly the dependency set it can audit. It follows that
pip-audit does not cover this package: nothing can, since there is no
advisory source for an unpublished project. It is a test-only dependency,
absent from `requirements.txt` and from the runtime `dependencies`, so it
never reaches a deployed image.

Because the package is an optional extra, its tests would otherwise
*skip* when it is missing. A skip in CI would mean the install step
silently did not run while the connector's entire test surface vanished,
so both test modules fail loudly rather than skip when `CI` is set.

Every field in this document is **VERIFIED** against the cited draft
unless it is explicitly marked **ASSUMED**, which is reserved for
integration decisions Inntris makes that VI does not specify.

---

## 2. What Inntris accepts

| Layer | Accepted | Notes |
| --- | --- | --- |
| L1 — issuer SD-JWT (`sd+jwt`) | yes | ES256, verified against a trusted issuer key |
| L2 — user KB-SD-JWT+KB (`kb-sd-jwt+kb`), autonomous mode | yes | the delegation itself |
| L2 — user KB-SD-JWT (`kb-sd-jwt`), immediate mode | **no** | confirms final values, delegates to no agent |
| L3a / L3b — agent KB-SD-JWT | **no** | see §8 |

Credential types (credential-format.md §10):

* L1 `vct`: `https://credentials.mastercard.com/card` (the Mastercard
  reference profile; configurable per deployment)
* L2 checkout `vct`: `mandate.checkout.open.1`
* L2 payment `vct`: `mandate.payment.open.1`

### Presentation shape

The caller presents the material on a `DelegatedAuthorityClaim`:

```json
{
  "issuer": "https://issuer.mastercard.com",
  "external_reference_id": "<conditional_transaction_id>",
  "evidence": {
    "layer1": "<serialized L1 SD-JWT>",
    "layer2": "<serialized L2 SD-JWT>"
  }
}
```

`external_reference_id` is the VI mandate-pair identifier — the
`conditional_transaction_id` of the payment mandate's
`mandate.payment.reference` constraint (credential-format.md §8.1). The
connector derives the same value from the credential and refuses the claim
if the two disagree, so the durable decision record always names the exact
delegation it was made under. Any other evidence key, and any key naming
Layer 3, is rejected rather than ignored.

---

## 3. Verification checklist

Performed in order, fail-closed at every step.

| # | Check | Performed by |
| --- | --- | --- |
| 1 | evidence shape, size bound, no Layer 3 | Inntris |
| 2 | L1 issuer is trusted and a key resolves for its `kid` | Inntris |
| 3 | L1 ES256 signature under that key | reference impl |
| 4 | L1 header `alg`/`typ`, `vct`, `_sd_alg` | reference impl |
| 5 | L1 `exp` / `iat` within 300s clock skew | reference impl |
| 6 | L2 ES256 signature under the user key from L1 `cnf.jwk` | reference impl |
| 7 | L2 `sd_hash` == `B64U(SHA-256(ASCII(serialized L1)))` | reference impl |
| 8 | L2 `exp` / `iat` within 300s clock skew | reference impl |
| 9 | L2 `aud` equals this principal's provisioned audience | both |
| 10 | L1 `iat`/`exp`, L2 `iat`/`exp`/`nonce` are **present** | Inntris (see §9) |
| 11 | autonomous mode: L2 `typ` is `kb-sd-jwt+kb`, both mandate VCTs are the open ones | both |
| 12 | exactly one mandate pair, both mandates disclosed | Inntris |
| 13 | `mandate.payment.reference.conditional_transaction_id` hashes to the checkout disclosure | reference impl |
| 14 | agent `cnf.jwk` identical across the pair, `cnf.jwk.kid` consistent | reference impl |
| 15 | agent key thumbprint bound to this Inntris principal, not revoked | Inntris |
| 16 | claim reference equals the derived mandate-pair reference | Inntris |
| 17 | the two validity windows overlap; the effective window is their intersection | Inntris |
| 18 | every machine-enforceable payment constraint maps, or refuse | Inntris |

`skip_issuer_verification=True` is never used and is not reachable from
this connector.

### Typed failure codes

Every refusal is data, never an exception. The codes are
`AuthorityVerificationFailure` values, which the payment domain already
maps onto `DecisionReason`:

| Situation | Code |
| --- | --- |
| no claim presented | `authority_not_found` |
| malformed material, Layer 3 presented, immediate mode, missing required claim, claim/credential issuer disagreement | `authority_artefact_invalid` |
| no trusted issuer key, or the L1 signature does not verify | `authority_signature_invalid` |
| `sd_hash`, pairing or reference-binding mismatch; wrong claim reference | `authority_digest_mismatch` |
| L2 dated beyond the skew tolerance | `authority_not_yet_valid` |
| L1 or L2 expired, or their windows do not overlap | `authority_expired` |
| no binding provisioned for the principal | `authority_principal_mismatch` |
| wrong audience, or an agent key not bound to this principal | `authority_delegate_not_bound` |
| the bound agent key has been revoked | `authority_revoked` |
| unsupported or undisclosed constraint, multi-pair L2, partial disclosure of the pair | `authority_scope_unreadable` |
| the pinned reference implementation cannot be loaded | `authority_provider_unavailable` |

---

## 4. Issuer-key resolution

`IssuerKeyResolver` is an interface. The shipped implementation,
`StaticIssuerKeyResolver`, is offline: it serves keys provisioned out of
band as `{issuer: {kid: jwk}}`, and it performs no network I/O, so a
verification result never depends on whether an issuer's JWKS endpoint
happened to be reachable.

* a `kid` that resolves to nothing, an unknown issuer, or a `kid` omitted
  from the L1 header all resolve to **no key**, and no key means no
  verification;
* revocation is expressed on the key's RFC 7638 thumbprint, not on its
  `kid`, so a stale label cannot resurrect a retired key;
* keysets are validated when they are provisioned, so a malformed key
  fails at configuration time rather than at the first verification.

Production key discovery — JWKS fetch, caching, rotation polling — is
**not implemented** and remains Phase 7A. Nothing in the pinned draft
makes a local implementation necessary for the checks above.

---

## 5. Principal / delegate binding

A VI chain that verifies proves that *some* user delegated to *some* agent
key. It says nothing about whether that agent is the authenticated Inntris
principal. Inntris therefore requires an explicit trusted binding on two
dimensions:

| Dimension | Source in the credential | Bound against |
| --- | --- | --- |
| audience | L2 `aud` (credential-format.md §4.3) | `expected_audience` |
| delegate key | RFC 7638 thumbprint of the mandates' `cnf.jwk` | `agent_key_thumbprints` |

`cnf.jwk.kid` may additionally be checked against `agent_key_ids`, but only
as a **secondary consistency check**. A `kid` is a label chosen by whoever
wrote the credential; it is not globally unique and matching one proves
nothing. Identity is always the thumbprint or a signature.

Inntris principals sign requests with **Ed25519**; VI agents sign with
**ES256 over P-256**. These are different credentials for the same actor
and nothing here compares one to the other — the link is an
operator-provisioned fact, and it is the only link accepted.

Bindings reach the provider through either:

* `ExecutionContext.principal_binding["mastercard_vi"]`, assembled
  server-side from agent metadata under the key
  `authority_principal_binding` (**ASSUMED** — the metadata key and shape
  are an Inntris integration decision, not a VI concept); or
* an injected `PrincipalDelegateBindingResolver`.

A context that carries the key but cannot be read fails closed rather than
falling through to the resolver.

**Rotation and revocation.** `agent_key_thumbprints` may hold several
values so a replacement key can be provisioned before the old one is
retired. A thumbprint in `revoked_agent_key_thumbprints` is refused even if
it is also still listed as active — a revocation that could be cancelled by
forgetting to remove the old entry is not a revocation. An empty active set
cannot be provisioned at all.

---

## 5a. Effective chain validity

Delegated authority exists only while **every** credential it rests on is
current, so the effective window is the *intersection* of the layers' own
windows — never Layer 2's alone:

```
not_before = max(L1.iat, L2.iat)
not_after  = min(L1.exp, L2.exp)
```

Worked example. A mandate valid until 11:00 resting on an issuer
credential that expires at 10:05 delegates nothing after 10:05.
Verification at 10:00 succeeds; the authority, and every grant clamped
against it, still ends at **10:05**.

These exact values are used consistently for:

* `DelegatedAuthorityReference.not_before` / `.not_after`
* `ResolvedAuthority.not_before` / `.not_after`
* the `not_before` / `not_after` keys in the mapped scope, and therefore
  `PaymentDelegationConstraints.not_before` / `.not_after`
* `clamp_grant_expiry(authority_expires_at=…)` on the issuance path, which
  takes a minimum — so a grant can never outlive the tighter of the two
  credentials, whatever the TTL ceiling allows

**No clock skew is added.** Skew (300s, per the draft's recommendation) is
a tolerance for *reading* a timestamp during verification. Letting it
reach the authority window would turn a tolerance for clock drift into
extra real authority, so the two deliberately disagree: the reference
verifier may accept a credential that expired 60 seconds ago, and the
authority it yields is already outside its own validity, which the payment
domain blocks with `AUTHORITY_EXPIRED`.

**An empty or inverted intersection fails closed** with
`authority_expired`. This is reachable even when both layers pass
verification — Layer 1 expiring in 60 seconds while Layer 2 is dated 120
seconds ahead sits inside the skew tolerance at both ends, yet yields a
window that never opens. It is implemented in
`effective_chain_validity()` and covered by
`tests/test_mastercard_vi_provider.py::TestEffectiveChainValidity`.

---

## 6. Scope mapping

The connector emits only the vendor-neutral scope keys the payment domain
already understands (`api/domains/payment/delegation.py`). No VI or
Mastercard identifier, type name or field name reaches
`api/core/authority/` or `api/domains/payment/`; a test asserts it.

### Supported constraint types

| VI constraint | Fields read | Inntris scope key |
| --- | --- | --- |
| `mandate.payment.amount_range` | `currency`, `max` | `currency`, `max_amount` |
| `mandate.payment.allowed_payees` | `allowed` (disclosed entries) | `allowed_payees` |
| — | L2 `iat` | `not_before` |
| — | L2 `exp` | `not_after` |

`mandate.payment.reference` is **structural**: the pinned reference
implementation verifies it in `verify_l2_reference_binding` and explicitly
excludes it from constraint checking (constraints.md §4.8). It bounds
nothing about the act, so it maps to nothing.

### Amounts

VI expresses amounts as integer minor units per ISO 4217 (constraints.md
§4.4). Inntris's canonical money type is built from an exact major-unit
decimal. The conversion happens **once**, in
`minor_units_to_major_string`, by digit placement rather than float or
decimal-context arithmetic — so `2000000` becomes exactly `"20000.00"` and
nothing can be quietly rounded by a precision setting.

`amount_range` is a **per-transaction bound**. It is not a cumulative
budget and Inntris does not treat it as one: two separate acts of the
maximum each are both within it, exactly as the draft says
(constraints.md §4.4, "Per-transaction scope").

Only currencies in `SUPPORTED_CURRENCIES` (USD today) can be enforced. Any
other currency fails closed rather than being read as "no limit".

### Payees

Each **disclosed** payee becomes one neutral reference:

* `payee:id:<id>` when the payee object carries an `id`;
* `payee:name-website:<name>|<website>` otherwise, with `\` and `|`
  escaped so a separator inside a merchant name cannot collapse two payees
  into one reference.

This mirrors the draft's own matching rule (constraints.md §4.3): `id` is
the primary key, and the `name` + `website` pair is the human-anchored
identity the user actually approved. All comparisons are exact — the draft
forbids substring and case-insensitive payee matching (§7.3), and nothing
here trims, lowercases or normalises what the user signed.

A payee reference is an **identity, not a destination**. See §7.

---

## 7. Payee → execution destination

A delegated payee identity is not proof that a particular account belongs
to that payee. The mapped `allowed_payees` references are resolved by the
Phase 2 `PayeeBindingResolver` into a concrete `ExecutionDestination`
(network, account, asset) from trusted server-side state, and the proposed
act must match that destination on all three dimensions. A payee with no
binding, or a destination that does not match, fails closed.

So the full path is:

```
VI payee object  ->  neutral payee reference  ->  trusted payee binding
                 ->  ExecutionDestination(network, account, asset)
                 ->  compared against the act the executor would perform
```

Nothing in the middle of that chain is taken from the request.

---

## 8. Selective disclosure posture

VI lets a holder withhold individual merchant, payee and item disclosures.
The reference implementation's posture is to **skip** an allowlist it
cannot see (constraints.md §4.3 step 3). Inntris is an authority issuer, so
skipping is not available to it:

| Situation | Inntris |
| --- | --- |
| both mandates disclosed, all payees disclosed | enforce the full allowlist |
| both mandates disclosed, **some** payees disclosed | enforce only the disclosed subset — strictly narrower than what was delegated |
| both mandates disclosed, **no** payees disclosed | **fail closed**: nothing can be shown to satisfy the allowlist |
| one mandate withheld | **fail closed**: the pair cannot be verified |
| more than one mandate pair | **fail closed**: Inntris cannot tell which pair a proposed act falls under |

This is deliberately more conservative than the draft requires of a
general verifier, and it is the correct posture for something that issues
execution authority rather than merely validating a presentation.

---

## 9. Recorded divergences from the reference implementation

Where the normative documents and the reference code disagree, the
normative security requirement wins. Each divergence is recorded rather
than absorbed.

**1. Required claims the reference implementation tolerates the absence of.**
credential-format.md §3.3 and §4.3 mark L1 `iat`/`exp` and L2
`iat`/`exp`/`nonce` REQUIRED. `verify_chain` treats an absent `exp` or
`iat` as "no constraint" (`_is_expired(None, …)` returns `None`). Inntris
requires them and refuses a credential without a validity window with
`authority_artefact_invalid`. Direction: Inntris is stricter.

**2. Payee matching under mixed identification.** The draft's matcher falls
back to `name` + `website` whenever *either* side lacks an `id`. Inntris
keys each side independently, so an allowlist entry with an `id` does not
match a proposed payee without one, even when the name and website agree.
Direction: Inntris is stricter — a differential test asserts that Inntris
**never accepts a payee the reference checker rejects**, across the whole
allowlist/candidate matrix.

**3. Positive `min` on an amount range.** The reference checker enforces a
lower bound; Inntris's neutral scope has nowhere to carry one. Rather than
enforce the ceiling and drop the floor — half a constraint is broader than
the constraint — Inntris refuses the delegation with
`authority_scope_unreadable`.

**4. Repeated constraints of one mapped type.** The draft permits several
constraints of the same type, each validated independently. Combining two
into one neutral scope would mean inventing an intersection rule the draft
does not define, so Inntris refuses instead of guessing.

Failure-reason classification of reference-implementation error strings is
substring-based and therefore brittle. Nothing security-relevant rests on
it: every classified case is already a refusal, an unmatched message falls
through to `authority_artefact_invalid`, and the checks whose reason
matters most are additionally performed by Inntris itself. An upstream
drift degrades the *reason* recorded, never the outcome.

---

## 10. Deliberately not implemented

| | Why |
| --- | --- |
| **L3 verification** (L3a payment, L3b checkout) | Inntris decides *before* an act; Layer 3 is the agent's record of an act already committed to a network and a merchant, so at evaluation time none exists. Presented Layer 3 material is **refused**, not ignored, so no reading of the output can suggest Inntris verified a completed VI transaction. |
| Completed-transaction / final-action verification | follows from the above |
| `mandate.payment.budget` | needs a per-mandate cumulative spend ledger this release does not keep — fails closed |
| `mandate.payment.recurrence`, `mandate.payment.agent_recurrence` | need occurrence accounting this release does not keep — fail closed |
| `mandate.checkout.allowed_merchants`, `mandate.checkout.line_items` | these bound the agent's *merchant checkout*, which Inntris neither performs nor issues authority for. The checkout mandate is still verified in full for chain integrity, pairing and delegate identity, and the constraint types are recorded on the mapping result; what Inntris will not do is issue authority for the checkout leg and imply it checked it. An **unregistered** constraint type in either mandate still fails closed, because the draft requires open mandates to reject those (constraints.md §5.4). |
| Multi-pair L2 credentials | supported by the draft; Inntris cannot tell which pair a proposed act falls under, so it fails closed |
| Production issuer-key discovery (JWKS fetch, caching, rotation polling) | Phase 7A |
| Mastercard Agent Pay network or API calls | out of scope |
| AP4M execution, settlement, any real executor | out of scope |
| A second authority provider | out of scope |

### Delegation reuse

Every Inntris grant is single-use. That does **not** make a VI mandate
single-use, and the draft does not say it is, so the connector is stateless
and does not refuse a second resolution of the same mandate. What it does
instead:

* records the stable mandate-pair reference on every resolution, so the
  durable decision record always names which delegation it was made under;
* treats `amount_range` as a per-transaction bound, never a running total;
* fails closed on any constraint that would make usage accounting
  necessary.

Issuance idempotency at the Inntris layer still prevents duplicate grants
from the same evaluation request. No "one grant ever per L2" rule is
invented.

---

## 11. Invariants

* zero organisation-policy decisions in the connector;
* a valid VI chain never by itself produces an Inntris `ALLOW`;
* current Inntris policy can still block a VI-valid act;
* no Mastercard or VI identifier or type name reaches
  `api/core/authority/` or `api/domains/payment/`;
* wrong issuer, wrong audience, wrong delegate, expiry, insufficient
  disclosure and an unsupported required constraint all fail closed;
* expected denial is data — the provider does not raise on a credential
  that fails to verify;
* no claim of Mastercard partnership, certification, endorsement or
  conformance.

---

## 12. Where the code is

| | |
| --- | --- |
| Connector | `api/connectors/mastercard_vi/` |
| Pinned upstream metadata | `api/connectors/mastercard_vi/profile.py` |
| Reference-implementation loader | `api/connectors/mastercard_vi/reference.py` |
| Issuer keys and thumbprints | `api/connectors/mastercard_vi/keys.py` |
| Principal / delegate binding | `api/connectors/mastercard_vi/binding.py` |
| Presented credential material | `api/connectors/mastercard_vi/credential.py` |
| Scope mapping | `api/connectors/mastercard_vi/scope.py` |
| The provider | `api/connectors/mastercard_vi/provider.py` |
| Provider + adversarial tests | `tests/test_mastercard_vi_provider.py` |
| Differential + mapping tests | `tests/test_mastercard_vi_scope_mapping.py` |
| Recorded pin | `tests/fixtures/mastercard_vi/upstream_pin.json` |
| Adversarial catalogue | `tests/fixtures/mastercard_vi/cases.json` |
| Golden scope mapping | `tests/fixtures/mastercard_vi/golden_scope.json` |

---

## 13. Phase 6 handoff — what must be proved next

Phase 5 stops at **issuance**. It establishes that a delegation verified at
the moment a grant was issued. That is explicitly *not* enough to spend
one, and Phase 6 must prove the rest:

1. **Current delegated authority is revalidated before the first
   consumption.** Verification at issuance time says what was true then.
   A mandate can be revoked, or reach the effective `not_after` of §5a,
   between issuance and execution.
2. **No delegated grant may consume merely because issuance-time
   verification succeeded.** Re-presenting the issuance-time conclusion is
   not revalidation.
3. **The existing `AUTHORITY_UNVERIFIED` protection stays fail-closed.**
   `AuthorityStore` already refuses to consume a grant that carries an
   `authority_scope_digest` when no current authority evidence accompanies
   the attempt — absent evidence is not evidence of validity. Phase 6 must
   satisfy that gate with real re-resolution, never bypass, relax or stub
   it. The adjacent checks it must also keep honouring: revoked evidence →
   `AUTHORITY_REVOKED`; evidence past its expiry, or a grant past
   `authority_expires_at` → `AUTHORITY_EXPIRED`; unverified evidence →
   `AUTHORITY_VERIFICATION_FAILED`; evidence whose scope digest is not the
   one the grant was issued under → `AUTHORITY_SCOPE_EXCEEDED`.

The end-to-end path Phase 6 owns is
`provider -> policy -> grant -> current delegated-authority revalidation ->
consume`.

### Deferred to Phase 7A (release gate)

Production provider *composition* is deliberately absent from Phase 5 and
remains a Phase 7A gate:

* production packaging and deployment of the connector;
* live JWKS discovery, caching and rotation polling (§4 ships an offline
  resolver and an interface only);
* the provider factory and its runtime configuration/wiring;
* issuer and delegate key lifecycle management.

Nothing in Phase 5 is wired into a deployed path, and no public endpoint
was added.

---

## 14. Handoff

| | |
| --- | --- |
| Upstream commit pinned | `356c29635f1c44df7de02edb58699ca9f29bece6` |
| Draft / package version observed | 0.1-draft (2026-02-18) / `verifiable-intent` 0.1.0 |
| Verification functions used | `verify_chain`, `verify_l2_reference_binding` (via `verify_chain`), `decode_sd_jwt`, `resolve_disclosures`, `hash_disclosure`; `check_constraints` in the differential tests only |
| Issuer-key strategy | `IssuerKeyResolver` interface; offline `StaticIssuerKeyResolver` over provisioned keysets; fail closed when no key resolves. Network discovery deferred to Phase 7A |
| Principal / delegate binding | expected L2 `aud` + RFC 7638 thumbprint of the mandates' `cnf.jwk`, from `ExecutionContext.principal_binding["mastercard_vi"]` (agent metadata key `authority_principal_binding`) or an injected `PrincipalDelegateBindingResolver`. `kid` is a secondary check only |
| Supported constraint types | `mandate.payment.amount_range`, `mandate.payment.allowed_payees` (+ `mandate.payment.reference` verified structurally) |
| Unsupported-constraint behaviour | fail closed with `authority_scope_unreadable`; nothing is silently ignored |
| Selective-disclosure behaviour | partial payee disclosure narrows; zero disclosed payees, a withheld mandate, or a multi-pair L2 fail closed |
| Fixture paths | `tests/fixtures/mastercard_vi/{upstream_pin,cases,golden_scope}.json`; credentials are minted deterministically by the builder in `tests/test_mastercard_vi_provider.py` |
| Effective validity rule | `not_before = max(L1.iat, L2.iat)`, `not_after = min(L1.exp, L2.exp)`, no clock skew added; empty intersection fails closed — see §5a |
| Typed authority failure codes | see §3 |
| Not implemented | L3 verification, budget/recurrence accounting, Agent Pay APIs, AP4M, settlement, production key discovery — see §10 |
