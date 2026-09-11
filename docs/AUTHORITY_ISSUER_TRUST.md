# Delegated-authority issuer trust

Phase 7A, Gate 3. How Core decides that an external delegation is real, whose
it is, and whether it is still live.

## The four questions

A presented delegation is worthless until all four are answered from state a
caller cannot write:

| Question | Answered from |
|---|---|
| Did this issuer really sign it? | `INNTRIS_AUTHORITY_TRUST*` configuration (`api/trust/issuer_registry.py`) |
| Is it still live? | `authority_trust_revocations` (migration 0024) |
| Whose is it? | `authority_principal_bindings` (migration 0025) |
| What does it permit? | The signed scope, narrowed by organisation policy |

## No network key discovery

Issuer keys come from configuration and nowhere else. There is no online
discovery client, and this build makes no claim that any card scheme or issuer
operates a key-discovery endpoint for this purpose.

This is worth stating plainly because it answers several release questions at
once: there is no key cache, so no cache-poisoning or staleness to reason
about; there is no refresh interval, because trust material changes only when
a deployment changes it; and no network outage can change a verification
answer, because no answer depends on the network.

The one live dependency is revocation, which is a database read on the same
connection the request already needs, and it **fails closed**: if Core cannot
establish that an issuer, key or delegation is still live, no new delegated
authority is accepted.

## Configuring trust

Set exactly one of:

* `INNTRIS_AUTHORITY_TRUST_FILE` — path to a JSON file;
* `INNTRIS_AUTHORITY_TRUST` — the same JSON inline.

Setting both is refused, as is a malformed document: a deployment with broken
trust configuration must fail to start rather than come up quietly trusting
nobody and refusing traffic it should serve. **No configuration at all** is a
different and valid state — no issuer is trusted, so every presented
delegation blocks with `authority_provider_unavailable`.

```json
{
  "version": 1,
  "issuers": [
    {
      "issuer_id": "acme-issuer",
      "display_name": "ACME Delegated Authority",
      "status": "active",
      "keys": [
        {
          "key_id": "acme-2026-01",
          "public_key": "<64 hex chars, or base64, of the raw Ed25519 public key>",
          "fingerprint": "<sha256 of the raw public key; checked against the key>",
          "status": "active",
          "not_after": "2027-01-01T00:00:00Z"
        }
      ],
      "principal_claim_bindings": {
        "account_reference": "issuer_account_reference"
      },
      "expresses_delegate_binding": false,
      "scope_field_mapping": {
        "spend_ceiling": "max_amount",
        "denomination": "currency",
        "payees": "allowed_payees"
      }
    }
  ]
}
```

Four things this file will refuse:

* **Anything shaped like a private key.** Keys named `private_key`, `secret`,
  `seed`, `signing_key`, JWK `d`/`k`, or any PEM private block at any depth.
  Core verifies issuer signatures and never produces one, so it has no
  legitimate use for issuer private material. A config that tolerated a leaked
  secret would train people to leave it there.
* **A fingerprint that disagrees with its own key.** The fingerprint is what an
  operator reads aloud during a rotation; if the two disagree, one is wrong and
  there is no way to tell which.
* **An issuer with no `principal_claim_bindings`.** Its delegations could not
  be tied to any particular principal, so they would fit every principal in the
  organisation.
* **`expresses_delegate_binding` without `delegate_binding_key`**, or the
  reverse.

`scope_field_mapping` translates the issuer's field names into the neutral keys
the payment domain enforces (`max_amount`, `currency`, `allowed_payees`,
`not_before`, `not_after`). An issuer field with no mapping is carried through
under its own name, which makes it an *unsupported constraint* downstream and
blocks the payment. Dropping it instead would silently broaden what the issuer
granted.

## Key rotation

Rotation is additive, then subtractive, and the two steps are separated by
however long the issuer's in-flight delegations live.

1. **Publish and configure the new key alongside the old one**, both `active`.
   Deploy. Both keys now verify, so delegations signed either side of the
   issuer's own cutover are accepted.
2. **Confirm the issuer has cut over** — new delegations arrive signed by the
   new key.
3. **Mark the old key `retired`.** Deploy. A retired key can no longer
   authenticate *new* authority. This is deliberately not `revoked`: what it
   signed while active was legitimate and stays verifiable for audit.
4. Record both fingerprints in the release evidence.

Setting `not_after` on a key achieves step 3 on a schedule instead of a deploy.
The key stops authenticating new authority at that instant.

## Revocation and disabling

Configuration is reviewed and deployed; that is right for trust and far too
slow for distrust. When a key is compromised at 03:00 the answer must change in
seconds. So **trust is configured and distrust is data**: a row in
`authority_trust_revocations` overrides configuration and is never overridden
by it.

```bash
# Distrust one signing key, immediately
python -m scripts.authority_control revoke \
    --subject issuer_key --issuer acme-issuer --id <fingerprint> \
    --by alice@example.com --approval INC-2026-0009 \
    --reason "issuer disclosed key compromise"

# Distrust everything an issuer ever signed
python -m scripts.authority_control revoke \
    --subject issuer --id acme-issuer \
    --by alice@example.com --approval INC-2026-0010 --reason "issuer breach"

# Distrust one customer's delegation
python -m scripts.authority_control revoke \
    --subject authority_reference --issuer acme-issuer --id <their reference> \
    --by alice@example.com --approval INC-2026-0011 \
    --reason "customer reported compromise"

# Undo a revocation made in error
python -m scripts.authority_control reinstate \
    --subject issuer_key --issuer acme-issuer --id <fingerprint> \
    --by alice@example.com --approval INC-2026-0012 --reason "false alarm"
```

Revocation applies to **new** resolutions. Authority already issued keeps its
own lifecycle (migration 0019): revoking a key does not strand an executor
that is mid-flight on a grant issued while the key was good. To stop issuance
altogether while an incident is being assessed, pull the issuance kill switch
as well:

```bash
python -m scripts.authority_control kill \
    --control authority_issuance --global \
    --by alice@example.com --approval INC-2026-0013 --reason "issuer breach"
```

Revocations are scoped per issuer. The same fingerprint configured for two
issuers is two subjects, and revoking one does not distrust the other.

## Principal binding — and why not `agents.metadata`

A verified delegation says "the holder of account X may spend up to Y". Core
has to know whether the agent in front of it *is* account X.

The obvious place for that was the agent's metadata. It is not usable, and the
reason is recorded here so nobody moves it there later: both
`POST /agents/register` and the public registration route copy caller-supplied
metadata onto the agent, minus a lifecycle blocklist. A caller can therefore
choose their own agent's metadata. If the binding lived there, an attacker
could register an agent declaring somebody else's issuer account reference,
present that account's genuine delegation, and have everything verify — real
signature, real delegation, and the only thing tying it to a principal written
by the attacker.

`authority_principal_bindings` is written by the system role through an
administrative path that records an actor and an approval reference, and is
never written from a registration request.

```bash
python -m scripts.authority_control bind \
    --org <uuid> --agent <uuid> --issuer acme-issuer \
    --key issuer_account_reference --value acct_1234 \
    --by alice@example.com --approval CHG-2026-0043 \
    --reason "canary principal provisioning"
```

A principal with no binding at an issuer cannot use *any* of that issuer's
delegations, however genuine. That is the intended default.

## Bounds on what a caller can make Core do

`api/trust/artefact.py` applies every bound before interpreting anything:

| Bound | Default |
|---|---|
| Total artefact size | 16 KiB |
| JSON nesting depth | 8 |
| Object keys anywhere | 256 |
| Longest string | 2048 |
| Longest array | 64 |
| Parse + verify budget | 2 s, on a monotonic clock |

Also refused: duplicate JSON keys (parsers disagree about which wins, and a
payload whose meaning depends on that must not reach a policy decision);
floating-point numbers (they do not round-trip identically through every
producer's canonicalisation, and money must never be one); an unknown format
identifier; and any signature algorithm other than Ed25519 — accepting an
algorithm name and then not checking it is worse than refusing it.

The signature covers the RFC 8785 canonical form of the payload, so re-ordered
keys, different number formatting and added whitespace all verify identically,
and anything that canonicalises differently is a different payload.

## Order of checks

Cheapest first, each narrowing what follows, so a hostile caller cannot make
Core do expensive work with rubbish:

1. parse under bounds;
2. issuer configured and enabled;
3. signing key known, active, in date;
4. **revocation** — before the signature, so a revoked key is never verified;
5. signature;
6. validity window;
7. principal binding;
8. delegate binding, where the issuer expresses one;
9. scope translation.

Every failure is returned as a non-verified resolution with a typed reason, so
the decision blocks with a truthful explanation. Only two things raise: a
caller handing over something structurally impossible, and an inability to
establish revocation state — which is not a verdict about the artefact and
must not be recorded as one.

## What a VERIFIED resolution does not mean

It means this issuer signed this delegation, it is in date, nobody revoked it,
and it names this principal. It does **not** mean the act is permitted.
Organisation policy still decides, and a delegated scope can only narrow what
policy already allows — never widen a limit, re-enable a blocked action, or
authorise a destination the organisation refuses.
