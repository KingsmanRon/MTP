# Inntris Security Overview

**Last reviewed:** June 8, 2026
**Purpose:** Buyer-facing security and data-handling summary
**Status:** Describes repository-backed controls. Production settings require
environment-specific verification.

## Product Boundary

Inntris evaluates a proposed AI agent action before execution and returns a
PASS, BLOCK, or ESCALATE decision. It then records the decision and produces a
verifiable receipt.

Inntris is a real enforcement control only when the customer places it in the
mandatory execution path. If an agent can bypass Inntris and call the protected
system directly, Inntris can record covered actions but cannot prevent bypassed
actions.

## What A Receipt Proves

For a covered action, a receipt can provide evidence of:

- which registered agent key signed the action envelope;
- which action type and payload hash were evaluated;
- whether the configured policy allowed or blocked the request;
- which policy hash was bound to a policy-evaluated receipt;
- whether the receipt fingerprint still matches its canonical fields; and
- whether the receipt was included in a Merkle root anchored on Base L2.

## What A Receipt Does Not Prove

A receipt does not independently prove:

- that an agent had no alternative path around Inntris;
- that the action payload was factually correct or morally safe;
- that a downstream system executed an approved action exactly as requested;
- that a trust score alone makes an irreversible action safe;
- that the customer's private key was never compromised; or
- compliance with a law, framework, or certification by itself.

## Core Controls

| Control | Current implementation |
| --- | --- |
| Agent identity | Ed25519 signature verification against a registered public key |
| Replay defense | Per-agent nonce uniqueness in Redis; `/verify` fails closed if nonce verification is unavailable |
| Action policy | Explicit allowlist and blocklist, with block taking precedence |
| Emergency stop | Suspended and revoked agents fail policy evaluation before execution |
| Spend controls | Per-action and daily USD limits |
| Traffic controls | Per-agent verification request limit per minute |
| Approval evidence | Short-lived HMAC approval token for approved actions |
| Audit evidence | Approved and rejected decisions are written to the audit trail |
| Receipt integrity | Canonical fingerprint plus optional policy-hash binding |
| Public anchoring | Merkle roots submitted to Base L2 and independently queryable |
| Admin session | API key held server-side behind an encrypted HTTP-only session cookie |
| Tenant isolation | Organization checks in API handlers; RLS migrations and tests exist, but activation must be verified per deployment |

## Decision Order

Runtime actions are evaluated in this order:

1. Agent status
2. Action allowlist and blocklist
3. Trust-score threshold
4. Timestamp validity
5. Rate limit
6. Spend limits when an amount is present

The first failed check blocks or escalates the action. For irreversible actions,
customers should use explicit permissions, transaction simulation where
applicable, limits, and human approval in addition to advisory reputation or
trust signals.

## Data Handling

### Data Inntris Receives

- Agent identifier
- Action type
- Action-specific payload
- Signature, nonce, timestamp, and optional policy hash
- Request metadata such as IP address and user agent

### Data Stored

- The action payload and its cryptographic hash
- Verification verdict and reason
- Signature validity and audit metadata
- Receipt, Merkle, and on-chain anchor references

Customers should avoid placing unnecessary personal data or secrets in action
payloads. The public verification surface exposes a fixed receipt subset and
does not expose the raw action payload.

### Data Written On-Chain

Inntris writes Merkle roots and batch metadata to Base L2. Raw customer payloads,
personal data, signatures, and secrets are not written on-chain.

## Failure Behavior

- Invalid signatures are blocked and recorded as security events.
- Replayed nonces are blocked.
- `/verify` fails closed when Redis is unavailable for nonce verification.
- Suspended agents are blocked before action execution.
- Explicitly blocked or non-allowlisted action types are blocked.
- Requests above configured spend limits are blocked.
- Requests above the configured rate limit are escalated.
- New receipts can remain in `pending_anchor` until the next anchor batch
  confirms.

## Key Boundaries

- Customer agent private keys remain in the customer-controlled runtime.
- Inntris stores the corresponding public key.
- Organization API keys are stored as hashes in the backend.
- The anchor worker currently reads its signing key from the deployment secret
  environment. KMS or HSM custody is not yet a repository-backed claim.
- Approval tokens are HMAC-signed with a server secret and expire after a short
  window.

## Operations And Response

The repository contains procedures for:

- signature failure and replay incidents;
- anchor-worker and RPC failures;
- contract pause and admin incidents;
- rate-limit storms;
- service-secret and anchor-submitter rotation;
- GDPR and CCPA erasure while preserving proof-of-existence fields; and
- timelock-gated contract administration.

Before a production rollout, Inntris and the customer should agree on incident
owners, escalation channels, retention, backup policy, and the exact protected
execution boundary.

## Known Limitations

- The production deployment must be checked to confirm RLS roles, migrations,
  contract roles, monitoring, backups, and timelock topology are active.
- A customer integration can defeat prevention if it permits direct execution
  without validating the Inntris approval result.
- Service and anchor keys are not yet proven to use KMS or HSM custody.
- Security scanning currently reports findings but some jobs are configured as
  report-only rather than hard release blockers.
- Inntris does not currently claim SOC 2, ISO 27001, or another formal
  certification.

For engineering detail and residual risks, see
[`docs/THREAT_MODEL.md`](../THREAT_MODEL.md).
