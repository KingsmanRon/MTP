# Inntris Trust Pack

**Last reviewed:** June 8, 2026

This directory is the buyer-facing entry point for evaluating Inntris security,
control boundaries, and evidence. It separates three different kinds of claims:

1. **Repository-backed:** implemented and testable from this repository.
2. **Deployment-backed:** requires current production readback before it can be
   claimed for a specific environment.
3. **Roadmap:** not available today and must not be presented as shipped.

Inntris is a policy decision point and evidence system for high-risk AI agent
actions. It is effective only when the protected action is technically unable
to execute without a valid Inntris PASS decision.

## Start Here

| Document | Audience | Purpose |
| --- | --- | --- |
| [Security overview](SECURITY_OVERVIEW.md) | Buyer, security, governance | Plain-language security and data-handling summary |
| [Production readback checklist](PRODUCTION_READBACK_CHECKLIST.md) | Operator, security review | Evidence required before claiming live controls |
| [14-day pilot SOW](../pilot/AGENT_ACTION_PROOF_PILOT_SOW.md) | Buyer, sponsor, procurement | Fixed-scope pilot template |
| [Pilot evidence-pack template](../pilot/PILOT_EVIDENCE_PACK_TEMPLATE.md) | Pilot team, buyer | Repeatable final pilot artifact |
| [Engineering threat model](../THREAT_MODEL.md) | Security engineering | STRIDE analysis with code references and residual risks |
| [Receipt canonicalization](../RECEIPT_CANONICALIZATION.md) | Integrators, auditors | Signing and fingerprint contract |
| [Security policy](../../SECURITY.md) | Security researchers, buyers | Reporting process and response targets |
| [Operations runbooks](../runbooks/README.md) | Operators, security review | Incident response, rotation, timelock, and erasure procedures |

## Evidence Available Now

- Public PASS receipt:
  `https://www.inntris.com/verify/d8dd0902-4750-42d2-9516-92bf6362e815`
- Public BLOCK receipt:
  `https://www.inntris.com/verify/3030c27c-87c4-4464-b4af-605fbe638e0e`
- Public API health:
  `https://api.inntris.com/health`
- Receipt schema:
  `https://api.inntris.com/schema/receipt/v1.json`
- Base mainnet contract:
  `0x0600eA15802c8d2EA429371b2EB0aacCFe321480`

Live URLs and production settings must be read back again immediately before a
buyer review. A repository document is not proof that a production setting is
active.

## Control Status

### Repository-Backed

- Ed25519 verification of signed action envelopes
- Nonce replay protection that fails closed when Redis is unavailable
- Explicit action allowlists and blocklists
- Agent status enforcement, including suspension
- Daily, per-action, and per-minute limits
- HMAC approval tokens for approved actions
- Audit records for approved, blocked, rate-limited, and invalid-signature paths
- Receipt fingerprinting and policy-hash binding
- Merkle batching and Base L2 anchoring
- Public receipt and Merkle proof endpoints
- Incident response, secret rotation, timelock, and GDPR erasure runbooks
- Tenant RLS migrations and integration tests

### Deployment-Backed

Confirm these for each production or customer deployment:

- Runtime database role and RLS activation
- Applied database migration set
- Contract admin, submitter, and pauser role holders
- Whether Safe and timelock administration are active on the deployed contract
- Backup, retention, alerting, and monitoring configuration
- Secret-store and key-rotation implementation
- Current dependency and security-scan findings
- Actual anchoring cadence and backlog

### Roadmap Or Not Yet Evidenced

- KMS or HSM custody for all service keys
- Formal SOC 2, ISO 27001, or regulatory certification
- A contractual uptime SLA
- Automatic per-tenant Ed25519 key rotation
- Proof that every customer integration has made Inntris a mandatory execution
  boundary

## External-Sharing Rule

Share the security overview and pilot SOW first. Provide the engineering threat
model and runbooks during technical diligence. Do not claim a deployment-backed
control until current evidence has been captured for the environment being
discussed.
