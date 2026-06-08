# Security Policy

Inntris builds infrastructure that backs legal claims about AI agent
behavior. Cryptographic and operational integrity are core product
requirements, not afterthoughts. We take vulnerability reports seriously
and we commit to timelines and transparency with every reporter.

## Supported versions

| Version | Security updates |
|---------|-----------------|
| `master` | Yes |
| Latest tagged release | Yes |
| Prior tagged releases | Best-effort for 90 days after the next tag |

Pre-1.0 releases are considered tracking `main`. Downstream integrators
should pin to a specific commit and subscribe to our advisories.

## Reporting a vulnerability

**Do not open a public GitHub issue.** Report privately by one of:

* GitHub Security Advisories: use the **Report a vulnerability** button
  on the repo's Security tab.
* Email: `security@inntris.com`. For sensitive reports, encrypt with
  the PGP key published at <https://inntris.com/.well-known/security.asc>
  (fingerprint to be published on first release).

Include, at minimum:

* Affected component (API endpoint, worker, contract, frontend).
* Reproduction steps or a minimal proof-of-concept.
* Your assessment of impact and any suggested remediation.
* Whether you have disclosed to any third party.

### Response SLA

| Stage | Target |
|-------|--------|
| Acknowledge receipt | 2 business days |
| Initial triage & severity classification | 5 business days |
| Fix released (Critical) | 7 days |
| Fix released (High) | 30 days |
| Fix released (Medium) | 90 days |
| Public advisory with credit | Within 7 days of fix release (or sooner at your request) |

If a report involves on-chain contract behavior or key compromise, we
may ask you to delay public disclosure up to an additional 30 days
while we coordinate a timelock-gated remediation (see
`docs/runbooks/timelock_admin.md`).

## Scope

### In scope
* Any code in this repository: API, workers, MCP server, frontend,
  contracts (`contracts/AnchorRegistry.sol`), migrations.
* The public API at `api.inntris.com` (once published — verify the
  host in production docs).
* Any contract deployed by our CI pipeline to public L2s.

### Out of scope
* Social engineering of Inntris staff.
* Physical attacks or access to Inntris premises.
* Denial-of-service attacks against the public API (rate limiting is
  working as intended if it fails your traffic closed).
* Vulnerabilities in third-party dependencies that have no public fix
  and no mitigation in our code — please still report, we will
  coordinate upstream, but no bounty applies.
* Issues that require root access to an organization's own
  infrastructure to exploit.

## Rewards

We do not currently run a public bug bounty program. We do recognize
reporters by name in the published advisory (with your permission)
and in the CHANGELOG. Formal bounty coordination may be added once
the product reaches general availability.

## Our security posture

Current hardening in this repo, for context when prioritizing a report:

* **Ed25519 signature verification** on every `/verify` call, with
  nonce replay prevention and fail-closed rate limiting.
* **Row-level security** policies and a tenant-role downgrade path for
  tenant-scoped Postgres tables (`database/migrations/005_rls_policies.sql`).
  Production activation depends on the applied migrations and runtime DSN and
  must be verified per deployment.
* **TimelockController** gates `AnchorRegistry` admin; 48h delay on
  every admin op. See `docs/runbooks/timelock_admin.md`.
* **Chain-ID verification** at worker startup and a gas-price cap on
  every anchor tx, so a misconfigured RPC cannot burn operator ETH
  or land a tx on the wrong chain.
* **Observability**: every request carries a correlation ID; outcomes
  are exported as Prometheus counters so anomalous spikes alert
  before customers notice. See `docs/runbooks/incident_response.md`.
* **GDPR erasure** preserves on-chain Merkle proofs while removing
  PII; see `docs/runbooks/gdpr_erasure.md`.
* **Automated scanning**: Dependabot for dependencies, Semgrep for
  SAST, Trivy for SCA and secret detection. See
  `.github/workflows/security.yml`.

Known gaps are tracked in `docs/THREAT_MODEL.md` §4 (Residual Risks).

## Artifact signing

When release artifacts (container images, published wheels) are
produced, they will be signed with [Sigstore
cosign](https://www.sigstore.dev/). The signing identity and
transparency-log entries will be published in the release notes.
Until a release pipeline is live, this policy is aspirational —
verify by cloning and building from a specific commit.

---

*This policy is versioned alongside the code. When it changes, we
note the change in the commit message; substantive changes get a PR
with a reviewer from the security team.*
