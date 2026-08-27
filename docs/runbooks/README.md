# Operations runbooks

Operator-facing playbooks. Each runbook is grounded in the code that
actually ships — counters, env vars, and contract methods referenced
by name. When behavior changes, the runbook should change in the same
PR.

| Runbook | Phase | Purpose |
|---------|-------|---------|
| [incident_response.md](incident_response.md) | 3.4 | Triage playbook for the incident classes the platform reports on, including an anchor stuck at `submitted` because the RPC refuses reads (3a). |
| [secrets_rotation.md](secrets_rotation.md) | 3.5 | Inventory of every env-var secret plus a per-secret rotation procedure. |
| [timelock_admin.md](timelock_admin.md) | 3.3 | Deploying and operating the Safe + TimelockController topology for `AnchorRegistry` admin ops. |
| [gdpr_erasure.md](gdpr_erasure.md) | 4B | GDPR Art. 17 / CCPA 1798.105 erasure procedure that preserves on-chain Merkle proofs. |
| [webhooks.md](webhooks.md) | Security | Safe destination requirements, signature verification, rotation, retries, and dead letter investigation. |

See `docs/THREAT_MODEL.md` for the adversary model these runbooks
assume, and `.github/workflows/ci.yml` for what is enforced
automatically in CI vs. left to operator discipline.
