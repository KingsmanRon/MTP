# Operations runbooks

Operator-facing playbooks. Each runbook is grounded in the code that
actually ships — counters, env vars, and contract methods referenced
by name. When behavior changes, the runbook should change in the same
PR.

| Runbook | Phase | Purpose |
|---------|-------|---------|
| [incident_response.md](incident_response.md) | 3.4 | Triage playbook for the five incident classes the platform reports on. |
| [secrets_rotation.md](secrets_rotation.md) | 3.5 | Inventory of every env-var secret plus a per-secret rotation procedure. |
| [timelock_admin.md](timelock_admin.md) | 3.3 | Deploying and operating the Safe + TimelockController topology for `AnchorRegistry` admin ops. |

See `docs/THREAT_MODEL.md` for the adversary model these runbooks
assume, and `.github/workflows/ci.yml` for what is enforced
automatically in CI vs. left to operator discipline.
