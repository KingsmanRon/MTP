# Production Trust Readback Checklist

**Purpose:** Capture current evidence before a buyer security review, pilot
kickoff, production rollout, or public security claim.

Repository configuration is not proof that a control is live. Complete this
checklist from the environment being discussed and attach the evidence to the
review packet. Never paste secrets into the packet.

## Review Header

| Field | Value |
| --- | --- |
| Environment | `[production / staging / customer]` |
| Date and time UTC | `[timestamp]` |
| Reviewer | `[name]` |
| Application commit | `[sha]` |
| Frontend deployment | `[deployment id / url]` |
| API deployment | `[deployment id / url]` |
| Database migration version | `[version / evidence]` |
| Contract address and chain | `[address / chain id]` |

## 1. Public Service And Receipt Evidence

- [ ] `GET /health` returns the expected environment state.
- [ ] Canonical PASS receipt loads and all expected checks resolve.
- [ ] Canonical BLOCK receipt loads and all expected checks resolve.
- [ ] Receipt chain ID and block-explorer destination are correct.
- [ ] Public receipt does not expose the raw action payload.
- [ ] A newly generated receipt reaches `pending_anchor` and later `verified`.

Evidence:

```text
[URLs, timestamps, receipt IDs, screenshots, or exported JSON hashes]
```

## 2. Mandatory Execution Boundary

- [ ] The selected workflow calls Inntris before the protected action.
- [ ] The downstream system rejects calls without a valid approval result or
      equivalent enforced gateway decision.
- [ ] Direct credentials or bypass routes are removed, scoped, or documented.
- [ ] Suspended-agent behavior was tested against the real protected path.

Evidence:

```text
[architecture path, configuration reference, test result]
```

## 3. Policy And Admin Controls

- [ ] Agent status control works.
- [ ] Explicit blocklist takes precedence over allowlist.
- [ ] Non-allowlisted actions are blocked.
- [ ] Per-action spend limit was tested.
- [ ] Daily spend limit was tested.
- [ ] Rate limit was tested.
- [ ] Policy update validation rejects contradictory controls.
- [ ] Policy change owner and approval process are recorded.

Evidence:

```text
[agent id, policy hash, scenario receipts, owner]
```

## 4. Database And Tenant Isolation

- [ ] Required migrations are applied.
- [ ] Runtime database role is recorded without exposing credentials.
- [ ] Tenant RLS role and policies are active if RLS is claimed.
- [ ] Cross-tenant read and write tests fail as expected.
- [ ] Audit-log UPDATE and DELETE restrictions are active.
- [ ] Anchor worker can update only required Merkle reference fields.

Evidence:

```text
[migration output, role flags, test output, query hashes]
```

## 5. Key And Secret Controls

- [ ] Agent private keys remain in customer-controlled custody.
- [ ] Organization API keys are stored as hashes.
- [ ] Admin session secret and server secret meet production length rules.
- [ ] Anchor submitter key storage method is documented.
- [ ] Current rotation owner and last rotation date are recorded.
- [ ] No plaintext secrets appear in the attached evidence.

Evidence:

```text
[secret-store reference names, fingerprints, dates; never raw values]
```

## 6. Blockchain And Anchor Operations

- [ ] Worker verifies the expected chain ID.
- [ ] Contract address matches the intended environment.
- [ ] Current admin, submitter, and pauser holders are read back.
- [ ] Safe and timelock topology is verified before it is claimed.
- [ ] Anchor backlog is within the agreed target.
- [ ] Failed and dead-letter anchor batches are reviewed.
- [ ] Gas cap and RPC circuit breaker settings are recorded.

Evidence:

```text
[block explorer links, role readback, worker metrics]
```

## 7. Monitoring, Backup, And Incident Readiness

- [ ] Verification, signature-failure, replay, rate-limit, and anchor metrics
      are visible.
- [ ] Alerts have owners and tested destinations.
- [ ] Backup and retention configuration is read back from the provider.
- [ ] Restore or recovery procedure has a recorded test date.
- [ ] Incident-response owner and customer contact path are agreed.
- [ ] Security-reporting contact works.

Evidence:

```text
[dashboard links, alert tests, provider readback, owner names]
```

## 8. Security Scanning And Release State

- [ ] CI ran against the exact intended release commit.
- [ ] Frontend tests, type-check, and build passed.
- [ ] Backend tests passed.
- [ ] Contract tests passed if contract code changed.
- [ ] Current dependency findings were reviewed.
- [ ] SAST, SCA, and secret-scan findings were reviewed.
- [ ] Any accepted finding has an owner and expiry or follow-up date.

Evidence:

```text
[run URLs, command output summary, accepted-risk register]
```

## Final Decision

| Decision | Value |
| --- | --- |
| Ready for buyer review | `[yes / no]` |
| Ready for pilot | `[yes / no]` |
| Ready for production | `[yes / no]` |
| Blocking findings | `[list]` |
| Accepted residual risks | `[list]` |
| Approver | `[name]` |
| Approval timestamp UTC | `[timestamp]` |

Approval of this checklist authorizes only the named environment and scope. It
does not authorize unrelated policy changes, releases, or customer workflows.
