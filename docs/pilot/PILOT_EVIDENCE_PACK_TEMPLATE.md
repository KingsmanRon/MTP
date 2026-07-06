# Inntris Pilot Evidence Pack

**Pilot:** `[customer / workflow]`
**Pilot period:** `[start date]` to `[end date]`
**Evidence snapshot:** `[UTC timestamp]`
**Inntris commit:** `[sha]`

This packet records what was tested and observed during one Agent Action Proof
Pilot. It is evidence for a scoped decision, not a certification or guarantee
about actions outside the covered workflow.

Export the machine-verifiable pack with `scripts/build_evidence_pack.py`
(keygen → ingest → build). The resulting archive is byte-reproducible, signs a
per-file SHA-256 manifest as the attested object, re-verifies every ingest
hash at assembly, and embeds a standalone offline verifier plus
[the verification methodology](../../evidence_pack/pack_contents/METHODOLOGY.md).
Include this completed document in the pack as `evidence/report.md`.

## 1. Executive Result

| Field | Result |
| --- | --- |
| Protected workflow | `[workflow]` |
| Protected action | `[action]` |
| Business consequence | `[loss or exposure]` |
| Mandatory execution boundary demonstrated | `[yes / no / partial]` |
| Overall recommendation | `[proceed / proceed with conditions / do not proceed]` |
| Primary finding | `[finding]` |
| Production owner | `[name / team]` |

## 2. Scope And Boundary

Describe the exact covered path:

```text
Agent -> Inntris policy decision -> approval validation -> protected system
```

Document:

- systems and identities in scope;
- entry point and protected action;
- credentials and direct execution paths;
- where Inntris is mandatory;
- where Inntris can be bypassed; and
- excluded workflows.

## 3. Applied Policy

| Control | Final value |
| --- | --- |
| Agent ID | `[id]` |
| Agent status | `[status]` |
| Allowed actions | `[list]` |
| Blocked actions | `[list]` |
| Daily spend limit | `[value]` |
| Per-action spend limit | `[value]` |
| Rate limit | `[value]` |
| Policy hash | `[hash]` |
| Policy owner | `[name]` |

Attach the final policy or a redacted representation suitable for review.

## 4. Scenario Results

| Scenario | Expected | Actual | Receipt or evidence | Result |
| --- | --- | --- | --- | --- |
| Allowed action | PASS and execute | `[actual]` | `[link / id]` | `[PASS / FAIL]` |
| Explicitly blocked action | BLOCK and no execution | `[actual]` | `[link / id]` | `[PASS / FAIL]` |
| Above per-action limit | BLOCK and no execution | `[actual]` | `[link / id]` | `[PASS / FAIL]` |
| Above daily limit | BLOCK and no execution | `[actual]` | `[link / id]` | `[PASS / FAIL]` |
| Rate limit exceeded | ESCALATE and no unapproved execution | `[actual]` | `[link / id]` | `[PASS / FAIL]` |
| Replayed nonce | BLOCK | `[actual]` | `[link / id]` | `[PASS / FAIL]` |
| Agent suspended | BLOCK and no execution | `[actual]` | `[link / id]` | `[PASS / FAIL]` |
| Invalid signature | BLOCK | `[actual]` | `[link / id]` | `[PASS / FAIL]` |

Remove scenarios that are not applicable and explain why.

## 5. Receipt Verification

For representative PASS and BLOCK receipts, record:

| Check | PASS receipt | BLOCK receipt |
| --- | --- | --- |
| Receipt ID | `[id]` | `[id]` |
| Agent signature | `[verified / failed]` | `[verified / failed]` |
| Policy hash | `[verified / not applicable / failed]` | `[verified / not applicable / failed]` |
| Receipt fingerprint | `[verified / failed]` | `[verified / failed]` |
| On-chain anchor | `[verified / pending / failed]` | `[verified / pending / failed]` |
| Independent reviewer | `[name]` | `[name]` |

## 6. Success Criteria

| Criterion | Result | Evidence | Owner if failed |
| --- | --- | --- | --- |
| Covered action cannot execute without PASS | `[result]` | `[evidence]` | `[owner]` |
| Allowed actions produce receipts | `[result]` | `[evidence]` | `[owner]` |
| Blocked actions receive no approval token | `[result]` | `[evidence]` | `[owner]` |
| Policy is understandable and owned | `[result]` | `[evidence]` | `[owner]` |
| Policy hash is bound where required | `[result]` | `[evidence]` | `[owner]` |
| Suspension fails closed | `[result]` | `[evidence]` | `[owner]` |
| Integration overhead is acceptable | `[result]` | `[evidence]` | `[owner]` |

## 7. Findings And Residual Risks

| Severity | Finding | Evidence | Recommendation | Owner |
| --- | --- | --- | --- | --- |
| `[critical/high/medium/low]` | `[finding]` | `[evidence]` | `[action]` | `[owner]` |

Always include:

- known bypass paths;
- customer-controlled key and credential risks;
- deployment controls not verified during the pilot;
- pending anchors or unavailable evidence;
- dependencies on human approval; and
- any action types not covered.

## 8. Production Readiness

Complete the
[Production Trust Readback Checklist](../trust/PRODUCTION_READBACK_CHECKLIST.md)
for the target environment before recommending production.

| Gate | State | Required next action |
| --- | --- | --- |
| Execution boundary | `[ready / blocked]` | `[action]` |
| Policy ownership | `[ready / blocked]` | `[action]` |
| Tenant isolation | `[ready / blocked]` | `[action]` |
| Key custody and rotation | `[ready / blocked]` | `[action]` |
| Monitoring and incident response | `[ready / blocked]` | `[action]` |
| Backup and recovery | `[ready / blocked]` | `[action]` |
| Security findings | `[ready / blocked]` | `[action]` |

## 9. Recommendation

Choose one:

- **Proceed:** the covered workflow is ready for the agreed production rollout.
- **Proceed with conditions:** rollout only after the listed blockers close.
- **Do not proceed:** the current boundary cannot reliably control the action.

Recommendation:

```text
[decision, rationale, conditions, and owner]
```

## 10. Approval

| Role | Name | Decision | Date |
| --- | --- | --- | --- |
| Customer technical owner |  |  |  |
| Customer risk or business owner |  |  |  |
| Inntris pilot owner |  |  |  |

Approval applies only to the scoped workflow and evidence snapshot above.
