# Inntris Agent Action Proof Pilot

## Statement Of Work Template

**Version:** June 8, 2026
**Duration:** 14 calendar days
**Starting price:** USD 5,000
**Status:** Working commercial template. Final scope, legal terms, and price
require an executed order form or agreement.

## 1. Objective

Inntris will instrument one high-risk AI agent workflow so the customer can:

- define which actions are allowed or blocked before execution;
- apply identity, action, rate, and spend controls;
- produce a receipt for every covered PASS, BLOCK, or ESCALATE decision; and
- assess whether the workflow is suitable for a production rollout.

The pilot is intended to answer:

> Can the customer control one consequential agent action and independently
> verify the resulting decisions?

## 2. In-Scope Workflow

The parties will select one workflow before kickoff.

| Field | Agreed value |
| --- | --- |
| Workflow name | `[customer workflow]` |
| Business owner | `[name / team]` |
| Technical owner | `[name / team]` |
| Protected action | `[payment / tool call / production change / data export / other]` |
| Agent runtime | `[runtime / framework]` |
| Protected downstream system | `[system]` |
| Production consequence if unauthorized | `[loss or exposure]` |

The workflow must expose a technical decision point before the protected action
executes. A workflow that cannot be gated can be assessed or attested, but it
cannot demonstrate prevention.

## 3. Deliverables

Inntris will provide:

1. One registered agent identity and protected action boundary.
2. One agreed policy configuration covering relevant allow/block permissions,
   status controls, rate limit, and spend limits where applicable.
3. Integration guidance for the selected workflow.
4. PASS and BLOCK test scenarios, plus ESCALATE when rate limiting applies.
5. Verifiable receipts for covered pilot decisions.
6. A pilot evidence pack containing:
   - workflow and boundary description;
   - final policy and policy hash;
   - scenario results and receipt links;
   - risks, bypass paths, and residual risks observed;
   - production rollout recommendation; and
   - open decisions and owners.
7. A final review session with technical and business stakeholders.

## 4. Pilot Timeline

### Days 1-2: Choose And Map The Action

- Confirm workflow, consequence, and owner.
- Identify the mandatory execution boundary.
- Document current authorization and evidence gaps.
- Confirm test environment, data, and access.

### Days 3-7: Integrate And Enforce

- Register agent identity.
- Integrate the Inntris verification call before execution.
- Configure policy, permissions, rate limit, and spend limits.
- Confirm direct bypass paths are removed or explicitly documented.

### Days 8-11: Exercise The Boundary

- Run approved, blocked, replay, suspension, and limit scenarios as applicable.
- Inspect receipts and public or private verification.
- Record issues and adjust the policy within the agreed scope.

### Days 12-14: Evidence And Recommendation

- Repeat final success scenarios.
- Assemble the pilot evidence pack.
- Review residual risks and production requirements.
- Deliver rollout recommendation.

## 5. Success Criteria

The pilot is successful when all agreed mandatory criteria pass.

| Criterion | Mandatory | Result |
| --- | --- | --- |
| Covered actions cannot execute without an Inntris PASS decision | Yes | `[PASS / FAIL]` |
| Covered allowed actions produce verifiable receipts | Yes | `[PASS / FAIL]` |
| Covered blocked actions do not receive an approval token | Yes | `[PASS / FAIL]` |
| Block reasons are understandable to the workflow owner | Yes | `[PASS / FAIL]` |
| Policy hash is bound to policy-evaluated receipts | Yes | `[PASS / FAIL]` |
| Agent suspension causes new covered requests to fail closed | Yes | `[PASS / FAIL]` |
| Integration overhead is acceptable to the customer | Yes | `[PASS / FAIL]` |
| Receipts can be independently inspected by the agreed reviewer | Yes | `[PASS / FAIL]` |

Optional workflow-specific criteria may be added before kickoff.

## 6. Customer Responsibilities

The customer will:

- provide a technical owner and a business or risk owner;
- provide access to a safe pilot or test environment;
- identify the action that must be gated and its direct execution paths;
- retain custody of customer agent private keys and downstream credentials;
- provide representative test scenarios and test data;
- avoid sending unnecessary secrets or personal data in pilot payloads;
- participate in kickoff, integration, and final review sessions; and
- approve any move from test to production.

## 7. Inntris Responsibilities

Inntris will:

- provide integration and policy configuration support;
- operate the Inntris pilot control and receipt surfaces;
- document observed risks and bypass paths;
- avoid claiming that a control is active without evidence;
- notify the customer of material pilot incidents; and
- deliver the evidence pack and rollout recommendation.

## 8. Security And Data Handling

- The customer retains its agent private keys and downstream credentials.
- Inntris receives the selected action payload, action metadata, and signature
  material required for verification.
- The customer and Inntris will agree on the minimum necessary payload before
  testing.
- Raw payloads are not written on-chain. Merkle roots and batch metadata are
  written on-chain.
- Public receipt sharing is optional and must be agreed for the pilot.
- Production-specific retention, deletion, backup, residency, and incident
  terms are outside this template unless added to the executed agreement.

## 9. Out Of Scope

Unless added through written change control, the pilot excludes:

- more than one workflow or materially different action boundary;
- production deployment or production credentials;
- custom compliance certification or legal opinion;
- formal penetration testing;
- customer-wide agent inventory or migration;
- custom dashboards, reports, or integrations unrelated to the selected flow;
- guaranteed uptime or response SLA; and
- remediation of vulnerabilities in customer or third-party systems.

## 10. Change Control

Either party may request a scope change. The change is accepted only when both
parties agree in writing on the revised deliverables, timing, price, and
success criteria.

## 11. Completion And Acceptance

The pilot completes when:

- the 14-day period ends;
- the evidence pack and rollout recommendation are delivered; and
- the final review session occurs or the customer elects not to attend.

The final report will mark each success criterion PASS, FAIL, NOT TESTED, or NOT
APPLICABLE. A failed criterion is a pilot finding, not an automatic extension
of the pilot.

## 12. Commercial Summary

| Item | Value |
| --- | --- |
| Pilot fee | `[USD 5,000 or agreed amount]` |
| Payment schedule | `[agreed terms]` |
| Start date | `[date]` |
| End date | `[date]` |
| Inntris owner | `[name]` |
| Customer owner | `[name]` |

## 13. Approval

This SOW becomes binding only when incorporated into an executed agreement or
order form signed by authorized representatives.

| Party | Name | Title | Signature | Date |
| --- | --- | --- | --- | --- |
| Customer |  |  |  |  |
| Inntris |  |  |  |  |
