# ECC Reuse Assessment For Inntris

**Reviewed:** June 8, 2026
**Source repository:** `affaan-m/ECC` at local commit `90dfd950`
**License:** MIT

## Executive Call

ECC is useful to Inntris as an operating-pattern and document-pattern library.
It is not useful as a dependency to import wholesale into the Inntris product.

The highest-value ideas are:

1. Separate reputation or historical trust from authorization of the current
   action.
2. Produce portable evidence packs for buyers and auditors.
3. Track policy baselines and drift over time.
4. Require explicit owner approval and live readback before high-impact
   release or operational actions.
5. Use evidence-first production audits and repeatable evaluation scenarios.

## Useful Now

### 1. Honest Trust-Boundary Format

ECC's AURA integration documents:

- what a trust verdict proves;
- what it explicitly does not prove;
- failure modes;
- mitigations; and
- residual risk owned by the caller.

This is directly useful for Inntris buyer communication. Inntris should use the
same honesty pattern for receipts and policy decisions.

Important product implication:

> A historical trust score can inform policy, but it should not be the sole
> authorization for an irreversible current action.

Explicit permissions, limits, transaction or action validation, and human
approval should remain separate policy inputs.

### 2. Buyer Evidence Packs

ECC's AgentShield roadmap treats a portable evidence pack as a first-class
enterprise deliverable. For Inntris, each pilot evidence pack should include:

- workflow and control-boundary description;
- applied policy and policy hash;
- PASS, BLOCK, and ESCALATE scenarios;
- receipt links and exported records;
- deployment and integration evidence;
- residual risks and bypass paths;
- production-readiness recommendation; and
- owner-ready action list.

This should become a productized pilot output before building another demo.

### 3. Policy Baseline And Drift

ECC recommends comparing the current security state against the last accepted
baseline. Inntris can apply the same concept to agent policy:

- who changed the policy;
- what allow/block permissions changed;
- which spend or rate limits changed;
- prior and new policy hash;
- effective time;
- approval status; and
- which receipts were issued under each version.

This is a strong future admin feature and enterprise narrative.

### 4. Explicit Approval Gates

ECC's owner approval packet separates evidence from permission to act. Inntris
should use this model for:

- production policy promotion;
- agent reactivation after suspension;
- unusually high spend-limit changes;
- new administrative permissions;
- contract role changes; and
- release or deployment approval.

An evidence packet should never authorize its own promotion.

### 5. Production Audit And Evaluation

ECC's production-audit and eval-harness patterns are useful for Inntris demos
and releases:

- define success criteria before integration;
- run deterministic PASS and BLOCK scenarios;
- keep human review for security-sensitive judgments;
- capture missing evidence and residual risk;
- repeat critical scenarios to measure stability; and
- block claims that lack live readback.

The pilot SOW now uses this pattern.

### 6. Agentic Security Minimum Bar

ECC's security guidance reinforces several Inntris product and trust-pack
themes:

- least agency and least privilege;
- approval boundaries outside the model;
- separate identities and scoped credentials;
- fail-closed behavior;
- tool-call and network observability;
- kill switches; and
- untrusted-input isolation.

These are useful as pilot discovery questions and future policy templates.

### 7. Sales And Demo Operations

ECC includes reusable workflows for brand voice, marketing campaigns, investor
materials, and presentation creation. The useful lesson is procedural:

- define positioning before copy;
- keep one source of truth for claims and numbers;
- make every claim supportable;
- gate outbound material with explicit approval; and
- preserve evidence behind launch claims.

## Potential Product Features Inspired By ECC

Prioritized for Inntris:

| Priority | Feature | Why it matters |
| --- | --- | --- |
| 1 | Pilot evidence-pack export | Turns the 14-day pilot into a concrete buyer deliverable |
| 2 | Policy change history and hash diff | Gives admins proof of what changed and when |
| 3 | Policy promotion approvals | Adds human governance for high-impact control changes |
| 4 | Deployment evidence/readback page | Separates configured controls from verified-live controls |
| 5 | Scenario/eval runner for policies | Makes PASS/BLOCK behavior repeatable before production |
| 6 | Organization policy templates | Extends the current agent-level presets across teams |
| 7 | External reputation-signal adapter | Useful only as an advisory policy input, never sole authorization |

## What Not To Import

- Do not copy the entire ECC plugin, hook, skill, or cross-harness surface into
  Inntris.
- Do not add AgentShield or another scanner as a runtime product dependency
  without a separate security and maintenance review.
- Do not install unreviewed hooks into production or developer machines.
- Do not mix generic coding-agent orchestration with the Inntris customer
  control plane.
- Do not let prompt instructions stand in for code-enforced authorization.
- Do not present ECC's security claims as Inntris evidence.

## License Guidance

ECC is MIT-licensed. Ideas and patterns can be adapted freely. If Inntris copies
substantial ECC code or documentation, preserve the ECC copyright and MIT
license notice in the copied or distributed material. This assessment adapts
ideas and structure; it does not copy ECC runtime code.

## Recommendation

Use ECC as a reference library for operating discipline. The immediate Inntris
move is to ship a buyer evidence-pack format and policy-change evidence, not to
merge ECC into the product.
