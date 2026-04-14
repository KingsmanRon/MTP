# Inntris Opportunity Scout Report — 2026-04-14

## Context
Post-promptfoo attestation success. Seeking next demo target.
Pipeline: Scout → Architect → PoC Reviewer.

---

COMPANY: Mastra AI
URL: https://mastra.ai
REPO: https://github.com/mastra-ai/mastra
STAGE: YC W25, $13M funding. 23k+ GitHub stars. 300k+ weekly npm downloads.
FIT SCORE: 14/15 — Agent:3 Audit:2 Reach:3 Distribution:3 Speed:3

WHY NOW (≤3 sentences):
Mastra ships autonomous TypeScript agents with native MCP support and tool
calling. 300k+ weekly npm downloads means wrapping Mastra wraps a category.
EU AI Act Article 12 tamper-evident logging deadline (Aug 2026) hits their
enterprise users first — and they have no audit layer today.

INTEGRATION WEDGE:
`/packages` agent execution path — tool calling middleware intercept before
agent.execute(). MCP server authoring support means Inntris can ship as an
MCP tool server that plugs into any Mastra agent. The `agents/` directory
contains the core Agent class with tool dispatch.

POC HYPOTHESIS (1 sentence):
If we ship an inntris-verify MCP server + Mastra middleware wrapper, they see
a BLOCKED verdict on a malicious tool call in their console, and the
conversation becomes "how do we ship this to our enterprise users before Aug
2026?"

DISTRIBUTION UNLOCK:
Every Mastra user (300k+/week npm). TypeScript agent ecosystem broadly.
Pattern ports directly to VoltAgent, Trigger.dev, and other TS frameworks.

HANDOFF TO ARCHITECT: Yes
FIRST QUESTION THE ARCHITECT MUST ANSWER:
Where exactly in Mastra's agent execution loop does tool dispatch happen, and
can middleware intercept it before the tool function runs?

---

COMPANY: LiteLLM (BerriAI)
URL: https://litellm.ai
REPO: https://github.com/BerriAI/litellm
STAGE: 43k+ GitHub stars. Adopted by Stripe, Netflix, OpenAI Agents SDK.
FIT SCORE: 13/15 — Agent:2 Audit:3 Reach:3 Distribution:3 Speed:2

WHY NOW (≤3 sentences):
LiteLLM is the de facto LLM gateway. Issue #24534 is a community request for
cryptographic audit trails via Asqav — proving demand signal. Their callback
and custom guardrail infrastructure is purpose-built for this integration.
(https://github.com/BerriAI/litellm/issues/24534)

INTEGRATION WEDGE:
Custom callback handler or guardrail plugin in the LiteLLM proxy. Intercepts
at the `litellm.callbacks` layer before tool call execution. The proxy's
`proxy_server_config.yaml` supports custom middleware deployment.

POC HYPOTHESIS (1 sentence):
If we ship a LiteLLM custom callback that signs + anchors every tool call,
their 43k-star community sees Inntris as the production-grade alternative to
Asqav's hash-chain-only approach, and the conversation becomes "merge this as
an official integration."

DISTRIBUTION UNLOCK:
Every LiteLLM proxy deployment (thousands of companies). Python AI agent
ecosystem broadly. Pattern ports to any OpenAI-compatible gateway.

HANDOFF TO ARCHITECT: Yes
FIRST QUESTION THE ARCHITECT MUST ANSWER:
What is the exact callback interface for intercepting tool calls in
litellm.callbacks, and does it fire BEFORE or AFTER tool execution?

---

COMPANY: Trigger.dev
URL: https://trigger.dev
REPO: https://github.com/triggerdotdev/trigger.dev
STAGE: $16M Series A. 14.5k+ GitHub stars. 30k+ developers. Apache-2.0.
FIT SCORE: 12/15 — Agent:3 Audit:2 Reach:3 Distribution:2 Speed:2

WHY NOW (≤3 sentences):
Trigger.dev runs durable AI agent tasks with automatic retries, queuing, and
observability — but has no cryptographic attestation of what those agents
actually did. Their human-in-the-loop pause/approve pattern is a natural fit
for policy-before-execution enforcement. $16M Series A means they're scaling
enterprise, where audit requirements hit hardest.

INTEGRATION WEDGE:
TypeScript SDK task execution layer. The `packages/` monorepo contains the
core SDK where agent tasks dispatch tool calls. MCP integration already
exists as a topic tag on the repo.

POC HYPOTHESIS (1 sentence):
If we wrap Trigger.dev's task execution with inntris-verify, they see a
tamper-evident audit trail of every AI agent action in their dashboard, and
the conversation becomes "can we ship this as a first-party integration?"

DISTRIBUTION UNLOCK:
30k+ Trigger.dev developers. Durable execution / background job ecosystem.

HANDOFF TO ARCHITECT: Yes
FIRST QUESTION THE ARCHITECT MUST ANSWER:
Where in Trigger.dev's task execution lifecycle can middleware intercept tool
calls before the tool function runs?

---

COMPANY: Letta AI (formerly MemGPT)
URL: https://letta.com
REPO: https://github.com/letta-ai/letta
STAGE: $10M seed (Felicis), UC Berkeley spinout. 22k+ GitHub stars. Apache-2.0.
FIT SCORE: 11/15 — Agent:3 Audit:2 Reach:3 Distribution:2 Speed:1

WHY NOW (≤3 sentences):
Letta ships stateful agents with persistent memory and tool calling — the
highest-stakes agent pattern (agents that remember and act autonomously). The
`/otel` directory shows they're building observability, but observability is
not attestation. Their API-first design (`/agents/messages.create()`) has a
clean intercept point.

INTEGRATION WEDGE:
Agent Messages API at `/agents/messages.create()`. Tool invocation layer
where tool definitions array dispatches to external functions. The `/otel`
OpenTelemetry hooks could be extended with cryptographic signing.

POC HYPOTHESIS (1 sentence):
If we sign every Letta agent tool call with Ed25519 and anchor the batch, a
stateful agent's entire action history becomes independently verifiable — and
the conversation becomes "memory + attestation is the enterprise trust story."

DISTRIBUTION UNLOCK:
Stateful agent category. MemGPT community (research + production).

HANDOFF TO ARCHITECT: Yes
FIRST QUESTION THE ARCHITECT MUST ANSWER:
What is the exact code path from agent message creation to tool execution in
Letta's agent loop?

---

COMPANY: VoltAgent
URL: https://voltagent.dev
REPO: https://github.com/VoltAgent/voltagent
STAGE: 5k+ GitHub stars. MIT license. Early stage (funding unknown).
FIT SCORE: 10/15 — Agent:2 Audit:1 Reach:3 Distribution:2 Speed:2

WHY NOW (≤3 sentences):
VoltAgent is a growing TypeScript agent framework with native MCP support,
guardrails, and tool orchestration. Their VoltOps Console provides
observability, but no cryptographic audit trail. The MIT license and clean
TypeScript codebase make integration straightforward.

INTEGRATION WEDGE:
Agent tool dispatch in the `@voltagent/core` package. MCP server support
means Inntris can plug in as an MCP tool server. Guardrails infrastructure
may accept custom audit hooks.

POC HYPOTHESIS (1 sentence):
If we ship an Inntris guardrail for VoltAgent, they see cryptographic
attestation alongside their existing observability, and the conversation
becomes "this is the missing piece for our enterprise story."

DISTRIBUTION UNLOCK:
Small but growing TypeScript agent ecosystem. Pattern reusable from Mastra.

HANDOFF TO ARCHITECT: No
FIRST QUESTION THE ARCHITECT MUST ANSWER:
N/A — defer until Mastra PoC ships and TypeScript pattern is proven.

---

## RECOMMENDATION

**Primary target: Mastra AI (14/15)**

Rationale:
- Highest distribution leverage (300k+ weekly npm, framework = category)
- TypeScript aligns with existing Inntris patterns
- MCP support means Inntris ships as a standard tool server, not a custom fork
- EU AI Act deadline creates urgency for their enterprise users
- PoC pattern ports directly to Trigger.dev and VoltAgent

**Secondary target: LiteLLM (13/15)**

Rationale:
- Proven demand (issue #24534)
- Largest star count (43k) and enterprise adoption (Stripe, Netflix)
- Python diversifies beyond TypeScript
- Callback infrastructure is purpose-built for this

**Pipeline: Mastra first → LiteLLM second → Trigger.dev third**
