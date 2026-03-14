# CLAUDE.md

> This file is the single source of truth for how Claude operates in this repo.
> Update it after every correction. Review it at the start of every session.
> **Growth gate:** If this file exceeds 300 lines, review and consolidate. Merge overlapping rules. Delete anything that hasn't been relevant in 5+ sessions.

---

## Thinking Depth — When to Use Extended Thinking

Claude Code has a built-in thinking budget hierarchy. Use the right level for the right task — ultrathink costs tokens and time, so don't default to it.

| Keyword | Thinking Budget | Use When |
|---|---|---|
| *(none)* | minimal | Simple edits, quick fixes, renaming |
| `think` | ~4,000 tokens | Routine refactors, small features |
| `think hard` / `megathink` | ~10,000 tokens | New features, non-trivial debugging |
| `think harder` / `ultrathink` | ~31,999 tokens | Architecture decisions, stuck in a loop, crypto/security logic, multi-service design |

**Rules:**
- `ultrathink` **only works in Claude Code CLI** — not in claude.ai web or raw API
- Use it sparingly: overuse wastes tokens and slows output without improving simple tasks
- The sweet spot: prefix your plan-mode prompts with `ultrathink` for architecture and security tasks
- Use `/effort` to set session-level effort: `low` / `medium` / `high` / `max`

**Recommended workflow for complex tasks:**
```
1. ultrathink. Read all relevant files first. Do NOT write code yet.
2. ultrathink. Analyse what you've read and propose a plan. Do NOT code yet.
3. [Review + approve plan]
4. Implement based on confirmed plan.
5. Commit and push PR.
```

---

## Context & Token Hygiene

The context window is a finite resource. Mismanaging it silently degrades output quality.

**Rules:**
- **Load only what's relevant** — at session start, load files for the current task, not the whole repo. If you're fixing `src/auth/verify.py`, don't also load `src/frontend/styles.css`.
- **Use `/compact` proactively** — when a session has been running long (20+ tool calls or 3+ major tasks), run `/compact` to summarize and reclaim context. Don't wait until output quality visibly degrades.
- **Signal context pressure** — if the context window is getting crowded, tell the user: *"Context is getting heavy. I recommend compacting or starting a fresh session for the next task."* Don't silently degrade.
- **One concern per session** — if a session starts drifting across unrelated tasks, suggest splitting into a new session rather than cramming everything in.
- **Subagents are context-free** — offload parallel research or isolated tasks to subagents specifically to protect the main context window.

---

## Workflow Orchestration

### 1. Plan Mode Default
- Enter plan mode for ANY non-trivial task (3+ steps or architectural decisions)
- Prefix plan prompts with `ultrathink` for complex architecture or security decisions
- Write detailed specs upfront — reduce ambiguity before touching code
- If something goes sideways, **STOP and re-plan immediately** — don't keep pushing
- Use plan mode for verification steps too, not just building
- One person reviews the plan before auto-accept mode is switched on

### 2. Subagent Strategy
- Use subagents to keep the main context window clean
- **One task per subagent** — focused, auditable, isolated execution
- Offload research, exploration, and parallel analysis to subagents
- For complex problems, spin up multiple subagents in parallel for throughput
- Lead agent should use `ultrathink` to plan which subagents to spin up and define their roles

**How to invoke subagents:**
```bash
# From within a Claude Code session — use natural language
"Spawn a subagent to clean up the auth module — scope it to src/auth/ only"
"Use a subagent to run the full test suite and report failures"
"Spin up a subagent to review the architecture of the policy engine"

# Or use the slash command
/task "Run end-to-end tests for the verify endpoint and report all failures"
```

**Subagent scoping patterns for this repo:**
```
Cleanup       → scope to changed files from current PR
Verification  → scope to test suite + target endpoint/module
Architecture  → scope to service boundary under review
Research      → scope to specific library/API docs
```

### 3. Documentation Search Before Implementing

**Rule: If you are not 100% certain an API, library, or framework feature works as expected — search for the current official documentation before writing a single line of code.**

- Use web search to fetch the latest docs for any library, SDK, or framework being used
- Prefer official sources: `docs.*`, `github.com/[org]/[repo]`, official changelogs
- If the docs are ambiguous or contradictory, surface this to the user — don't guess
- **Only implement if you are 100% confident it will work.** If not, say so explicitly and show the user the relevant doc section.
- This applies especially to: Railway CLI, Vercel SDK, FastAPI versions, Next.js App Router behaviour, Solidity contract interfaces, and MCP server specs

```
# Good pattern
1. "Let me check the current Railway deploy API docs before implementing this."
2. [fetch docs]
3. "Based on the docs, here is exactly what will happen: ..."
4. [implement with confidence]

# Bad pattern
1. Assume behaviour from training data
2. Implement
3. Fail at runtime
4. Debug
```

### 4. Self-Improvement Loop
- After ANY correction from the user: update `tasks/lessons.md` with the pattern
- Write rules for yourself that **prevent** the same mistake — not just describe it
- Ruthlessly iterate on lessons until mistake rate visibly drops
- Review `tasks/lessons.md` at the start of every session for the relevant project
- If a lesson is no longer relevant, remove it — don't let the file bloat

### 5. Verification Before Done
- **Never mark a task complete without proving it works**
- Run tests, check logs, hit the actual endpoint — demonstrate correctness
- Diff behaviour between `main` and your changes when relevant
- Ask yourself: "Would a staff engineer approve this?"
- For API changes: test the happy path, an error path, and a boundary case
- For security-sensitive changes (crypto, auth, policy engine): mandatory verification before marking done

### 6. Demand Elegance (Balanced)
- For non-trivial changes: pause and ask "is there a more elegant way?"
- If a fix feels hacky: `ultrathink` — "Knowing everything I know now, implement the elegant solution"
- Skip this for simple, obvious fixes — don't over-engineer
- **Tiebreaker: Elegance means simplicity with intent — not abstraction for its own sake. If the simple solution is also the elegant one, you're done.**

### 7. Autonomous Bug Fixing
- When given a bug report: **just fix it** — don't ask for hand-holding
- Point at logs, errors, and failing tests — then resolve them
- Zero context switching required from the user
- Go fix failing CI tests without being told how
- If root cause is unclear, investigate first (check logs/traces), then fix

### 8. Error Recovery & Rollback
- **If a fix introduces a new failure, revert immediately and re-plan** — don't stack patches on top of a broken fix
- Use `git stash` or `git checkout -- <file>` to revert quickly; don't manually undo line-by-line
- After reverting, re-enter plan mode with `ultrathink` to understand why the fix failed before trying again
- If two consecutive fix attempts fail on the same issue, **stop and surface it to the user** with a clear summary of what was tried and why it failed
- Never let a broken state persist in the working tree longer than one fix attempt

---

## Task Management

Every non-trivial session follows this sequence:

1. **Plan First** — Write plan to `tasks/todo.md` with checkable items
2. **Verify Plan** — Check in before starting implementation; don't 1-shot without alignment
3. **Track Progress** — Mark items complete (`- [x]`) as you go
4. **Explain Changes** — High-level summary at each step (what changed and why)
5. **Document Results** — Add a review section to `tasks/todo.md` when done
6. **Capture Lessons** — Update `tasks/lessons.md` after any correction

### tasks/ file conventions
```
tasks/
├── todo.md        # Current session plan with checkboxes
└── lessons.md     # Accumulated correction patterns (never delete, only improve)
```

---

## Core Principles

- **Simplicity First** — Make every change as simple as possible. Impact minimal code. This is the default; "elegance" is not an excuse to add complexity.
- **No Laziness** — Find root causes. No temporary fixes. Senior developer standards.
- **Minimal Impact** — Changes should only touch what's necessary. Don't introduce new surface area.
- **No Guessing** — If context is missing, ask once, precisely. Don't invent assumptions.
- **Fail Loudly** — Prefer explicit errors over silent failures. Make problems visible.
- **Docs First** — Never implement an integration from memory. Fetch and verify the current docs first.
- **Revert Before Retry** — If a fix fails, revert to a known-good state before attempting again.

---

## Git & PR Discipline

- Use `/commit-push-pr` for every completed unit of work
- Pre-compute git context inline (status, branch, diff summary) to avoid back-and-forth
- Commit messages follow: `type(scope): description` — e.g. `fix(api): resolve nonce replay in anchor worker`
- Never push directly to `main` — always branch + PR
- PRs must include: what changed, why, and how it was verified

---

## Permissions & Safety

- Pre-allowed safe bash commands are in `.claude/settings.json` — don't bypass this
- Do not use `--dangerously-skip-permissions` in day-to-day work
- For long-running sandboxed tasks only: `--permission-mode=dontAsk` is acceptable
- Security-sensitive changes (crypto, auth, policy engine) require explicit verification step before marking done

---

## MCP & Tool Use

### General
- Use available CLI tools autonomously (`bq`, `railway`, `vercel`, etc.)
- MCP config lives in `.mcp.json` — check it into git
- If a tool fails, diagnose and retry once before surfacing to the user

### MCP Server Expectations
- **Verify MCP tool availability at session start** — if an expected MCP server is not responding, surface this immediately rather than failing mid-task
- Expected servers for this repo: document each MCP server and its purpose in `.mcp.json` with inline comments or a companion `MCP_SERVERS.md`
- If MCP auth expires mid-session (token refresh failure, 401/403 responses), stop the current task and tell the user: *"MCP auth for [server] has expired. Please re-authenticate before I continue."*
- Don't retry auth failures silently — they won't self-resolve

### Slack MCP
- Search and post without asking — just do it
- Use threads for follow-ups, not new messages

---

## Context Loading (Session Start)

At the start of any session, load in this order:
1. This file (`CLAUDE.md`)
2. `tasks/lessons.md` (project-specific)
3. `tasks/todo.md` if continuing an existing thread
4. Relevant source files for the current task — **not the whole repo**

**Anti-pattern:** Loading 10+ files "just in case" at session start. This eats context budget for files you may never reference. Load on demand.

---

## What Gets Added Here

- Any time Claude does something wrong → add a rule that prevents it next time
- Any time a pattern proves itself → document it
- Any time a section becomes stale → update or remove it
- This file should get **better with every session**, not longer
- **Hard limit: 300 lines.** If this file exceeds 300 lines, consolidate overlapping rules and prune anything that hasn't been relevant in 5+ sessions.
