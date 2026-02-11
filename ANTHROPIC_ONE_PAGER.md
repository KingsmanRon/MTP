# Inntris Core — One Pager

## The VISA Network for AI Agents

**Problem:** AI agents make real decisions (payments, emails, API calls) with no standard for verification, control, or accountability.

**Solution:** Universal verification infrastructure providing cryptographic identity, policy enforcement, and forensic audit trails.

---

## How It Works

```
Agent wants to act → Calls Inntris Guard → Verified? → Action proceeds
                                        → Blocked?  → Action prevented
                                                       Alert generated
                                                       Audit logged
```

**Three Guarantees:**
| Guarantee | Implementation | Benefit |
|-----------|---------------|---------|
| **Identity** | Ed25519 cryptographic signatures | Prove which agent acted |
| **Control** | Policy engine (limits, allowlists) | Define what agents can do |
| **Audit** | Append-only logs + blockchain anchors | Court-admissible evidence |

---

## MCP Integration

```json
{
  "mcpServers": {
    "inntris-guard": {
      "command": "npx",
      "args": ["inntris-mcp-server"]
    }
  }
}
```

**Three MCP Tools:**
- `inntris_guard` — Verify before sensitive actions
- `inntris_check_status` — Query limits and trust score
- `inntris_log_audit` — Log events for audit trail

---

## Key Metrics

| Metric | Value |
|--------|-------|
| Verification Latency | <100ms |
| Signature Algorithm | Ed25519 |
| Blockchain | Base L2 |
| Audit Retention | Forever |

---

## The Ask

1. **Recommended Integration** — Include Inntris in MCP best practices
2. **Documentation** — Reference for financial/sensitive agent actions
3. **Co-Marketing** — Joint announcement on agent safety

---

## Contact

[Your Name] | [Email] | [Phone]

*"Protecting Intellect. The Universal Liability Shield for Autonomous Agents."*
