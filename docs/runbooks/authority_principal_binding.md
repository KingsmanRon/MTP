# Principal binding — provisioning and provenance remediation

`agents.metadata["authority_principal_binding"]` names the delegate keys and
the audience a principal's **delegated authority** is bound to. It is
server-owned trusted state, read by
`api/services/authority_service.py::_principal_binding_for` and preferred by
the Verifiable Intent provider over its own injected resolver.

Whoever can write it decides which delegate key may act for that principal,
and whether a revoked key stays revoked.

## What changed

Every caller-controlled ingress now refuses the key:

| ingress | behaviour |
|---|---|
| public registration (`_public_registration_metadata`) | silently filtered |
| `POST /admin/agents` (org-scoped `write`) | silently filtered |
| `PATCH /admin/agents/{id}` | **refused, HTTP 400** |

The boundary is the shared set `SERVER_OWNED_AGENT_METADATA_KEYS` in
`api/legacy_main.py`, folded into `CALLER_BLOCKED_AGENT_METADATA_KEYS` and
`PUBLIC_REGISTRATION_METADATA_BLOCKLIST`, so a new ingress that reuses either
set inherits the whole rule rather than half of it.

Storage, shape, the reader and the provider's binding precedence are
deliberately unchanged. Precedence is safe *because* the context value is now
server-owned — the fix is ownership, not precedence.

Provisioning remains **out of band**: a trusted operator writing the agent
record directly. That is what the reader already documented, and it is how
`scripts/mastercard_vi/harness.py` provisions bindings for the Phase-6 proof.

## Provenance rule

This field was historically caller-writable. **Presence in the database is
not proof of trusted provisioning.**

Audit query:

```sql
SELECT id, org_id
FROM agents
WHERE metadata ? 'authority_principal_binding';
```

For each row:

- **proven operator/trusted provenance** — may be retained;
- **unknown provenance** — treat as untrusted.

Before delegated authority is enabled for a principal whose binding has
unknown provenance, remove or quarantine the binding and re-provision it
through a trusted channel.

Do **not** grandfather an unknown binding because it looks plausible. A
binding an organisation wrote for itself will look exactly like one an
operator wrote for it; only the provenance record distinguishes them, and if
there is no such record the answer is "untrusted".

## Future provisioning surface

Not built here, and deliberately not exposed through generic metadata
editing. A dedicated authority-management operation would need:

- a system/platform-authorised actor — never an ordinary org `write` key, and
  never the public registration path;
- explicit organisation and principal;
- explicit expected audience;
- explicit delegate key/thumbprint set;
- explicit revocation state where applicable;
- an approval/reference field;
- an immutable administrative audit event;
- tenant isolation;
- a least-privilege authority-management permission.
