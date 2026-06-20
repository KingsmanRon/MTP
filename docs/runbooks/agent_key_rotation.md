# Runbook: Agent signing-key rotation

Each agent holds an Ed25519 keypair. The CI workflow stores the **private seed**
as the `INNTRIS_PRIVATE_KEY_B64` GitHub Secret; the server stores only the
**public key**. Rotation replaces the public key in place — preserving the
agent's trust score, registered policy, and audit history — and the old key
stops verifying immediately.

## When to rotate

- **Leak response** — the private-key secret was exposed (logs, fork PR, a
  former maintainer, a misconfigured workflow).
- **Hygiene** — periodic rotation, or off-boarding.

## Per-repo agents

Prefer **one agent per repository**, not one shared key across an org. A leak
is then contained to a single repo, and you can rotate or revoke that agent
without disrupting others. Create a distinct agent per repo and register each
repo's `.inntris.yml` against its own agent.

## Rotate from the admin UI (recommended)

1. Open the agent → **AI PR Guard** tab → **Signing key**.
2. Click **Rotate signing key**, optionally enter a reason, confirm.
3. The browser generates a new keypair (WebCrypto Ed25519). The server receives
   only the public key; the **private seed is shown once**.
4. Copy the seed into the repo's `INNTRIS_PRIVATE_KEY_B64` GitHub Secret.
5. The previous key is now rejected (`signature_invalid`). The next workflow run
   uses the new secret.

If the browser cannot generate Ed25519 keys, use the CLI flow below.

## Rotate via the API (CLI / automation)

Generate a keypair offline, then submit the **public** key:

```bash
# Generate seed + public key (Python example)
python - <<'PY'
import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
sk = Ed25519PrivateKey.generate()
seed = sk.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                        serialization.NoEncryption())
pub = sk.public_key().public_bytes(serialization.Encoding.Raw,
                                   serialization.PublicFormat.Raw)
print("INNTRIS_PRIVATE_KEY_B64:", base64.b64encode(seed).decode())
print("public_key:", base64.b64encode(pub).decode())
PY

# Submit the public key (the seed never leaves your machine)
curl -X POST "$INNTRIS_API_URL/admin/agents/$AGENT_ID/rotate-key" \
  -H "X-API-Key: $ADMIN_API_KEY" -H "Content-Type: application/json" \
  -d '{"public_key":"<base64 public key>","reason":"leak response"}'
```

Then set `INNTRIS_PRIVATE_KEY_B64` to the printed seed in the repo secrets.

## Scope the blast radius of a leak

Every verification records the signing key in its audit metadata
(`metadata.key_fingerprint`). After rotating, identify everything the leaked key
authorized:

```sql
SELECT id, action_type, verdict, timestamp
FROM audit_logs
WHERE metadata->>'key_fingerprint' = '<retired fingerprint>'
ORDER BY timestamp DESC;
```

Retired keys and their versions are recorded in `agent_key_history`. If any
high-risk action was approved under the leaked key after the suspected exposure,
treat it as suspect and review the corresponding PR/deploy.

## If you cannot rotate immediately

Suspend the agent (AI PR Guard / Action controls → **Suspend agent**). Every
verification then fails closed (`agent_not_active`) regardless of key, buying
time until you rotate.
