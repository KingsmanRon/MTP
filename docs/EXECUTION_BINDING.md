# Binding execution to the approval (don't authorize the claim — authorize the act)

`POST /verify` approves the action the agent **declared** (its signed `payload`,
including the `amount`). It does not and cannot see what your executor actually
does next. So an approval, on its own, says *"this agent was allowed to do the
thing it described"* — not *"this exact transaction may settle."*

**The executor MUST close that gap.** Before performing the guarded side effect
(moving money, calling the payment rail, etc.), re-present the approval to
`POST /verify-token` with the **exact** action parameters and `consume: true`,
and proceed only if the response is `valid: true`.

This turns "approve $10 / execute $10,000" into a hard failure.

## The rule

```
verdict = POST /verify-token {
  approval_token,                 # from the /verify response
  agent_id,                       # cross-checked against the token
  action_type, payload,           # the EXACT values that were signed/approved
  nonce, timestamp, sig_version,
  consume: true                   # single-use: one approval = one execution
}
proceed only if verdict.valid === true
```

Each guard does one job:

| Field | What it proves | Failure → `valid:false` reason |
|---|---|---|
| `approval_token` | the server issued this approval, unforged, unexpired | "invalid, tampered, or expired" |
| `action_type`+`payload`+`nonce`+`timestamp` | the token authorizes **this** action — a tampered `amount` recomputes a different hash | "action hash mismatch" (`action_hash_matches:false`) |
| `agent_id` | the token belongs to the acting agent | "agent_id does not match" |
| `consume:true` | the approval hasn't already been spent | "Token already used (single-use)" |

If `/verify-token` is unreachable, errors, or returns `valid:false` for **any**
reason — **do not execute.** Fail closed. (When `consume:true` and the cache is
offline, the server itself returns `valid:false` rather than allow an
unenforceable double-spend.)

## Why you must retain the signed params

The action hash is recomputed from `action_type`, `payload`, `nonce`, and
`timestamp` — so the executor needs the same values the agent signed. Build the
`/verify` request with `build_signed_verify_request(...)` (it returns the body
including `nonce` and `timestamp`) and keep that body alongside the
`approval_token` you get back.

```python
import requests
from api.agent_client import build_signed_verify_request

body = build_signed_verify_request(
    agent_id=agent_id, signing_key=sk,
    action_type="financial_transaction",
    payload={"amount": "10.00", "currency": "USD", "recipient": "acct_123"},
)
approved = requests.post(f"{API}/verify", json=body, timeout=30)
if approved.status_code != 200:
    raise SystemExit("not approved — do not execute")
token = approved.json()["approval_token"]

# ── before moving money, bind the execution to the approval ──
gate = requests.post(f"{API}/verify-token", json={
    "approval_token": token,
    "agent_id": body["agent_id"],
    "action_type": body["action_type"],
    "payload": body["payload"],          # the exact approved payload
    "nonce": body["nonce"],
    "timestamp": body["timestamp"],
    "sig_version": body["sig_version"],
    "consume": True,                      # single-use
}, timeout=30).json()

if not gate.get("valid"):
    raise SystemExit(f"execution blocked: {gate.get('reason')}")

settle_payment(body["payload"])          # safe: bound + single-use
```

A second attempt to settle with the same approval returns
`valid:false, "Token already used (single-use)"`, and any change to the payload
(e.g. a different amount) returns `valid:false, action_hash_matches:false`.

See also [`REQUEST_SIGNING.md`](REQUEST_SIGNING.md) for producing the `/verify`
signature.
