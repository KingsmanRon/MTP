# Webhook operations

This runbook covers tenant webhook configuration, receiver verification,
rotation, delivery investigation, and dead letter handling.

## Destination requirements

The destination must be a public HTTPS URL on port 443 with a resolvable public
hostname. Inntris rejects redirects and any destination that resolves to a
loopback, private, link local, multicast, unspecified, or reserved address.
The receiver must return a 2xx response and keep its response body at or below
64 KiB.

## Initial configuration

Use an organisation API key with `admin` scope:

```bash
curl -X PATCH "$INNTRIS_API_URL/admin/organization" \
  -H "X-API-Key: $INNTRIS_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"webhook_url":"https://hooks.example.com/inntris"}'
```

When the organisation has no signing secret, the response includes
`webhook_signing_secret` and `webhook_secret_version`. Store the secret in the
receiver secret manager immediately. Inntris does not expose it again.

## Receiver verification

Verify the HMAC against the exact raw request body and the signed routing
headers before parsing JSON. Compare the expected and received values in
constant time.

```python
import hashlib
import hmac
import json


def verify_inntris_webhook(raw_body: bytes, headers: dict[str, str], secret: str) -> bool:
    body = raw_body.decode("utf-8")
    signed = json.dumps(
        {
            "body": body,
            "delivery_id": headers["X-Inntris-Delivery-ID"],
            "event": headers["X-Inntris-Event"],
            "secret_version": int(headers["X-Inntris-Secret-Version"]),
            "version": 1,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    expected = hmac.new(
        secret.encode("utf-8"), signed.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    received_signature = headers["X-Inntris-Signature"]
    return hmac.compare_digest(expected, received_signature)
```

The relevant headers are:

| Header | Meaning |
|---|---|
| `X-Inntris-Signature` | Lowercase hexadecimal HMAC SHA256 of the canonical signed envelope |
| `X-Inntris-Signature-Algorithm` | `hmac-sha256` |
| `X-Inntris-Signature-Version` | Canonical signed envelope version, currently `1` |
| `X-Inntris-Secret-Version` | Organisation secret version used for signing |
| `X-Inntris-Delivery-ID` | Stable delivery identifier used across retries |
| `X-Inntris-Event` | Event name |

Deduplicate side effects using `X-Inntris-Delivery-ID`. A retry uses the same
delivery identifier. The delivery ID, event and secret version are covered by
the HMAC, so changing a deduplication or routing header invalidates the request.

## Delivery states

List recent deliveries:

```bash
curl "$INNTRIS_API_URL/admin/organization/webhook-deliveries?limit=50" \
  -H "X-API-Key: $INNTRIS_API_KEY"
```

Filter dead letters:

```bash
curl "$INNTRIS_API_URL/admin/organization/webhook-deliveries?status=dead_letter&limit=100" \
  -H "X-API-Key: $INNTRIS_API_KEY"
```

`pending`, `delivering`, and `retrying` are active states. `delivered` is
terminal success. `dead_letter` is terminal failure and includes the last
status and bounded error text. Retryable failures receive no more than three
cumulative attempts. The recovery loop resumes due deliveries after an API
restart.

Investigate a dead letter by checking the destination certificate, DNS answers,
HTTP status, response size, and whether the receiver changed location. Fix the
receiver or configure a new safe URL. There is intentionally no automatic
redelivery of a terminal dead letter; replay must be an explicit, audited
operator action.

## Secret rotation

The rotation endpoint returns the new secret exactly once and increments its
version:

```bash
curl -X POST "$INNTRIS_API_URL/admin/organization/webhook-secret/rotate" \
  -H "X-API-Key: $INNTRIS_API_KEY"
```

Rotation takes effect immediately. Coordinate the receiver update in a quiet
window and monitor delivery state. If zero message loss is required, first
drain all active deliveries, temporarily clear the webhook URL, rotate and
install the receiver secret, then restore the URL. Events produced while the
URL is cleared do not enqueue webhook deliveries, so schedule this as a short
maintenance window or provide a separate event reconciliation path.

## Disabling delivery

Clear the destination without deleting the encrypted tenant secret:

```bash
curl -X PATCH "$INNTRIS_API_URL/admin/organization" \
  -H "X-API-Key: $INNTRIS_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"webhook_url":null}'
```

Reenabling a destination reuses the current signing secret. Rotate first if the
receiver no longer has that secret.
