"""Who is asking to spend authority, established from trusted credentials.

The distinction this module exists to enforce
---------------------------------------------
``executor_reference`` is a **caller-supplied string**. It names an
operation so humans and logs can follow it. It is not identity, and
anyone who has seen one can type it.

The executor's *identity* comes from the authenticated API key: which
key, which organisation, which scopes. That is server-side state the
caller cannot choose. From it we derive an
``executor_binding_digest``, which is what a grant is bound to at
issuance and what consumption compares.

So copying somebody's ``executor_reference`` gains an attacker nothing:
the binding is derived from the credential they do not have.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from typing import Any, Final
from uuid import UUID

from api import jcs

#: Versioned preimage identifier for the executor binding digest.
EXECUTOR_BINDING_FORMAT: Final[str] = "inntris-executor-binding-v1"

#: Scope an API key must hold to consume execution authority. ``admin``
#: satisfies it, matching the existing require_api_scope convention.
EXECUTE_SCOPE: Final[str] = "execute"

#: Scopes accepted for consuming authority. ``write`` is included because
#: existing service keys that already drive /verify-token hold it, and
#: this phase must not lock out callers that legitimately execute today.
CONSUME_SCOPES: Final[frozenset[str]] = frozenset({EXECUTE_SCOPE, "write", "admin"})

#: Environments in which a synthetic, organisation-wide executor identity is
#: tolerated. Production is deliberately absent.
_NON_PRODUCTION_ENVIRONMENTS: Final[frozenset[str]] = frozenset({"development", "test", "ci"})


class ExecutorAuthError(PermissionError):
    """The caller is not entitled to consume authority in this context."""


def executor_binding_digest(
    *,
    organisation_id: UUID | str,
    api_key_id: UUID | str,
) -> str:
    """The digest a grant is bound to, derived only from trusted identity.

    Deliberately excludes every caller-supplied value. Two different API
    keys in one organisation produce different bindings, so a grant issued
    for one executor cannot be spent by another.
    """
    return jcs.sha256_hex(
        {
            "format": EXECUTOR_BINDING_FORMAT,
            "organisation_id": str(organisation_id),
            "api_key_id": str(api_key_id),
        }
    )


@dataclass(frozen=True, slots=True)
class AuthenticatedExecutorContext:
    """An executor established from credentials, never from the request body."""

    organisation_id: UUID
    api_key_id: str
    scopes: frozenset[str]
    binding_digest: str
    #: Caller-supplied operation label. Carried for audit; never trusted.
    executor_reference: str | None = None

    @property
    def may_consume(self) -> bool:
        return bool(self.scopes & CONSUME_SCOPES)

    def require_consume(self) -> None:
        if not self.may_consume:
            raise ExecutorAuthError(
                "API key requires one of "
                f"{', '.join(sorted(CONSUME_SCOPES))} to consume execution authority"
            )

    def owns_organisation(self, organisation_id: UUID | str) -> bool:
        return str(self.organisation_id) == str(organisation_id)


def _normalise_scopes(scopes: Any) -> frozenset[str]:
    if not scopes:
        return frozenset({"read"})
    if isinstance(scopes, (list, tuple, set, frozenset)):
        return frozenset(str(s).strip().lower() for s in scopes if str(s).strip())
    text = str(scopes).strip().lower()
    return frozenset({text}) if text else frozenset({"read"})


def executor_context_from_auth(
    auth: dict[str, Any],
    *,
    executor_reference: str | None = None,
    environment: str | None = None,
) -> AuthenticatedExecutorContext:
    """Derive the executor context from an authenticated API-key record.

    ``auth`` is the dict the existing ``verify_api_key`` dependency
    returns. The API key's own identity is what binds. A context with no
    key identity is refused outside development: binding to the
    organisation alone would make every key in it one executor, and the
    whole point of the binding is that it distinguishes them.
    """
    organisation_id = auth.get("org_id")
    if organisation_id is None:
        raise ExecutorAuthError("authenticated context carries no organisation")

    api_key_id = auth.get("api_key_id") or auth.get("key_id")
    if not api_key_id:
        # Refuse rather than collapsing every key in an organisation into one
        # executor identity. That fallback would make two production keys
        # indistinguishable, so one could spend the other's grant.
        environment = (
            (environment if environment is not None else os.getenv("ENVIRONMENT", "development"))
            .strip()
            .lower()
        )
        if environment not in _NON_PRODUCTION_ENVIRONMENTS:
            raise ExecutorAuthError(
                "authenticated context carries no API key identity; execution "
                "authority cannot be bound to an organisation alone"
            )
        api_key_id = f"org-default:{organisation_id}"

    digest = executor_binding_digest(organisation_id=organisation_id, api_key_id=api_key_id)
    return AuthenticatedExecutorContext(
        organisation_id=(
            organisation_id if isinstance(organisation_id, UUID) else UUID(str(organisation_id))
        ),
        api_key_id=str(api_key_id),
        scopes=_normalise_scopes(auth.get("scopes")),
        binding_digest=digest,
        executor_reference=executor_reference,
    )


def binding_matches(context: AuthenticatedExecutorContext, stored_digest: str) -> bool:
    """Constant-shape comparison of the authenticated binding to the grant's."""
    return secrets.compare_digest(context.binding_digest, stored_digest)
