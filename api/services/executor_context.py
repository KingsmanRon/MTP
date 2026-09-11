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

#: Separator for an action-scoped execute grant: ``execute:financial_transaction``
#: permits consuming authority for that action class and no other.
#:
#: Phase 7A, Gate 5. A key that can execute *anything* its organisation can
#: authorise is more privilege than any single executor needs. Scoping is
#: opt-in per key and additive: a key carrying no ``execute:<action>`` entry
#: behaves exactly as it does today, so nothing existing is locked out, and a
#: key carrying one is narrowed to it.
EXECUTE_SCOPE_SEPARATOR: Final[str] = ":"

#: Requires a dedicated ``execute`` (or ``execute:<action>``) scope rather
#: than accepting the broad ``write``. Off by default so existing service
#: keys keep working; the release record states whether it is on.
REQUIRE_EXECUTE_SCOPE_ENV: Final[str] = "INNTRIS_REQUIRE_EXECUTE_SCOPE"

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
    def action_scopes(self) -> frozenset[str]:
        """Action classes this key is narrowed to, if any.

        Empty means "not narrowed", which is today's behaviour and remains
        the default. Non-empty means this key may consume authority for
        exactly these action classes.
        """
        return frozenset(
            scope.split(EXECUTE_SCOPE_SEPARATOR, 1)[1].strip()
            for scope in self.scopes
            if scope.startswith(EXECUTE_SCOPE + EXECUTE_SCOPE_SEPARATOR)
            and scope.split(EXECUTE_SCOPE_SEPARATOR, 1)[1].strip()
        )

    @property
    def may_consume(self) -> bool:
        # An action-scoped key holds no bare ``execute``, so recognise it
        # here too -- otherwise narrowing a key would remove its ability to
        # consume anything at all.
        return bool(self.scopes & CONSUME_SCOPES) or bool(self.action_scopes)

    def require_consume(self, *, require_execute_scope: bool | None = None) -> None:
        """Refuse a key not entitled to consume execution authority.

        With ``require_execute_scope`` the broad ``write`` is not enough: the
        key must hold ``execute`` or ``execute:<action>``. That is the
        least-privilege posture, and it is configurable rather than forced
        because existing service keys legitimately drive ``/verify-token``
        today and this phase must not lock them out mid-release.
        """
        strict = (
            require_execute_scope
            if require_execute_scope is not None
            else _require_execute_scope_configured()
        )
        if strict:
            if EXECUTE_SCOPE in self.scopes or self.action_scopes:
                return
            raise ExecutorAuthError(
                f"API key requires the dedicated '{EXECUTE_SCOPE}' scope to "
                f"consume execution authority ({REQUIRE_EXECUTE_SCOPE_ENV} is on)"
            )
        if not self.may_consume:
            raise ExecutorAuthError(
                "API key requires one of "
                f"{', '.join(sorted(CONSUME_SCOPES))} to consume execution authority"
            )

    def require_action(self, action_type: str) -> None:
        """Refuse an action class this key was not provisioned for.

        A key with no ``execute:<action>`` entry is unnarrowed and passes.
        A narrowed key passes only for the classes it names -- so an executor
        provisioned for payments cannot be turned on a code release, even
        within its own organisation.
        """
        narrowed = self.action_scopes
        if narrowed and action_type not in narrowed:
            raise ExecutorAuthError(
                f"API key is scoped to {', '.join(sorted(narrowed))} and may not "
                f"consume execution authority for {action_type!r}"
            )

    def owns_organisation(self, organisation_id: UUID | str) -> bool:
        return str(self.organisation_id) == str(organisation_id)


def _require_execute_scope_configured() -> bool:
    return (os.getenv(REQUIRE_EXECUTE_SCOPE_ENV, "") or "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


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
