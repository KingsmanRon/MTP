"""POST /authority/evaluate and POST /authority/consume.

Both are thin. They authenticate, derive trusted identity, and call the
same services the legacy routes call. No decision logic lives here.

What these endpoints refuse to take from the caller
---------------------------------------------------
Organisation, principal and any verification status are derived from the
authenticated API key and the server's own agent record. The request may
name an agent and carry an *opaque reference* to external authority; it
may not assert who it is or what has been verified.

Possession of a grant id is not authority. Consumption requires the
unforgeable token AND authentication as the executor the grant was bound
to at issuance.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from api.core.authority.authority import DelegatedAuthorityClaim
from api.core.authority.decision import Decision
from api.services.authority_service import (
    AuthorityConsumptionService,
    AuthorityEvaluationService,
)
from api.services.executor_context import ExecutorAuthError, executor_context_from_auth

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/authority", tags=["Execution Authority"])


class AuthorityClaimBody(BaseModel):
    """An opaque pointer at external delegated-authority evidence.

    A claim, not a conclusion: it names an issuer and a reference, and a
    configured provider resolves it server-side. There is deliberately no
    field here for a verification status.
    """

    model_config = ConfigDict(strict=False)

    issuer: str = Field(..., min_length=1, max_length=512)
    external_reference_id: str = Field(..., min_length=1, max_length=512)
    evidence: dict[str, Any] = Field(default_factory=dict)


class EvaluateRequest(BaseModel):
    """Service-authenticated evaluation request.

    There is deliberately no ``signed_action_hash`` field. That name means
    "the request hash an agent signed and Core verified"; this surface
    verifies no agent signature, so accepting a caller's value would give
    one field two meanings and let an unverified assertion reach a public
    receipt. Agent-signed flows use ``POST /verify``.
    """

    model_config = ConfigDict(strict=False)

    agent_id: UUID = Field(..., description="Principal this act belongs to")
    action_type: str = Field(..., min_length=1, max_length=100)
    payload: dict[str, Any] = Field(default_factory=dict)
    issuance_ref: str = Field(
        ...,
        min_length=1,
        max_length=512,
        description=(
            "Stable caller reference making issuance idempotent. The same "
            "reference with identical material returns the original grant; "
            "with changed material it is a conflict."
        ),
    )
    nonce: str | None = Field(
        None,
        max_length=64,
        description=(
            "Caller-chosen uniqueness token. It participates in "
            "execution_action_hash, so two acts differing only by nonce are "
            "different acts."
        ),
    )
    timestamp: str | None = Field(
        None,
        description=(
            "ISO-8601 instant with an explicit UTC offset, saying when the act "
            "occurred. It is a security input: it is fed to the Core freshness "
            "check as the decision instant, exactly as POST /verify does. A "
            "malformed or naive value is refused rather than replaced by server "
            "time. Omit it and server time is authoritative."
        ),
    )
    delegated_authority: AuthorityClaimBody | None = None
    executor_reference: str | None = Field(
        None,
        max_length=512,
        description=(
            "Operation label for audit only. Executor identity comes from the "
            "authenticated credential; this field proves nothing."
        ),
    )


class ConsumeRequest(BaseModel):
    model_config = ConfigDict(strict=False)

    authority_token: str = Field(..., min_length=1)
    agent_id: UUID
    action_type: str = Field(..., min_length=1, max_length=100)
    payload: dict[str, Any] = Field(default_factory=dict)
    execution_ref: str = Field(
        ...,
        min_length=1,
        max_length=512,
        description="Stable executor reference. Required: a consumption that cannot be recovered is unanswerable after a lost response.",
    )
    executor_reference: str | None = Field(None, max_length=512)


def _executor_or_403(auth: dict[str, Any], executor_reference: str | None):
    try:
        return executor_context_from_auth(auth, executor_reference=executor_reference)
    except ExecutorAuthError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc


def register(app, *, get_db, require_api_scope, get_agent_or_404, server_secret_provider):
    """Attach the authority routes to the existing application.

    Dependencies are injected rather than imported so this module does not
    reach back into the legacy module and create an import cycle.
    """

    @router.post("/evaluate", status_code=status.HTTP_200_OK)
    async def evaluate_authority(
        body: EvaluateRequest,
        database=Depends(get_db),
        auth: dict = Depends(require_api_scope("write")),
    ) -> dict[str, Any]:
        executor = _executor_or_403(auth, body.executor_reference)
        agent = await get_agent_or_404(database, body.agent_id)

        if str(agent.org_id) != str(auth["org_id"]):
            # Do not disclose that the agent exists in another organisation.
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")

        claim = (
            DelegatedAuthorityClaim(
                issuer=body.delegated_authority.issuer,
                external_reference_id=body.delegated_authority.external_reference_id,
                evidence=body.delegated_authority.evidence,
            )
            if body.delegated_authority is not None
            else None
        )

        service = AuthorityEvaluationService(
            database, server_secret=server_secret_provider()
        )

        # The SAME live state /verify reads, so Core sees the real counts
        # rather than defaults. The authoritative rate-limit enforcement is
        # the atomic reserve-and-increment inside issuance, which holds
        # regardless; this makes the Core pre-check meaningful too, and
        # keeps the two surfaces feeding the shared evaluation identically.
        now = datetime.now(UTC)
        minute_count, _ = await database.get_rate_limit_count(
            agent.id, "minute", now.replace(second=0, microsecond=0)
        )
        daily_spend = await database.get_daily_spend(agent.id)
        registered_policy = await database.get_active_agent_policy(agent.id)

        result = await service.evaluate(
            agent=agent,
            action_type=body.action_type,
            payload=body.payload,
            executor=executor,
            issuance_ref=body.issuance_ref,
            # Deliberately not settable by the caller. This surface is
            # service-authenticated, not agent-signed, so it has verified no
            # agent signature and must not publish one.
            verified_signed_action_hash=None,
            nonce=body.nonce,
            timestamp=body.timestamp,
            authority_claim=claim,
            daily_spend=daily_spend,
            minute_request_count=minute_count,
            registered_policy=registered_policy,
        )

        response: dict[str, Any] = {
            "decision": result.decision.value,
            "reasons": [reason.value for reason in result.reasons],
            "execution_action_hash": result.execution_action_hash,
            "policy_snapshot_format": result.policy_snapshot_format,
            "policy_snapshot_digest": result.policy_snapshot_digest,
            "policy_revision": result.policy_revision,
        }
        if result.decision is Decision.ALLOW and result.authorises_execution:
            response.update(
                {
                    "grant_id": str(result.grant_id),
                    "authority_token": result.authority_token,
                    "expires_at": result.expires_at.isoformat().replace("+00:00", "Z"),
                }
            )
        else:
            # A BLOCK, or an ALLOW that produced no usable authority, never
            # carries a token. There is no partial success here.
            response["grant_id"] = None
            response["authority_token"] = None
        if result.detail:
            response["detail"] = result.detail
        return response

    @router.post("/consume", status_code=status.HTTP_200_OK)
    async def consume_authority(
        body: ConsumeRequest,
        database=Depends(get_db),
        auth: dict = Depends(require_api_scope("write")),
    ) -> dict[str, Any]:
        executor = _executor_or_403(auth, body.executor_reference)
        agent = await get_agent_or_404(database, body.agent_id)
        if str(agent.org_id) != str(auth["org_id"]):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")

        service = AuthorityConsumptionService(
            database, server_secret=server_secret_provider()
        )
        try:
            result = await service.consume(
                authority_token=body.authority_token,
                executor=executor,
                agent=agent,
                action_type=body.action_type,
                payload=body.payload,
                execution_ref=body.execution_ref,
            )
        except ExecutorAuthError as exc:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)
            ) from exc

        return {
            "outcome": result.outcome.value,
            "may_execute": result.may_execute,
            "grant_id": str(result.grant_id) if result.grant_id else None,
            "consumption_audit_id": (
                str(result.consumption_audit_id) if result.consumption_audit_id else None
            ),
            "execution_ref": result.execution_ref,
            "reason": (
                result.rejection_reason.value if result.rejection_reason else None
            ),
        }

    app.include_router(router)
    return router


__all__ = [
    "AuthorityClaimBody",
    "ConsumeRequest",
    "EvaluateRequest",
    "register",
    "router",
]
