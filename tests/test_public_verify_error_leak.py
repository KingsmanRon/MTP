"""Tests that GET /public/verify/{record_id} does not leak infra detail.

The DB privilege error path used to return migration numbers, role names,
and table names in the public response body. This test pins the response
to a generic, infra-free string so that regressions surface immediately.
"""
from unittest.mock import AsyncMock, patch

import asyncpg
from fastapi.testclient import TestClient

from api.main import app


client = TestClient(app)


FORBIDDEN_SUBSTRINGS = (
    "migration",
    "role",
    "inntris_worker",
    "inntris_api",
    "DATABASE_URL",
    "merkle_proofs",
    "audit_logs",
    "agents",
)


class TestPublicVerifyErrorLeak:
    def test_privilege_error_returns_generic_503_without_infra_detail(self):
        """An InsufficientPrivilegeError must surface a generic 503 body.

        Asserts the response body contains none of the previously-leaked
        substrings (migration / role / table / env-var names).
        """
        with patch("api.main.db_pool") as mock_pool:
            conn = AsyncMock()
            conn.fetchrow = AsyncMock(
                side_effect=asyncpg.InsufficientPrivilegeError(
                    "permission denied for table merkle_proofs"
                )
            )
            mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=conn)
            mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)

            response = client.get(
                "/public/verify/00000000-0000-0000-0000-000000000001"
            )

        assert response.status_code == 503
        body = response.text
        body_lower = body.lower()
        for needle in FORBIDDEN_SUBSTRINGS:
            assert needle.lower() not in body_lower, (
                f"Public 503 body leaked forbidden substring {needle!r}: {body!r}"
            )
        assert "verification temporarily unavailable" in body_lower
