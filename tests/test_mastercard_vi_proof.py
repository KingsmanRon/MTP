"""Phase 6 — the seven headline cases, in CI, against real persistence.

Gated exactly like the other database integration tests: they need
``INNTRIS_DB_INTEGRATION=1`` and a ``DATABASE_URL`` pointing at a database
migrated to head. Nothing is simulated away — the same authority store,
the same evaluation and consumption services, the same policy engine.

Also gated on the pinned Verifiable Intent reference implementation. A
proof that silently skipped its own cryptography when the dependency was
absent would report green while proving nothing, so the pin is checked
and a mismatched build fails rather than skips.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

pytest.importorskip("asyncpg")
pytest.importorskip(
    "verifiable_intent",
    reason=(
        "the VI proof needs the pinned reference implementation: "
        "pip install -e '.[dev,vi-proof]'"
    ),
)

from api.database import Database  # noqa: E402
from api.receipts.v3 import load_evidence_signing_key  # noqa: E402
from scripts.mastercard_vi.cases import HEADLINE_CASES  # noqa: E402
from scripts.mastercard_vi.evidence import upstream_provenance  # noqa: E402
from scripts.mastercard_vi.harness import ProofHarness  # noqa: E402

INTEGRATION_ENABLED = os.getenv("INNTRIS_DB_INTEGRATION") == "1"
DATABASE_URL = os.getenv("DATABASE_URL", "")

pytestmark = pytest.mark.skipif(
    not (INTEGRATION_ENABLED and DATABASE_URL),
    reason="the VI proof requires INNTRIS_DB_INTEGRATION=1 and DATABASE_URL",
)


@pytest.fixture
async def database() -> AsyncIterator[Database]:
    db = await Database.create(DATABASE_URL, min_size=2, max_size=8)
    try:
        yield db
    finally:
        await db.close()


@pytest.fixture
def harness(database: Database, tmp_path: Path) -> ProofHarness:
    return ProofHarness(database, journal_path=str(tmp_path / "journal.sqlite"))


@pytest.fixture
def signing_key():
    return load_evidence_signing_key(environment="test")


class TestUpstreamPin:
    def test_the_installed_vi_build_is_the_pinned_one(self) -> None:
        """Which implementation verified the chain is the whole claim.

        An evidence file naming a commit that is not the code that ran
        would be the one lie this proof cannot afford.
        """
        provenance = upstream_provenance()
        assert provenance["matches_pin"], (
            f"pinned {provenance['pinned_commit']}, installed "
            f"{provenance['installed_commit']}"
        )


@pytest.mark.parametrize("case", HEADLINE_CASES, ids=lambda case: case.__name__)
class TestHeadlineCases:
    async def test_case_holds_every_assertion(
        self, case, harness: ProofHarness, tmp_path: Path, signing_key
    ) -> None:
        """Each case asserts its own expectations; this surfaces them.

        The evidence file is written to a temporary directory: CI proves
        the cases behave, and the committed evidence pack is produced by
        the documented command rather than by a test run.
        """
        outcome = await case(harness, tmp_path / "evidence", signing_key)

        assert outcome.checks, "a case that asserts nothing proves nothing"
        assert outcome.passed, "; ".join(outcome.failures)
        assert outcome.evidence_path is not None
        assert outcome.evidence_path.exists()


class TestTheThreeClaims:
    """The cases read together, which is how the proof is meant to be read."""

    async def test_a_vi_valid_action_is_blocked_by_stricter_organisation_policy(
        self, harness: ProofHarness, tmp_path: Path, signing_key
    ) -> None:
        """Claim 2: the BLOCK is Inntris's, not a broken credential."""
        from scripts.mastercard_vi.cases import case_2, case_3

        for case in (case_2, case_3):
            outcome = await case(harness, tmp_path / "evidence", signing_key)
            assert outcome.vi == "PASS"
            assert outcome.policy == "BLOCK"
            assert outcome.grant == "none"
            assert outcome.passed, "; ".join(outcome.failures)

    async def test_an_allow_becomes_bounded_execution_authority(
        self, harness: ProofHarness, tmp_path: Path, signing_key
    ) -> None:
        """Claim 3: bound to the exact action and the exact executor."""
        from scripts.mastercard_vi.cases import case_4, case_5, case_6, case_7

        for case in (case_4, case_5, case_6, case_7):
            outcome = await case(harness, tmp_path / "evidence", signing_key)
            assert outcome.passed, "; ".join(outcome.failures)

    async def test_the_mock_executor_never_acted_more_than_once_per_reference(
        self, harness: ProofHarness, tmp_path: Path, signing_key
    ) -> None:
        """Across every case: one side effect per execution_ref, at most."""
        for case in HEADLINE_CASES:
            await case(harness, tmp_path / "evidence", signing_key)

        references = [
            invocation["execution_ref"] for invocation in harness.side_effect.invocations
        ]
        assert len(references) == len(set(references)), (
            f"a reference was executed more than once: {references}"
        )
        for reference in set(references):
            assert harness.journal.side_effect_count(reference) == 1
