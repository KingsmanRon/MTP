"""Run the Verifiable Intent proof. One command, offline, deterministic.

    python -m scripts.mastercard_vi_proof

Prints a compact case table and writes one JSON evidence file per case.
Exits non-zero if any assertion fails.

What "offline" means
--------------------
No network call is made during the run, and none to Mastercard ever. The
delegation is signed in-process by the pinned reference implementation
and verified by the Phase-5 connector at ``api/connectors/mastercard_vi``;
the only external system is the PostgreSQL the authority store already
requires.

What "deterministic" means
--------------------------
Same cases, same decisions, same reason codes, every run. It does not
mean byte-identical artefacts: ES256 signatures carry a random nonce and
SD-JWT disclosures carry a random salt. Fixing those would mean patching
the reference implementation's cryptography, and a proof that weakened
the checks it is demonstrating would prove nothing. Each evidence file
therefore records the artefact digest of the run that produced it.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from api.database import Database  # noqa: E402
from api.receipts.v3 import load_evidence_signing_key  # noqa: E402
from scripts.mastercard_vi.cases import HEADLINE_CASES, CaseOutcome  # noqa: E402
from scripts.mastercard_vi.evidence import upstream_provenance  # noqa: E402
from scripts.mastercard_vi.harness import ProofHarness  # noqa: E402

DEFAULT_EVIDENCE_DIR = REPO_ROOT / "docs" / "proofs" / "mastercard-vi" / "evidence"

_COLUMNS = ("case", "VI", "Inntris policy", "grant", "consume", "evidence")


class ProofFailure(RuntimeError):
    """At least one case did not behave as the proof asserts it must."""


def _render_table(outcomes: list[CaseOutcome]) -> str:
    rows = [
        (
            outcome.title,
            outcome.vi,
            outcome.policy,
            outcome.grant,
            outcome.consume,
            outcome.evidence_path.name if outcome.evidence_path else "-",
        )
        for outcome in outcomes
    ]
    widths = [
        max(len(_COLUMNS[i]), *(len(row[i]) for row in rows)) if rows else len(_COLUMNS[i])
        for i in range(len(_COLUMNS))
    ]

    def line(values: tuple[str, ...]) -> str:
        return " | ".join(value.ljust(widths[i]) for i, value in enumerate(values))

    out = [line(_COLUMNS), "-+-".join("-" * width for width in widths)]
    out.extend(line(row) for row in rows)
    return "\n".join(out)


async def run(evidence_dir: Path, database_url: str) -> list[CaseOutcome]:
    """Run every headline case against a real authority database."""
    journal_path = evidence_dir.parent / "execution-journal.sqlite"
    journal_path.parent.mkdir(parents=True, exist_ok=True)
    # A fresh journal per run: the proof asserts side-effect counts, and a
    # journal carrying a previous run's operations would answer for it.
    journal_path.unlink(missing_ok=True)

    database = await Database.create(database_url, min_size=2, max_size=8)
    try:
        harness = ProofHarness(database, journal_path=str(journal_path))
        key = load_evidence_signing_key(environment="test")
        outcomes: list[CaseOutcome] = []
        for case in HEADLINE_CASES:
            # Each case builds its own organisation and agent, so no spend
            # window, rate window or consumed grant carries between them.
            outcomes.append(await case(harness, evidence_dir, key))
        return outcomes
    finally:
        await database.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="mastercard_vi_proof",
        description="Verifiable Intent proof: seven cases, seven evidence files.",
    )
    parser.add_argument(
        "--evidence-dir",
        type=Path,
        default=DEFAULT_EVIDENCE_DIR,
        help=f"where to write evidence files (default: {DEFAULT_EVIDENCE_DIR})",
    )
    parser.add_argument(
        "--database-url",
        default=os.getenv("DATABASE_URL", ""),
        help="PostgreSQL DSN migrated to head (default: $DATABASE_URL)",
    )
    args = parser.parse_args(argv)

    if not args.database_url:
        print(
            "DATABASE_URL is required: the proof runs against the real "
            "authority persistence, not a simulation.",
            file=sys.stderr,
        )
        return 2

    provenance = upstream_provenance()
    if not provenance["matches_pin"]:
        # The whole proof rests on which implementation verified the chain.
        print(
            "The installed verifiable-intent build is not the one the "
            "connector is pinned to (pinned "
            f"{provenance['pinned_commit']} / {provenance['pinned_package_version']}, "
            f"installed {provenance['installed_commit']} / "
            f"{provenance['installed_version']}). Install it with:\n"
            "  pip install -e '.[mastercard-vi]'",
            file=sys.stderr,
        )
        return 2

    outcomes = asyncio.run(run(args.evidence_dir, args.database_url))

    print()
    print("Verifiable Intent proof — Inntris Core")
    print("connector: api/connectors/mastercard_vi (Phase 5)")
    print(
        f"upstream:  {provenance['repository']}@{provenance['pinned_commit'][:12]} "
        f"(spec {provenance['spec_revision']}, {provenance['spec_date']})"
    )
    print()
    print(_render_table(outcomes))
    print()

    failed = [outcome for outcome in outcomes if not outcome.passed]
    for outcome in failed:
        print(f"FAILED {outcome.case_id}:", file=sys.stderr)
        for failure in outcome.failures:
            print(f"  - expected: {failure}", file=sys.stderr)

    total_checks = sum(len(outcome.checks) for outcome in outcomes)
    if failed:
        print(
            f"\n{len(failed)} of {len(outcomes)} cases failed "
            f"({total_checks} assertions evaluated).",
            file=sys.stderr,
        )
        return 1

    print(
        f"{len(outcomes)} cases passed, {total_checks} assertions held. "
        f"Evidence written to {args.evidence_dir}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
