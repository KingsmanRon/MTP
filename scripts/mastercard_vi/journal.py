"""A durable, restartable execution journal for the proof's mock executor.

This is a **proof component**. It is not a settlement engine and nothing
in Inntris depends on it. It exists so the proof can demonstrate, with a
store that genuinely survives a process restart, the one property that
distinguishes bounded execution authority from a policy API:

    an idempotent authority-consumption response is not a fresh
    instruction to call the external executor again.

State model
-----------
::

    prepared ──► in_progress ──► succeeded
                            ├──► failed_final
                            └──► outcome_unknown ──► succeeded
                                                └──► failed_final

``outcome_unknown`` is where a thrown or timed-out side effect lands. It
blocks automatic retry, because a timeout is not proof that nothing
happened; only an authoritative resolver — a reconciliation path with the
downstream system's own evidence — moves it onwards. That mirrors
``OutcomeState`` in the authority store rather than inventing a second,
looser failure model.

Keyed by ``execution_ref``
--------------------------
The caller generates ``execution_ref`` before its first attempt and
reuses it on every retry. One row per reference, and the row records the
grant, act and executor it was prepared for: a retry that arrives with
the same reference but different material is a conflict, not a retry.

Atomicity is the database's job
-------------------------------
Claiming is a single conditional UPDATE inside an IMMEDIATE transaction,
so two concurrent claimants contend in SQLite rather than in Python.
Exactly one sees ``CLAIMED``.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Final


class ExecutionState(StrEnum):
    """What is known about the side effect for one ``execution_ref``."""

    PREPARED = "prepared"
    IN_PROGRESS = "in_progress"
    SUCCEEDED = "succeeded"
    FAILED_FINAL = "failed_final"
    OUTCOME_UNKNOWN = "outcome_unknown"


#: States from which no further side effect may be attempted automatically.
TERMINAL_STATES: Final[frozenset[ExecutionState]] = frozenset(
    {ExecutionState.SUCCEEDED, ExecutionState.FAILED_FINAL}
)

#: The complete transition table. Anything absent from it is refused.
ALLOWED_TRANSITIONS: Final[dict[ExecutionState, frozenset[ExecutionState]]] = {
    ExecutionState.PREPARED: frozenset({ExecutionState.IN_PROGRESS}),
    ExecutionState.IN_PROGRESS: frozenset(
        {
            ExecutionState.SUCCEEDED,
            ExecutionState.FAILED_FINAL,
            ExecutionState.OUTCOME_UNKNOWN,
        }
    ),
    ExecutionState.OUTCOME_UNKNOWN: frozenset(
        {ExecutionState.SUCCEEDED, ExecutionState.FAILED_FINAL}
    ),
    ExecutionState.SUCCEEDED: frozenset(),
    ExecutionState.FAILED_FINAL: frozenset(),
}


class ClaimOutcome(StrEnum):
    """What a claim attempt did."""

    #: This caller won the claim and is the one that may invoke the side effect.
    CLAIMED = "claimed"
    #: A prior attempt already holds the operation and has not reported back.
    #: No second side effect. This is not an error; it is the guard working.
    ALREADY_IN_PROGRESS = "already_in_progress"
    #: The operation already reached a terminal state. Reconcile, do not repeat.
    ALREADY_FINAL = "already_final"
    #: The outcome is unknown. Blocked until an authoritative resolver decides.
    BLOCKED_UNKNOWN = "blocked_unknown"
    #: Nothing was prepared under this reference.
    NOT_PREPARED = "not_prepared"
    #: The reference exists, but for different grant/act/executor material.
    BINDING_CONFLICT = "binding_conflict"


class JournalError(RuntimeError):
    """The journal was asked for something its state model forbids."""


@dataclass(frozen=True, slots=True)
class ExecutionOperation:
    """One journalled operation, as stored."""

    execution_ref: str
    grant_id: str
    execution_action_hash: str
    executor_binding_digest: str
    state: ExecutionState
    attempts: int
    side_effects: int
    outcome_reference: str | None
    detail: str | None
    prepared_at: str
    updated_at: str

    @property
    def is_final(self) -> bool:
        return self.state in TERMINAL_STATES


@dataclass(frozen=True, slots=True)
class ClaimResult:
    outcome: ClaimOutcome
    operation: ExecutionOperation | None = None

    @property
    def may_invoke_side_effect(self) -> bool:
        """Only a won claim authorises touching the outside world."""
        return self.outcome is ClaimOutcome.CLAIMED


_SCHEMA: Final[str] = """
CREATE TABLE IF NOT EXISTS execution_operations (
    execution_ref            TEXT PRIMARY KEY,
    grant_id                 TEXT NOT NULL,
    execution_action_hash    TEXT NOT NULL,
    executor_binding_digest  TEXT NOT NULL,
    state                    TEXT NOT NULL,
    attempts                 INTEGER NOT NULL DEFAULT 0,
    side_effects             INTEGER NOT NULL DEFAULT 0,
    outcome_reference        TEXT,
    detail                   TEXT,
    prepared_at              TEXT NOT NULL,
    updated_at               TEXT NOT NULL
);
"""


def _now() -> str:
    return datetime.now(UTC).isoformat()


class ExecutionJournal:
    """A SQLite-backed journal. Durable across restarts by construction."""

    def __init__(self, path: str | Path) -> None:
        self._path = str(path)
        with self._connect() as conn:
            conn.executescript(_SCHEMA)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self._path, isolation_level=None, timeout=30)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=FULL")
            yield conn
        finally:
            conn.close()

    # -- step 1: prepare ---------------------------------------------------

    def prepare(
        self,
        *,
        execution_ref: str,
        grant_id: str,
        execution_action_hash: str,
        executor_binding_digest: str,
    ) -> ExecutionOperation:
        """Persist the intent to execute, BEFORE any authority is consumed.

        Idempotent for identical material: re-preparing the same reference
        returns the existing row rather than resetting it, which is what
        makes a crash between prepare and consume recoverable. Re-preparing
        the same reference for *different* material raises, because that
        reference already means something else.
        """
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    "SELECT * FROM execution_operations WHERE execution_ref = ?",
                    (execution_ref,),
                ).fetchone()
                if row is not None:
                    existing = _operation(row)
                    if (
                        existing.grant_id != grant_id
                        or existing.execution_action_hash != execution_action_hash
                        or existing.executor_binding_digest != executor_binding_digest
                    ):
                        raise JournalError(
                            f"execution_ref {execution_ref!r} is already prepared for "
                            "different grant/action/executor material"
                        )
                    conn.execute("COMMIT")
                    return existing
                stamp = _now()
                conn.execute(
                    """
                    INSERT INTO execution_operations (
                        execution_ref, grant_id, execution_action_hash,
                        executor_binding_digest, state, attempts, side_effects,
                        prepared_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, 0, 0, ?, ?)
                    """,
                    (
                        execution_ref,
                        grant_id,
                        execution_action_hash,
                        executor_binding_digest,
                        ExecutionState.PREPARED.value,
                        stamp,
                        stamp,
                    ),
                )
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
        operation = self.get(execution_ref)
        if operation is None:  # pragma: no cover - the insert just committed
            raise JournalError("prepare did not persist")
        return operation

    # -- step 3: atomically claim -----------------------------------------

    def claim(
        self,
        *,
        execution_ref: str,
        grant_id: str,
        execution_action_hash: str,
        executor_binding_digest: str,
    ) -> ClaimResult:
        """Win the right to invoke the side effect exactly once.

        The transition ``prepared -> in_progress`` is a conditional UPDATE
        inside an IMMEDIATE transaction, so concurrent claimants serialise
        in the database. Everything else — already running, already final,
        unknown — is reported without touching the row.
        """
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    "SELECT * FROM execution_operations WHERE execution_ref = ?",
                    (execution_ref,),
                ).fetchone()
                if row is None:
                    conn.execute("COMMIT")
                    return ClaimResult(ClaimOutcome.NOT_PREPARED)

                operation = _operation(row)
                if (
                    operation.grant_id != grant_id
                    or operation.execution_action_hash != execution_action_hash
                    or operation.executor_binding_digest != executor_binding_digest
                ):
                    conn.execute("COMMIT")
                    return ClaimResult(ClaimOutcome.BINDING_CONFLICT, operation)

                claimed = False
                if operation.state is ExecutionState.PREPARED:
                    cursor = conn.execute(
                        """
                        UPDATE execution_operations
                        SET state = ?, attempts = attempts + 1, updated_at = ?
                        WHERE execution_ref = ? AND state = ?
                        """,
                        (
                            ExecutionState.IN_PROGRESS.value,
                            _now(),
                            execution_ref,
                            ExecutionState.PREPARED.value,
                        ),
                    )
                    # rowcount, not total_changes: the question is whether
                    # THIS statement moved the row, and exactly one
                    # concurrent claimant can see a non-zero answer.
                    claimed = cursor.rowcount == 1
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise

        if operation.state is ExecutionState.PREPARED:
            outcome = ClaimOutcome.CLAIMED if claimed else ClaimOutcome.ALREADY_IN_PROGRESS
            return ClaimResult(outcome, self.get(execution_ref))
        if operation.state is ExecutionState.IN_PROGRESS:
            return ClaimResult(ClaimOutcome.ALREADY_IN_PROGRESS, operation)
        if operation.state is ExecutionState.OUTCOME_UNKNOWN:
            return ClaimResult(ClaimOutcome.BLOCKED_UNKNOWN, operation)
        return ClaimResult(ClaimOutcome.ALREADY_FINAL, operation)

    # -- step 5: record the outcome ---------------------------------------

    def record_outcome(
        self,
        *,
        execution_ref: str,
        state: ExecutionState,
        outcome_reference: str | None = None,
        detail: str | None = None,
        side_effect_invoked: bool = False,
    ) -> ExecutionOperation:
        """Move an operation onwards, refusing any undefined transition."""
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    "SELECT * FROM execution_operations WHERE execution_ref = ?",
                    (execution_ref,),
                ).fetchone()
                if row is None:
                    raise JournalError(f"no operation for execution_ref {execution_ref!r}")
                current = _operation(row).state
                if state not in ALLOWED_TRANSITIONS[current]:
                    raise JournalError(
                        f"{current.value} -> {state.value} is not a defined transition"
                    )
                conn.execute(
                    """
                    UPDATE execution_operations
                    SET state = ?,
                        outcome_reference = COALESCE(?, outcome_reference),
                        detail = ?,
                        side_effects = side_effects + ?,
                        updated_at = ?
                    WHERE execution_ref = ?
                    """,
                    (
                        state.value,
                        outcome_reference,
                        detail,
                        1 if side_effect_invoked else 0,
                        _now(),
                        execution_ref,
                    ),
                )
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
        operation = self.get(execution_ref)
        if operation is None:  # pragma: no cover
            raise JournalError("record_outcome did not persist")
        return operation

    def resolve_unknown(
        self,
        *,
        execution_ref: str,
        state: ExecutionState,
        outcome_reference: str | None = None,
        detail: str | None = None,
    ) -> ExecutionOperation:
        """The authoritative resolver's verdict on an unknown outcome.

        Separate from :meth:`record_outcome` only so the proof can show
        that nothing on the ordinary retry path can reach it. An automatic
        retry never resolves an unknown outcome; a reconciliation path
        holding the downstream system's own evidence does.
        """
        if state not in {ExecutionState.SUCCEEDED, ExecutionState.FAILED_FINAL}:
            raise JournalError("an unknown outcome resolves to succeeded or failed_final")
        current = self.get(execution_ref)
        if current is None:
            raise JournalError(f"no operation for execution_ref {execution_ref!r}")
        if current.state is not ExecutionState.OUTCOME_UNKNOWN:
            raise JournalError(
                f"only an unknown outcome is resolvable; this one is {current.state.value}"
            )
        return self.record_outcome(
            execution_ref=execution_ref,
            state=state,
            outcome_reference=outcome_reference,
            detail=detail,
        )

    # -- reading -----------------------------------------------------------

    def get(self, execution_ref: str) -> ExecutionOperation | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM execution_operations WHERE execution_ref = ?",
                (execution_ref,),
            ).fetchone()
        return _operation(row) if row is not None else None

    def side_effect_count(self, execution_ref: str) -> int:
        """How many times the mock side effect actually ran for this reference."""
        operation = self.get(execution_ref)
        return operation.side_effects if operation is not None else 0


def _operation(row: sqlite3.Row) -> ExecutionOperation:
    return ExecutionOperation(
        execution_ref=row["execution_ref"],
        grant_id=row["grant_id"],
        execution_action_hash=row["execution_action_hash"],
        executor_binding_digest=row["executor_binding_digest"],
        state=ExecutionState(row["state"]),
        attempts=row["attempts"],
        side_effects=row["side_effects"],
        outcome_reference=row["outcome_reference"],
        detail=row["detail"],
        prepared_at=row["prepared_at"],
        updated_at=row["updated_at"],
    )
