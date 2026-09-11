"""Proof harness for the Verifiable Intent evidence pack.

A **proof component**, not production code. Nothing in ``api/`` imports
it, and the mock executor and execution journal here settle nothing: they
exist so the proof can demonstrate execution-authority semantics against
a store that genuinely survives a restart.

The entry point is ``scripts/mastercard_vi_proof.py``; see
``docs/proofs/mastercard-vi/README.md`` for how to run it and what the
evidence does and does not prove.
"""

from __future__ import annotations

__all__: list[str] = []
