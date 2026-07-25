#!/usr/bin/env python3
"""Print the Python-side vectors asserted by the Solidity parity test.

Invariant 3 requires Python and Solidity to agree on Merkle roots and proofs.
``test/contracts/PolicyBoundLeafParity.t.sol`` pins that agreement by hard-coding
values produced here, so the Solidity suite is checking the real anchoring
implementation rather than a synthetic tree of its own construction.

Run this and paste the output into that file whenever the action-hash preimage
or the tree construction changes. If the constants there ever stop matching
this output, one of the two implementations has drifted — which is exactly the
failure the parity test exists to catch.

    python scripts/generate_leaf_parity_vectors.py
"""

from __future__ import annotations

import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from api.crypto import CryptoService  # noqa: E402
from workers.anchor_worker import (  # noqa: E402
    compute_merkle_proof,
    compute_merkle_root,
    keccak256,
)

AGENT_ID = "4f0e4fd5-5e2f-4e95-a2d5-78b0a7b0d66a"
ACTION_TYPE = "production_deployment"
TIMESTAMP = datetime(2026, 7, 25, 12, 0, 0, tzinfo=UTC)
POLICY_A = "1" * 64
POLICY_B = "2" * 64
LEAF_COUNT = 3  # odd, so final-node duplication is exercised


def action_hash(seq: int, policy_hash: str) -> str:
    return CryptoService.compute_action_hash(
        agent_id=AGENT_ID,
        action_type=ACTION_TYPE,
        payload={"seq": seq},
        nonce=f"nonce-{seq}",
        timestamp=TIMESTAMP,
        registered_policy_hash=policy_hash,
    )


def main() -> int:
    leaves = [action_hash(i, POLICY_A) for i in range(LEAF_COUNT)]
    root = compute_merkle_root(leaves)
    proof = compute_merkle_proof(leaves, 0)
    depth1_left = keccak256(bytes.fromhex(leaves[0]) + bytes.fromhex(leaves[1]))

    for i, leaf in enumerate(leaves):
        print(f"LEAF_{i}              = 0x{leaf};")
    print(f"ROOT                = 0x{root};")
    print(f"DEPTH_1_LEFT        = 0x{depth1_left.hex()};")
    print(f"PROOF_0_DEPTH_1     = 0x{proof[1]['hash']};")
    print(f"LEAF_0_OTHER_POLICY = 0x{action_hash(0, POLICY_B)};")
    print()
    print("proof positions for leaf 0:", [node["position"] for node in proof])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
