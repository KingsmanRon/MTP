// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/AnchorRegistry.sol";

/// @title Python/Solidity parity for policy-bound anchored leaves (B2.5)
/// @notice Invariant 3 requires Python and Solidity to produce identical roots
///         and proofs. The other suites build synthetic leaves, which proves
///         the tree walk but not that it agrees with the implementation that
///         actually anchors. Every constant below was produced by Python —
///         `CryptoService.compute_action_hash` under signing envelope v3, then
///         `workers.anchor_worker.compute_merkle_root` / `compute_merkle_proof`
///         — and is asserted here unchanged.
///
///         The leaves carry the v3 preimage, which binds
///         `registered_policy_hash`. That is an off-chain change only: the
///         AnchorRegistry is untouched and needs no redeploy, because a leaf is
///         opaque bytes32 to the contract. What these tests pin is that the
///         off-chain change did not break the on-chain verification path.
///
///         Regenerate these constants with:
///           python scripts/generate_leaf_parity_vectors.py
contract PolicyBoundLeafParityTest is Test {
    AnchorRegistry internal registry;

    address internal admin = address(0xA11CE);
    address internal submitter = address(0xB0B);

    // Three leaves — an odd count, so the tree exercises final-node
    // duplication, which is the rule most likely to diverge between
    // implementations.
    bytes32 internal constant LEAF_0 =
        0x2cb722cd85514fade08eaffa4c78fbd1419ce723e9226bfbfec79dd963caf484;
    bytes32 internal constant LEAF_1 =
        0xa4f56e81d5d46ef44e16df33e6d14f11e32b1bf4dc2daeb580a0bd1ed983df9c;
    bytes32 internal constant LEAF_2 =
        0x738c79fb32bdbd470827d4738cef03b85dc1c95a6502efc79c4835a906c5c70e;

    bytes32 internal constant ROOT =
        0x373fe712c363e2661fd8197c80c54dcabdadf17925212fcf0261555be376d3a6;

    // Depth-1 left node: keccak256(LEAF_0 || LEAF_1).
    bytes32 internal constant DEPTH_1_LEFT =
        0x50a864cc7ebe1f5e90f64aeccdc6f4cf06c50eb457124f73882faebaf0876e36;

    // Sibling at depth 1 for LEAF_0: keccak256(LEAF_2 || LEAF_2), the
    // duplicated odd node.
    bytes32 internal constant PROOF_0_DEPTH_1 =
        0xa71ad5b224e3925f704a6f08f05156d0d3da939a2da9e571d346368e47dbd763;

    // The same action under a DIFFERENT registered policy version. Identical
    // agent, action type, payload, nonce and timestamp — only the bound policy
    // differs, and the leaf is therefore different.
    bytes32 internal constant LEAF_0_OTHER_POLICY =
        0x4b4ee0bd537754c16de5fc7e980aace849fb5d080bc353f7e19176842945f188;

    function setUp() public {
        registry = new AnchorRegistry(admin, submitter);
        vm.prank(submitter);
        registry.anchorBatch(ROOT, 3, 1000, 2000);
    }

    function _proofForLeaf0()
        internal
        pure
        returns (bytes32[] memory proof, uint8[] memory positions)
    {
        proof = new bytes32[](2);
        proof[0] = LEAF_1;
        proof[1] = PROOF_0_DEPTH_1;
        positions = new uint8[](2);
        positions[0] = 1; // sibling on the right
        positions[1] = 1; // sibling on the right
    }

    /// @notice Solidity reconstructs the root Python computed, from Python's proof.
    function test_pythonRootAndProofVerifyOnChain() public {
        (bytes32[] memory proof, uint8[] memory positions) = _proofForLeaf0();
        assertTrue(registry.verifyProof(ROOT, LEAF_0, proof, positions));
    }

    /// @notice Interior hashing is keccak256(left || right), matching Python
    ///         node for node — including the odd-node duplication rule.
    function test_interiorNodeHashingMatchesPython() public {
        assertEq(keccak256(abi.encodePacked(LEAF_0, LEAF_1)), DEPTH_1_LEFT);
        // Odd count: the final node pairs with itself rather than being
        // promoted. This is the rule implementations most often disagree on.
        assertEq(keccak256(abi.encodePacked(LEAF_2, LEAF_2)), PROOF_0_DEPTH_1);
        assertEq(keccak256(abi.encodePacked(DEPTH_1_LEFT, PROOF_0_DEPTH_1)), ROOT);
    }

    /// @notice Swapping the bound policy version changes the leaf, so the
    ///         anchored proof no longer verifies. This is B2.4 reaching
    ///         on-chain with no contract change.
    function test_policySubstitutionBreaksTheAnchoredProof() public {
        (bytes32[] memory proof, uint8[] memory positions) = _proofForLeaf0();
        assertTrue(LEAF_0 != LEAF_0_OTHER_POLICY);
        assertFalse(registry.verifyProof(ROOT, LEAF_0_OTHER_POLICY, proof, positions));
    }

    /// @notice Tampered-leaf rejection still holds under the new preimage.
    function test_tamperedLeafStillRejected() public {
        (bytes32[] memory proof, uint8[] memory positions) = _proofForLeaf0();
        bytes32 tampered = keccak256(abi.encodePacked("not-a-real-action"));
        assertFalse(registry.verifyProof(ROOT, tampered, proof, positions));
    }

    /// @notice A correct leaf with a mangled position vector must not verify.
    function test_flippedProofPositionRejected() public {
        (bytes32[] memory proof, uint8[] memory positions) = _proofForLeaf0();
        positions[0] = 0; // claim the sibling was on the left
        assertFalse(registry.verifyProof(ROOT, LEAF_0, proof, positions));
    }
}
