// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// =============================================================================
// AnchorRegistry Foundry tests (Phase 2A)
// =============================================================================
// Forensic guarantees the contract must keep:
//   1. A root, once anchored, cannot be overwritten (RootAlreadyAnchored).
//   2. Only SUBMITTER_ROLE may call anchorBatch (AccessControl).
//   3. Pausing blocks new anchors but does not mutate stored roots.
//   4. verifyProof returns true exactly when the root is anchored AND the
//      proof reconstructs to it — never accepts an un-anchored root even
//      with a self-consistent proof.
//   5. anchorBatch rejects invalid input shapes (zero root, bad log count,
//      inverted timestamps) rather than storing a malformed Batch.
//
// These tests run in a deterministic EVM; `vm.warp` and `vm.prank` are used
// to simulate multiple submitters and the pause/unpause lifecycle.

import "forge-std/Test.sol";
import "../../contracts/AnchorRegistry.sol";

contract AnchorRegistryTest is Test {
    AnchorRegistry internal registry;

    address internal admin = address(0xA11CE);
    address internal submitter = address(0xB0B);
    address internal stranger = address(0xCAFE);

    bytes32 internal constant ROOT_A = keccak256("root-a");
    bytes32 internal constant ROOT_B = keccak256("root-b");

    function setUp() public {
        registry = new AnchorRegistry(admin, submitter);
    }

    // -------------------------------------------------------------------------
    // anchorBatch: happy path
    // -------------------------------------------------------------------------

    function test_anchorBatch_storesBatchAndIncrementsTotals() public {
        vm.prank(submitter);
        uint256 batchId = registry.anchorBatch(ROOT_A, 10, 1000, 2000);

        // batchId must be > 0 (0 means not-found in the getter contract).
        assertGt(batchId, 0);
        assertTrue(registry.isAnchored(ROOT_A));
        assertEq(registry.totalBatches(), 1);
        assertEq(registry.totalLogsAnchored(), 10);

        (uint256 returnedId, uint256 logCount, , address who) =
            registry.getBatch(ROOT_A);
        assertEq(returnedId, batchId);
        assertEq(logCount, 10);
        assertEq(who, submitter);
    }

    // -------------------------------------------------------------------------
    // anchorBatch: idempotency / no-overwrite
    // -------------------------------------------------------------------------

    function test_anchorBatch_revertsOnDuplicateRoot() public {
        vm.startPrank(submitter);
        registry.anchorBatch(ROOT_A, 10, 1000, 2000);

        // Even with a different log count / timestamp window, a second
        // submission of the same root must revert. This is the forensic
        // write-once property.
        vm.expectRevert(
            abi.encodeWithSelector(AnchorRegistry.RootAlreadyAnchored.selector, ROOT_A)
        );
        registry.anchorBatch(ROOT_A, 99, 3000, 4000);
        vm.stopPrank();

        // And the original totals are unchanged.
        assertEq(registry.totalBatches(), 1);
        assertEq(registry.totalLogsAnchored(), 10);
    }

    // -------------------------------------------------------------------------
    // anchorBatch: access control
    // -------------------------------------------------------------------------

    function test_anchorBatch_revertsForNonSubmitter() public {
        vm.prank(stranger);
        vm.expectRevert();  // OZ AccessControl emits its own custom error
        registry.anchorBatch(ROOT_A, 1, 1, 2);

        assertFalse(registry.isAnchored(ROOT_A));
    }

    function test_addSubmitter_canThenAnchor() public {
        vm.prank(admin);
        registry.addSubmitter(stranger);

        vm.prank(stranger);
        registry.anchorBatch(ROOT_A, 1, 1, 2);
        assertTrue(registry.isAnchored(ROOT_A));
    }

    function test_removeSubmitter_blocksFutureAnchors() public {
        vm.prank(admin);
        registry.removeSubmitter(submitter);

        vm.prank(submitter);
        vm.expectRevert();
        registry.anchorBatch(ROOT_A, 1, 1, 2);
    }

    // -------------------------------------------------------------------------
    // anchorBatch: input validation
    // -------------------------------------------------------------------------

    function test_anchorBatch_revertsOnZeroRoot() public {
        vm.prank(submitter);
        vm.expectRevert(AnchorRegistry.InvalidMerkleRoot.selector);
        registry.anchorBatch(bytes32(0), 1, 1, 2);
    }

    function test_anchorBatch_revertsOnZeroLogCount() public {
        vm.prank(submitter);
        vm.expectRevert(
            abi.encodeWithSelector(AnchorRegistry.InvalidLogCount.selector, uint256(0))
        );
        registry.anchorBatch(ROOT_A, 0, 1, 2);
    }

    function test_anchorBatch_revertsOnInvertedTimestamps() public {
        vm.prank(submitter);
        vm.expectRevert(
            abi.encodeWithSelector(
                AnchorRegistry.InvalidTimestamps.selector,
                uint256(2000),
                uint256(1000)
            )
        );
        registry.anchorBatch(ROOT_A, 5, 2000, 1000);
    }

    // -------------------------------------------------------------------------
    // Pause lifecycle
    // -------------------------------------------------------------------------

    function test_pause_blocksAnchors_butPreservesPriorRoots() public {
        vm.prank(submitter);
        registry.anchorBatch(ROOT_A, 5, 1, 2);

        vm.prank(admin);
        registry.pause();

        vm.prank(submitter);
        vm.expectRevert();  // Pausable reverts with EnforcedPause on OZ v5
        registry.anchorBatch(ROOT_B, 5, 3, 4);

        // Prior root is still queryable.
        assertTrue(registry.isAnchored(ROOT_A));
        assertFalse(registry.isAnchored(ROOT_B));

        vm.prank(admin);
        registry.unpause();

        vm.prank(submitter);
        registry.anchorBatch(ROOT_B, 5, 3, 4);
        assertTrue(registry.isAnchored(ROOT_B));
    }

    // -------------------------------------------------------------------------
    // verifyProof
    // -------------------------------------------------------------------------

    function test_verifyProof_returnsFalseForUnanchoredRoot() public view {
        bytes32[] memory proof = new bytes32[](0);
        uint8[] memory positions = new uint8[](0);

        // No anchor call — even a trivially-valid "zero proof" must not
        // falsely verify against an un-anchored root.
        bool ok = registry.verifyProof(ROOT_A, ROOT_A, proof, positions);
        assertFalse(ok);
    }

    function test_verifyProof_singleLeafBatch() public {
        // Single-leaf merkle tree: root == leaf, empty proof.
        bytes32 leaf = keccak256(abi.encodePacked(uint256(42)));
        vm.prank(submitter);
        registry.anchorBatch(leaf, 1, 1, 2);

        bytes32[] memory proof = new bytes32[](0);
        uint8[] memory positions = new uint8[](0);

        bool ok = registry.verifyProof(leaf, leaf, proof, positions);
        assertTrue(ok);
    }

    function test_verifyProof_twoLeafBatch() public {
        bytes32 leafL = keccak256(abi.encodePacked(uint256(1)));
        bytes32 leafR = keccak256(abi.encodePacked(uint256(2)));
        bytes32 root = keccak256(abi.encodePacked(leafL, leafR));

        vm.prank(submitter);
        registry.anchorBatch(root, 2, 1, 2);

        // Proving leafL: sibling is leafR on the right (position=1).
        bytes32[] memory proofL = new bytes32[](1);
        proofL[0] = leafR;
        uint8[] memory positionsL = new uint8[](1);
        positionsL[0] = 1;
        assertTrue(registry.verifyProof(root, leafL, proofL, positionsL));

        // Proving leafR: sibling is leafL on the left (position=0).
        bytes32[] memory proofR = new bytes32[](1);
        proofR[0] = leafL;
        uint8[] memory positionsR = new uint8[](1);
        positionsR[0] = 0;
        assertTrue(registry.verifyProof(root, leafR, proofR, positionsR));

        // A tampered leaf must NOT verify.
        bytes32 fakeLeaf = keccak256(abi.encodePacked(uint256(3)));
        assertFalse(registry.verifyProof(root, fakeLeaf, proofL, positionsL));
    }

    // -------------------------------------------------------------------------
    // Fuzz: any non-zero root with valid bounds should anchor exactly once.
    // -------------------------------------------------------------------------

    function testFuzz_anchorBatch_isWriteOnce(
        bytes32 root,
        uint64 logCount,
        uint64 startTs,
        uint64 endTs
    ) public {
        vm.assume(root != bytes32(0));
        vm.assume(logCount >= 1 && logCount <= 100_000);
        vm.assume(startTs <= endTs);

        vm.startPrank(submitter);
        registry.anchorBatch(root, logCount, startTs, endTs);

        vm.expectRevert(
            abi.encodeWithSelector(AnchorRegistry.RootAlreadyAnchored.selector, root)
        );
        registry.anchorBatch(root, logCount, startTs, endTs);
        vm.stopPrank();
    }
}
