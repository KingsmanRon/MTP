// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title AnchorRegistryTimelock.t
 * @notice Phase 3.3 — verify the Safe + Timelock topology for admin ops.
 *
 * These tests simulate the production wiring:
 *   * TimelockController is DEFAULT_ADMIN_ROLE holder on AnchorRegistry.
 *   * A Gnosis Safe address (simulated as an EOA) holds PROPOSER_ROLE.
 *   * No EOA on its own can add/remove submitters or grant roles.
 *
 * The critical properties we lock in:
 *   1. The Safe *alone* cannot add a submitter — it can only queue.
 *   2. An admin op cannot execute before minDelay has elapsed.
 *   3. After minDelay, anyone can execute, and the effect is applied.
 *   4. A non-Safe EOA cannot queue ops.
 *   5. The deployer has no lingering DEFAULT_ADMIN_ROLE after handoff.
 */

import {Test} from "forge-std/Test.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {AnchorRegistry} from "../../contracts/AnchorRegistry.sol";

contract AnchorRegistryTimelockTest is Test {
    TimelockController internal timelock;
    AnchorRegistry internal registry;

    address internal safe = address(0xA11CE);
    address internal submitter = address(0xBEEF);
    address internal attacker = address(0xBAD);
    address internal newSubmitter = address(0xFACE);
    uint256 internal constant MIN_DELAY = 2 days;

    function setUp() public {
        address[] memory proposers = new address[](1);
        proposers[0] = safe;
        address[] memory executors = new address[](1);
        executors[0] = address(0); // open execution post-delay

        timelock = new TimelockController(MIN_DELAY, proposers, executors, address(0));
        registry = new AnchorRegistry(address(timelock), submitter);
    }

    // ------------------------------------------------------------------
    // property 1+5: deployer / attacker cannot grant roles directly
    // ------------------------------------------------------------------

    function test_deployerHasNoAdminRole() public view {
        assertFalse(
            registry.hasRole(registry.DEFAULT_ADMIN_ROLE(), address(this)),
            "deployer must not retain admin"
        );
        assertTrue(
            registry.hasRole(registry.DEFAULT_ADMIN_ROLE(), address(timelock)),
            "timelock must be admin"
        );
    }

    function test_attackerCannotAddSubmitter() public {
        vm.prank(attacker);
        vm.expectRevert(); // AccessControl revert — exact selector differs by OZ version
        registry.addSubmitter(newSubmitter);
    }

    function test_safeCannotAddSubmitterDirectly() public {
        // Even the Safe cannot bypass the timelock — it has PROPOSER_ROLE
        // on the timelock but no role on the registry itself.
        vm.prank(safe);
        vm.expectRevert();
        registry.addSubmitter(newSubmitter);
    }

    // ------------------------------------------------------------------
    // property 4: non-Safe EOA cannot queue
    // ------------------------------------------------------------------

    function test_attackerCannotSchedule() public {
        bytes memory data = abi.encodeWithSelector(
            registry.addSubmitter.selector,
            newSubmitter
        );
        vm.prank(attacker);
        vm.expectRevert(); // missing PROPOSER_ROLE on the timelock
        timelock.schedule(
            address(registry),
            0,
            data,
            bytes32(0),
            bytes32(0),
            MIN_DELAY
        );
    }

    // ------------------------------------------------------------------
    // property 2+3: delay enforced, then executable
    // ------------------------------------------------------------------

    function test_safeQueuesAndExecutesAfterDelay() public {
        bytes memory data = abi.encodeWithSelector(
            registry.grantRole.selector,
            registry.SUBMITTER_ROLE(),
            newSubmitter
        );
        bytes32 salt = bytes32(uint256(1));

        vm.prank(safe);
        timelock.schedule(address(registry), 0, data, bytes32(0), salt, MIN_DELAY);

        // execute before delay -> revert
        vm.expectRevert();
        timelock.execute(address(registry), 0, data, bytes32(0), salt);

        // wait the full delay, then anyone can execute
        vm.warp(block.timestamp + MIN_DELAY);
        vm.prank(attacker); // executor role is open (address(0))
        timelock.execute(address(registry), 0, data, bytes32(0), salt);

        assertTrue(
            registry.hasRole(registry.SUBMITTER_ROLE(), newSubmitter),
            "new submitter must be granted after delay"
        );
    }

    function test_queuedOpCanBeCancelledBySafe() public {
        bytes memory data = abi.encodeWithSelector(
            registry.grantRole.selector,
            registry.SUBMITTER_ROLE(),
            newSubmitter
        );
        bytes32 salt = bytes32(uint256(2));

        vm.prank(safe);
        timelock.schedule(address(registry), 0, data, bytes32(0), salt, MIN_DELAY);

        bytes32 id = timelock.hashOperation(
            address(registry),
            0,
            data,
            bytes32(0),
            salt
        );
        assertTrue(timelock.isOperationPending(id), "op should be pending");

        // In the constructor we did NOT grant CANCELLER_ROLE separately,
        // so by default the Safe (proposer) is also the canceller — OZ
        // v4.x grants PROPOSER_ROLE = CANCELLER_ROLE on the same address.
        vm.prank(safe);
        timelock.cancel(id);
        assertFalse(timelock.isOperationPending(id), "op should be cancelled");
    }
}
