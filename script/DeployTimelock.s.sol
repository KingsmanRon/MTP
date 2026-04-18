// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title DeployTimelock
 * @notice Phase 3.3 — deploy AnchorRegistry under a TimelockController.
 *
 * Topology:
 *
 *     Gnosis Safe (multi-sig)         TimelockController           AnchorRegistry
 *     ───────────────────────         ──────────────────           ──────────────
 *          PROPOSER_ROLE    ─── queue ───>  (pending ops)
 *          CANCELLER_ROLE   ─── cancel ──>
 *          (anyone)         ── execute ──> after MIN_DELAY ──>  DEFAULT_ADMIN_ROLE
 *
 * Security properties:
 *   * Single-key compromise of the deployer cannot change submitters, add
 *     PAUSER_ROLE members, or unpause the contract — the timelock is the
 *     only holder of DEFAULT_ADMIN_ROLE after the handoff block.
 *   * Safe signers can *queue* admin ops but cannot execute them any
 *     faster than MIN_DELAY, giving on-chain observers (and the Pauser
 *     role) a window to react.
 *   * PAUSER_ROLE is held separately by an operational hot-wallet so
 *     emergency pause does not wait for the timelock delay. The tradeoff:
 *     pausing is fast (a hot key), but the pauser cannot *unpause* — that
 *     still goes through the timelock.
 *
 * Usage:
 *
 *     forge script script/DeployTimelock.s.sol:DeployTimelock \
 *         --rpc-url $RPC_URL \
 *         --broadcast \
 *         --verify
 *
 * Required env vars:
 *   SAFE_ADDRESS         Gnosis Safe multi-sig that will propose/cancel admin ops
 *   INITIAL_SUBMITTER    Worker key allowed to call anchorBatch()
 *   PAUSER_ADDRESS       Hot wallet holding PAUSER_ROLE for emergencies
 *   MIN_DELAY_SECONDS    Timelock delay (default 172800 = 48h)
 *
 * After a successful run:
 *   1. Verify the printed DEFAULT_ADMIN_ROLE is the timelock address.
 *   2. In the Safe, schedule `revokeRole(DEFAULT_ADMIN_ROLE, <deployer>)`
 *      to fully handoff from the deployer to the timelock. (Constructor
 *      does NOT grant the deployer admin in this script, so this step is
 *      only needed if a prior manual deploy exists.)
 */

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {AnchorRegistry} from "../contracts/AnchorRegistry.sol";

contract DeployTimelock is Script {
    function run() external {
        address safe = vm.envAddress("SAFE_ADDRESS");
        address submitter = vm.envAddress("INITIAL_SUBMITTER");
        address pauser = vm.envAddress("PAUSER_ADDRESS");
        uint256 minDelay = vm.envOr("MIN_DELAY_SECONDS", uint256(172800));

        require(safe != address(0), "SAFE_ADDRESS required");
        require(submitter != address(0), "INITIAL_SUBMITTER required");
        require(pauser != address(0), "PAUSER_ADDRESS required");

        // Proposers = [Safe], executors = [address(0)] means anyone can
        // execute a queued op after the delay (no monopoly on execution).
        address[] memory proposers = new address[](1);
        proposers[0] = safe;
        address[] memory executors = new address[](1);
        executors[0] = address(0);

        vm.startBroadcast();

        // admin=address(0) makes the timelock self-administered — only the
        // timelock itself can change its own proposers/executors (via a
        // queued op from the Safe), removing any EOA backdoor.
        TimelockController timelock = new TimelockController(
            minDelay,
            proposers,
            executors,
            address(0)
        );

        // AnchorRegistry admin = timelock. Pauser gets a separate hot key.
        // Deployer is NOT granted any role.
        AnchorRegistry registry = new AnchorRegistry(
            address(timelock),
            submitter
        );

        // Grant pauser role to the hot wallet via the timelock? No — the
        // constructor already grants PAUSER_ROLE to `admin` (the timelock).
        // Moving it to the hot wallet requires a queued op; we surface the
        // call the operator should run next:
        bytes memory grantPauserCall = abi.encodeWithSelector(
            registry.grantRole.selector,
            registry.PAUSER_ROLE(),
            pauser
        );

        vm.stopBroadcast();

        console2.log("TimelockController:", address(timelock));
        console2.log("AnchorRegistry:    ", address(registry));
        console2.log("Initial submitter: ", submitter);
        console2.log("Pauser target:     ", pauser);
        console2.log("Min delay (s):     ", minDelay);
        console2.log("--- Next step (submit from Safe) ---");
        console2.log(
            "timelock.schedule(registry, 0, <calldata>, bytes32(0), bytes32(0), minDelay)"
        );
        console2.logBytes(grantPauserCall);
    }
}
