// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title AnchorRegistry
 * @author Inntris INC
 * @notice Immutable registry for anchoring audit log Merkle roots on Base L2
 * @dev This contract stores Merkle roots from the Inntris Core audit system, providing
 *      cryptographic proof that audit logs existed at a specific point in time.
 *      Protecting Intellect. The Universal Liability Shield for Autonomous Agents.
 *
 * SECURITY CONSIDERATIONS:
 * - Merkle roots are immutable once anchored
 * - Only authorized submitters can anchor batches
 * - Each root can only be anchored once (no overwrites)
 * - All data is publicly verifiable
 *
 * FORENSIC GUARANTEES:
 * - Timestamp is block.timestamp (miner-controlled but reliable for legal purposes)
 * - Block number provides ordering guarantees
 * - Submitter address is recorded for accountability
 */

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

contract AnchorRegistry is AccessControl, Pausable, ReentrancyGuard {
    // =============================================================================
    // CONSTANTS & ROLES
    // =============================================================================

    /// @notice Role for addresses authorized to submit batches
    bytes32 public constant SUBMITTER_ROLE = keccak256("SUBMITTER_ROLE");

    /// @notice Role for addresses that can pause the contract in emergencies
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    /// @notice Minimum logs required per batch
    uint256 public constant MIN_LOGS_PER_BATCH = 1;

    /// @notice Maximum logs allowed per batch (gas considerations)
    uint256 public constant MAX_LOGS_PER_BATCH = 100000;

    // =============================================================================
    // STATE
    // =============================================================================

    /// @notice Struct representing an anchored batch of audit logs
    struct Batch {
        uint256 batchId;        // Unique batch identifier
        uint256 logCount;       // Number of logs in this batch
        uint256 timestamp;      // Block timestamp when anchored
        uint256 blockNumber;    // Block number when anchored
        uint256 startTimestamp; // Timestamp of first log in batch
        uint256 endTimestamp;   // Timestamp of last log in batch
        address submitter;      // Address that submitted the batch
    }

    /// @notice Counter for batch IDs
    uint256 private _batchIdCounter;

    /// @notice Mapping from Merkle root to batch data
    mapping(bytes32 => Batch) private _batches;

    /// @notice Mapping from batch ID to Merkle root (for iteration)
    mapping(uint256 => bytes32) private _batchIdToRoot;

    /// @notice Total number of logs anchored across all batches
    uint256 public totalLogsAnchored;

    /// @notice Total number of batches anchored
    uint256 public totalBatches;

    // =============================================================================
    // EVENTS
    // =============================================================================

    /// @notice Emitted when a new batch is anchored
    /// @param batchId Unique identifier for the batch
    /// @param merkleRoot The Merkle root of all log hashes in the batch
    /// @param logCount Number of logs in the batch
    /// @param submitter Address that submitted the batch
    event BatchAnchored(
        uint256 indexed batchId,
        bytes32 indexed merkleRoot,
        uint256 logCount,
        address indexed submitter
    );

    /// @notice Emitted when a submitter is added
    event SubmitterAdded(address indexed submitter, address indexed addedBy);

    /// @notice Emitted when a submitter is removed
    event SubmitterRemoved(address indexed submitter, address indexed removedBy);

    // =============================================================================
    // ERRORS
    // =============================================================================

    /// @notice Thrown when attempting to anchor an already-anchored root
    error RootAlreadyAnchored(bytes32 merkleRoot);

    /// @notice Thrown when the Merkle root is zero
    error InvalidMerkleRoot();

    /// @notice Thrown when log count is invalid
    error InvalidLogCount(uint256 logCount);

    /// @notice Thrown when timestamps are invalid
    error InvalidTimestamps(uint256 startTimestamp, uint256 endTimestamp);

    /// @notice Thrown when querying a non-existent batch
    error BatchNotFound(bytes32 merkleRoot);

    // =============================================================================
    // CONSTRUCTOR
    // =============================================================================

    /**
     * @notice Initialize the AnchorRegistry contract
     * @param admin Address to be granted the default admin role
     * @param initialSubmitter Initial address authorized to submit batches
     */
    constructor(address admin, address initialSubmitter) {
        require(admin != address(0), "Admin cannot be zero address");
        require(initialSubmitter != address(0), "Submitter cannot be zero address");

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(SUBMITTER_ROLE, initialSubmitter);
        _grantRole(PAUSER_ROLE, admin);

        _batchIdCounter = 1; // Start batch IDs at 1 (0 means not found)

        emit SubmitterAdded(initialSubmitter, admin);
    }

    // =============================================================================
    // EXTERNAL FUNCTIONS - WRITE
    // =============================================================================

    /**
     * @notice Anchor a batch of audit logs
     * @dev Only callable by addresses with SUBMITTER_ROLE
     * @param merkleRoot The SHA-256 Merkle root of all log hashes
     * @param logCount Number of logs in the batch
     * @param startTimestamp Unix timestamp of the first log
     * @param endTimestamp Unix timestamp of the last log
     * @return batchId The assigned batch ID
     *
     * Requirements:
     * - Contract must not be paused
     * - Caller must have SUBMITTER_ROLE
     * - merkleRoot must not be zero
     * - merkleRoot must not already be anchored
     * - logCount must be within valid range
     * - startTimestamp <= endTimestamp
     */
    function anchorBatch(
        bytes32 merkleRoot,
        uint256 logCount,
        uint256 startTimestamp,
        uint256 endTimestamp
    )
        external
        onlyRole(SUBMITTER_ROLE)
        whenNotPaused
        nonReentrant
        returns (uint256 batchId)
    {
        // Validate merkle root
        if (merkleRoot == bytes32(0)) {
            revert InvalidMerkleRoot();
        }

        // Check if already anchored
        if (_batches[merkleRoot].batchId != 0) {
            revert RootAlreadyAnchored(merkleRoot);
        }

        // Validate log count
        if (logCount < MIN_LOGS_PER_BATCH || logCount > MAX_LOGS_PER_BATCH) {
            revert InvalidLogCount(logCount);
        }

        // Validate timestamps
        if (startTimestamp > endTimestamp) {
            revert InvalidTimestamps(startTimestamp, endTimestamp);
        }

        // Assign batch ID
        batchId = _batchIdCounter++;

        // Store batch data
        _batches[merkleRoot] = Batch({
            batchId: batchId,
            logCount: logCount,
            timestamp: block.timestamp,
            blockNumber: block.number,
            startTimestamp: startTimestamp,
            endTimestamp: endTimestamp,
            submitter: msg.sender
        });

        // Store reverse mapping
        _batchIdToRoot[batchId] = merkleRoot;

        // Update totals
        totalLogsAnchored += logCount;
        totalBatches++;

        emit BatchAnchored(batchId, merkleRoot, logCount, msg.sender);

        return batchId;
    }

    /**
     * @notice Add a new authorized submitter
     * @dev Only callable by addresses with DEFAULT_ADMIN_ROLE
     * @param submitter Address to authorize
     */
    function addSubmitter(address submitter)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        require(submitter != address(0), "Submitter cannot be zero address");
        require(!hasRole(SUBMITTER_ROLE, submitter), "Already a submitter");

        _grantRole(SUBMITTER_ROLE, submitter);
        emit SubmitterAdded(submitter, msg.sender);
    }

    /**
     * @notice Remove an authorized submitter
     * @dev Only callable by addresses with DEFAULT_ADMIN_ROLE
     * @param submitter Address to deauthorize
     */
    function removeSubmitter(address submitter)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        require(hasRole(SUBMITTER_ROLE, submitter), "Not a submitter");

        _revokeRole(SUBMITTER_ROLE, submitter);
        emit SubmitterRemoved(submitter, msg.sender);
    }

    /**
     * @notice Pause the contract in case of emergency
     * @dev Only callable by addresses with PAUSER_ROLE
     */
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause the contract
     * @dev Only callable by addresses with DEFAULT_ADMIN_ROLE
     */
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    // =============================================================================
    // EXTERNAL FUNCTIONS - READ
    // =============================================================================

    /**
     * @notice Get batch data by Merkle root
     * @param merkleRoot The Merkle root to query
     * @return batchId The batch ID (0 if not found)
     * @return logCount Number of logs in the batch
     * @return timestamp Block timestamp when anchored
     * @return submitter Address that submitted the batch
     */
    function getBatch(bytes32 merkleRoot)
        external
        view
        returns (
            uint256 batchId,
            uint256 logCount,
            uint256 timestamp,
            address submitter
        )
    {
        Batch storage batch = _batches[merkleRoot];
        return (
            batch.batchId,
            batch.logCount,
            batch.timestamp,
            batch.submitter
        );
    }

    /**
     * @notice Get full batch data by Merkle root
     * @param merkleRoot The Merkle root to query
     * @return batch The complete batch struct
     */
    function getBatchFull(bytes32 merkleRoot)
        external
        view
        returns (Batch memory batch)
    {
        batch = _batches[merkleRoot];
        if (batch.batchId == 0) {
            revert BatchNotFound(merkleRoot);
        }
        return batch;
    }

    /**
     * @notice Get Merkle root by batch ID
     * @param batchId The batch ID to query
     * @return merkleRoot The associated Merkle root (bytes32(0) if not found)
     */
    function getMerkleRootByBatchId(uint256 batchId)
        external
        view
        returns (bytes32 merkleRoot)
    {
        return _batchIdToRoot[batchId];
    }

    /**
     * @notice Check if a Merkle root has been anchored
     * @param merkleRoot The Merkle root to check
     * @return anchored True if the root has been anchored
     */
    function isAnchored(bytes32 merkleRoot)
        external
        view
        returns (bool anchored)
    {
        return _batches[merkleRoot].batchId != 0;
    }

    /**
     * @notice Verify that a specific leaf is part of an anchored batch
     * @dev This performs on-chain Merkle proof verification
     * @param merkleRoot The anchored Merkle root
     * @param leaf The leaf hash to verify
     * @param proof Array of sibling hashes from leaf to root
     * @param positions Array of positions (0 = left, 1 = right) for each proof element
     * @return valid True if the proof is valid and the root is anchored
     */
    function verifyProof(
        bytes32 merkleRoot,
        bytes32 leaf,
        bytes32[] calldata proof,
        uint8[] calldata positions
    )
        external
        view
        returns (bool valid)
    {
        // Check if root is anchored
        if (_batches[merkleRoot].batchId == 0) {
            return false;
        }

        // Verify proof length matches positions length
        if (proof.length != positions.length) {
            return false;
        }

        // Compute root from leaf and proof
        bytes32 computedHash = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            if (positions[i] == 0) {
                // Sibling is on the left
                computedHash = keccak256(abi.encodePacked(proof[i], computedHash));
            } else {
                // Sibling is on the right
                computedHash = keccak256(abi.encodePacked(computedHash, proof[i]));
            }
        }

        return computedHash == merkleRoot;
    }

    /**
     * @notice Get the current batch ID counter
     * @return counter The next batch ID that will be assigned
     */
    function getCurrentBatchIdCounter()
        external
        view
        returns (uint256 counter)
    {
        return _batchIdCounter;
    }

    /**
     * @notice Check if an address is an authorized submitter
     * @param account The address to check
     * @return authorized True if the address can submit batches
     */
    function isSubmitter(address account)
        external
        view
        returns (bool authorized)
    {
        return hasRole(SUBMITTER_ROLE, account);
    }
}
