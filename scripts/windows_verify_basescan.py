"""
Windows-compatible script for verifying Merkle proofs on Basescan.
Run with: python scripts/windows_verify_basescan.py

This script helps you:
1. Find anchored audit logs in your database
2. Get Merkle proof data
3. Format it for Basescan verification
"""

import sys
import json

try:
    import requests
except ImportError:
    print("Missing dependency. Run: pip install requests")
    sys.exit(1)

# =============================================================================
# CONFIGURATION
# =============================================================================
API_URL = "http://localhost:8000"

# AnchorRegistry contract addresses
CONTRACTS = {
    "base_mainnet": {
        "address": "0x0600eA15802c8d2EA429371b2EB0aacCFe321480",
        "explorer": "https://basescan.org"
    },
    # Internal dev only — not a valid public verification path.
    # Public verify endpoint rejects chain_id != 8453 with HTTP 410.
    "_base_sepolia_dev_only": {
        "address": "0x0600ea15802c8d2ea429371b2eb0aaccfe321480",
        "explorer": "https://sepolia.basescan.org"
    }
}

# Default to mainnet — the only valid public chain
NETWORK = "base_mainnet"


def print_header(title: str):
    print(f"\n{'='*70}")
    print(f"  {title}")
    print('='*70)


def print_section(title: str):
    print(f"\n--- {title} ---")


# =============================================================================
# MAIN GUIDE
# =============================================================================

def main():
    print_header("MERKLE PROOF VERIFICATION ON BASESCAN")

    contract = CONTRACTS[NETWORK]

    print("""
This guide walks you through verifying a Merkle proof on Basescan.

PREREQUISITES:
- You need audit logs that have been anchored to the blockchain
- The Anchor Worker runs hourly and batches audit logs into Merkle trees
- Each batch's Merkle root is submitted to the AnchorRegistry contract
""")

    # =========================================================================
    # STEP 1: Check for anchored proofs
    # =========================================================================
    print_section("STEP 1: Find Anchored Audit Logs")

    print("""
Option A: Query via API (if endpoint exists):

    curl http://localhost:8000/admin/audit/search?has_merkle_proof=true

Option B: Query database directly:

    docker compose exec postgres psql -U postgres -d inntris -c "
    SELECT
        al.id as audit_id,
        al.action_type,
        al.verdict,
        al.timestamp,
        mp.merkle_root,
        mp.blockchain_tx_hash,
        mp.blockchain_block_number
    FROM audit_logs al
    JOIN merkle_proofs mp ON al.merkle_root_id = mp.id
    WHERE mp.status = 'confirmed'
    ORDER BY al.timestamp DESC
    LIMIT 5;
    "

Option C: Check merkle_proofs table for any confirmed anchors:

    docker compose exec postgres psql -U postgres -d inntris -c "
    SELECT
        id,
        merkle_root,
        batch_size,
        blockchain_tx_hash,
        blockchain_block_number,
        status,
        created_at
    FROM merkle_proofs
    WHERE status = 'confirmed'
    ORDER BY created_at DESC
    LIMIT 5;
    "
""")

    # =========================================================================
    # STEP 2: Go to Basescan
    # =========================================================================
    print_section("STEP 2: Open Basescan")

    explorer_url = contract["explorer"]
    contract_address = contract["address"]

    print(f"""
Navigate to the AnchorRegistry contract on Basescan:

    {explorer_url}/address/{contract_address}#readContract

For Base Sepolia (testnet):
    https://sepolia.basescan.org/address/0x0600ea15802c8d2ea429371b2eb0aaccfe321480#readContract

For Base Mainnet:
    https://basescan.org/address/YOUR_CONTRACT_ADDRESS#readContract
""")

    # =========================================================================
    # STEP 3: Check if root is anchored
    # =========================================================================
    print_section("STEP 3: Check if Merkle Root is Anchored")

    print("""
On the contract's "Read Contract" tab:

1. Find function: isAnchored
2. Enter your merkle_root (bytes32 format, e.g., 0xabc123...)
3. Click "Query"

Expected result:
    - true  = Root was anchored on-chain
    - false = Root not found (not yet anchored or invalid)

Example merkle_root format:
    0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
""")

    # =========================================================================
    # STEP 4: Get batch details
    # =========================================================================
    print_section("STEP 4: Get Batch Details")

    print("""
On the contract's "Read Contract" tab:

1. Find function: getBatch
2. Enter your merkle_root
3. Click "Query"

Returns:
    - batchId:   Sequential batch number (1, 2, 3, ...)
    - logCount:  Number of audit logs in this batch
    - timestamp: Unix timestamp when anchored
    - submitter: Wallet address of the Anchor Worker

Alternative: Use getBatchFull for complete details:
    - Also returns: blockNumber, startTimestamp, endTimestamp
""")

    # =========================================================================
    # STEP 5: Verify a specific audit log
    # =========================================================================
    print_section("STEP 5: Verify a Specific Audit Log (Merkle Proof)")

    print("""
To prove a specific audit log exists in an anchored batch:

FIRST, get the Merkle proof from your database:

    docker compose exec postgres psql -U postgres -d inntris -c "
    SELECT
        al.id,
        al.action_hash as leaf,
        al.merkle_leaf_index,
        mp.merkle_root
    FROM audit_logs al
    JOIN merkle_proofs mp ON al.merkle_root_id = mp.id
    WHERE al.id = 'YOUR_AUDIT_ID';
    "

The Merkle proof consists of:
    - merkleRoot: The anchored root (bytes32)
    - leaf:       Hash of the specific audit log (bytes32)
    - proof:      Array of sibling hashes [bytes32, bytes32, ...]
    - positions:  Array of positions [0, 1, 0, ...] (0=left, 1=right)

THEN, on Basescan "Read Contract" tab:

1. Find function: verifyProof
2. Enter parameters:
    - merkleRoot: 0xabc123...
    - leaf:       0xdef456...
    - proof:      ["0x111...","0x222...","0x333..."]
    - positions:  [0,1,0]
3. Click "Query"

Expected result:
    - true  = Proof is valid, audit log exists in anchored batch
    - false = Invalid proof or root not anchored
""")

    # =========================================================================
    # STEP 6: View transaction history
    # =========================================================================
    print_section("STEP 6: View Transaction History on Basescan")

    print(f"""
To see all anchored batches:

1. Go to: {explorer_url}/address/{contract_address}#events
2. Look for "BatchAnchored" events
3. Each event shows:
    - batchId
    - merkleRoot
    - logCount
    - submitter

To see a specific anchoring transaction:

1. Get the blockchain_tx_hash from your database
2. Go to: {explorer_url}/tx/YOUR_TX_HASH
3. View details:
    - Block number
    - Timestamp
    - Gas used
    - Input data (contains the Merkle root)
""")

    # =========================================================================
    # EXAMPLE: Format proof for Basescan
    # =========================================================================
    print_section("EXAMPLE: Formatted Proof for Basescan")

    example_proof = {
        "merkleRoot": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        "leaf": "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678",
        "proof": [
            "0x1111111111111111111111111111111111111111111111111111111111111111",
            "0x2222222222222222222222222222222222222222222222222222222222222222",
            "0x3333333333333333333333333333333333333333333333333333333333333333"
        ],
        "positions": [0, 1, 0]
    }

    print("Example values to enter in Basescan verifyProof function:\n")
    print(f"  merkleRoot: {example_proof['merkleRoot']}")
    print(f"  leaf:       {example_proof['leaf']}")
    print(f"  proof:      {json.dumps(example_proof['proof'])}")
    print(f"  positions:  {json.dumps(example_proof['positions'])}")

    # =========================================================================
    # Quick reference
    # =========================================================================
    print_section("QUICK REFERENCE: AnchorRegistry Functions")

    print("""
READ FUNCTIONS (no gas required):

    isAnchored(bytes32 merkleRoot) -> bool
        Check if a root has been anchored

    getBatch(bytes32 merkleRoot) -> (batchId, logCount, timestamp, submitter)
        Get basic batch info

    getBatchFull(bytes32 merkleRoot) -> Batch struct
        Get complete batch info including block number

    verifyProof(bytes32 merkleRoot, bytes32 leaf, bytes32[] proof, uint8[] positions) -> bool
        Verify a Merkle proof on-chain

    getMerkleRootByBatchId(uint256 batchId) -> bytes32
        Lookup root by batch ID

    totalLogsAnchored() -> uint256
        Total audit logs anchored across all batches

    totalBatches() -> uint256
        Total number of batches anchored
""")

    print_header("END OF GUIDE")
    print(f"""
Contract Address ({NETWORK}): {contract_address}
Explorer: {explorer_url}/address/{contract_address}

If you have anchored audit logs, you can now verify them on Basescan!
""")


if __name__ == "__main__":
    main()
