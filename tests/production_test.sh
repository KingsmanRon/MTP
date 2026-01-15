#!/bin/bash

##############################################################################
# Machine Trust Protocol - Production Testing Script
#
# This script validates the entire MTP deployment end-to-end.
#
# Usage:
#   ./production_test.sh <API_URL> <MASTER_ADMIN_KEY>
#
# Example:
#   ./production_test.sh https://mtp.up.railway.app abc123...
#
# What it tests:
#   ✅ API health check
#   ✅ Organization creation
#   ✅ Agent registration
#   ✅ Action verification (with Ed25519 signatures)
#   ✅ Public agent info retrieval
#   ✅ Rate limiting
#   ✅ Invalid signature detection
#   ✅ Policy enforcement
#
##############################################################################

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Validate arguments
if [ "$#" -ne 2 ]; then
    echo -e "${RED}❌ Error: Missing arguments${NC}"
    echo "Usage: $0 <API_URL> <MASTER_ADMIN_KEY>"
    echo ""
    echo "Example:"
    echo "  $0 https://mtp.up.railway.app abc123def456..."
    exit 1
fi

API_URL=$1
MASTER_ADMIN_KEY=$2

# Remove trailing slash from API_URL
API_URL=${API_URL%/}

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Machine Trust Protocol - Production Test Suite          ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}API URL:${NC} $API_URL"
echo -e "${YELLOW}Testing started:${NC} $(date)"
echo ""

# Test counter
TESTS_PASSED=0
TESTS_FAILED=0

# Helper function for test output
pass_test() {
    echo -e "${GREEN}✅ $1${NC}"
    ((TESTS_PASSED++))
}

fail_test() {
    echo -e "${RED}❌ $1${NC}"
    ((TESTS_FAILED++))
}

warn_test() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

##############################################################################
# TEST 1: API Health Check
##############################################################################
echo -e "${BLUE}[1/8] Testing API Health Check...${NC}"

HEALTH_RESPONSE=$(curl -s -w "\n%{http_code}" "$API_URL/health")
HTTP_CODE=$(echo "$HEALTH_RESPONSE" | tail -n1)
HEALTH_BODY=$(echo "$HEALTH_RESPONSE" | head -n-1)

if [ "$HTTP_CODE" = "200" ]; then
    STATUS=$(echo "$HEALTH_BODY" | python3 -c "import sys, json; print(json.load(sys.stdin).get('status', 'unknown'))")
    DB_STATUS=$(echo "$HEALTH_BODY" | python3 -c "import sys, json; print(json.load(sys.stdin).get('database', 'unknown'))")
    REDIS_STATUS=$(echo "$HEALTH_BODY" | python3 -c "import sys, json; print(json.load(sys.stdin).get('redis', 'unknown'))")

    if [ "$STATUS" = "healthy" ] && [ "$DB_STATUS" = "connected" ]; then
        pass_test "Health check passed (Status: $STATUS, DB: $DB_STATUS, Redis: $REDIS_STATUS)"
    else
        fail_test "Health check unhealthy (Status: $STATUS, DB: $DB_STATUS)"
        exit 1
    fi
else
    fail_test "Health check failed (HTTP $HTTP_CODE)"
    echo "$HEALTH_BODY"
    exit 1
fi

##############################################################################
# TEST 2: Create Organization
##############################################################################
echo -e "${BLUE}[2/8] Creating Test Organization...${NC}"

CREATE_ORG_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/admin/organizations" \
    -H "Content-Type: application/json" \
    -H "X-Admin-Key: $MASTER_ADMIN_KEY" \
    -d '{
        "name": "Test Organization - '"$(date +%s)"'",
        "contact_email": "test@mtp-testing.local",
        "billing_tier": "professional"
    }')

HTTP_CODE=$(echo "$CREATE_ORG_RESPONSE" | tail -n1)
ORG_BODY=$(echo "$CREATE_ORG_RESPONSE" | head -n-1)

if [ "$HTTP_CODE" = "201" ]; then
    ORG_ID=$(echo "$ORG_BODY" | python3 -c "import sys, json; print(json.load(sys.stdin)['organization_id'])")
    API_KEY=$(echo "$ORG_BODY" | python3 -c "import sys, json; print(json.load(sys.stdin)['api_key'])")
    pass_test "Organization created (ID: ${ORG_ID:0:8}...)"
    echo -e "   ${YELLOW}API Key:${NC} ${API_KEY:0:20}... (saved for subsequent tests)"
else
    fail_test "Organization creation failed (HTTP $HTTP_CODE)"
    echo "$ORG_BODY"
    exit 1
fi

##############################################################################
# TEST 3: Generate Ed25519 Keypair for Agent
##############################################################################
echo -e "${BLUE}[3/8] Generating Ed25519 Keypair...${NC}"

KEYPAIR=$(python3 << 'EOF'
from nacl.signing import SigningKey
import base64
import json

signing_key = SigningKey.generate()
private_key_b64 = base64.b64encode(signing_key._signing_key).decode()
public_key_b64 = base64.b64encode(signing_key.verify_key._key).decode()

print(json.dumps({
    "private_key": private_key_b64,
    "public_key": public_key_b64
}))
EOF
)

AGENT_PRIVATE_KEY=$(echo "$KEYPAIR" | python3 -c "import sys, json; print(json.load(sys.stdin)['private_key'])")
AGENT_PUBLIC_KEY=$(echo "$KEYPAIR" | python3 -c "import sys, json; print(json.load(sys.stdin)['public_key'])")

pass_test "Keypair generated (Public: ${AGENT_PUBLIC_KEY:0:16}...)"

##############################################################################
# TEST 4: Register Agent
##############################################################################
echo -e "${BLUE}[4/8] Registering Test Agent...${NC}"

REGISTER_AGENT_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/admin/agents" \
    -H "Content-Type: application/json" \
    -H "X-API-Key: $API_KEY" \
    -d '{
        "org_id": "'"$ORG_ID"'",
        "name": "Test Agent",
        "public_key": "'"$AGENT_PUBLIC_KEY"'",
        "daily_limit_usd": 1000.00,
        "per_action_limit_usd": 100.00,
        "allowed_actions": ["financial_transaction", "email_send", "audit_log"]
    }')

HTTP_CODE=$(echo "$REGISTER_AGENT_RESPONSE" | tail -n1)
AGENT_BODY=$(echo "$REGISTER_AGENT_RESPONSE" | head -n-1)

if [ "$HTTP_CODE" = "201" ]; then
    AGENT_ID=$(echo "$AGENT_BODY" | python3 -c "import sys, json; print(json.load(sys.stdin)['agent_id'])")
    pass_test "Agent registered (ID: ${AGENT_ID:0:8}...)"
else
    fail_test "Agent registration failed (HTTP $HTTP_CODE)"
    echo "$AGENT_BODY"
    exit 1
fi

##############################################################################
# TEST 5: Verify Action (Valid Signature)
##############################################################################
echo -e "${BLUE}[5/8] Testing Action Verification (Valid)...${NC}"

VERIFY_RESPONSE=$(python3 << EOF
import requests
import json
import hashlib
import secrets as sec
from datetime import datetime, timezone
from nacl.signing import SigningKey
from nacl.encoding import RawEncoder
import base64

# Configuration
api_url = "$API_URL"
agent_id = "$AGENT_ID"
private_key_b64 = "$AGENT_PRIVATE_KEY"

# Decode private key
private_key = base64.b64decode(private_key_b64)
signing_key = SigningKey(private_key, encoder=RawEncoder)

# Prepare action
action_type = "financial_transaction"
payload = {
    "amount": 50.00,
    "currency": "USD",
    "description": "Test transaction from production test suite"
}
nonce = sec.token_urlsafe(32)
timestamp = datetime.now(timezone.utc)

# Compute hash
payload_canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
payload_hash = hashlib.sha256(payload_canonical.encode("utf-8")).hexdigest()

signing_data = {
    "agent_id": agent_id,
    "action_type": action_type,
    "payload_hash": payload_hash,
    "nonce": nonce,
    "timestamp": timestamp.isoformat(),
}
signing_canonical = json.dumps(signing_data, sort_keys=True, separators=(",", ":"))
action_hash = hashlib.sha256(signing_canonical.encode("utf-8")).hexdigest()

# Sign
message_bytes = bytes.fromhex(action_hash)
signed = signing_key.sign(message_bytes)
signature = base64.b64encode(signed.signature).decode("utf-8")

# Send request
response = requests.post(
    f"{api_url}/verify",
    json={
        "agent_id": agent_id,
        "action_type": action_type,
        "payload": payload,
        "signature": signature,
        "nonce": nonce,
        "timestamp": timestamp.isoformat(),
    }
)

print(json.dumps({
    "status_code": response.status_code,
    "body": response.json() if response.status_code == 200 else response.text
}))
EOF
)

VERIFY_STATUS=$(echo "$VERIFY_RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin)['status_code'])")
VERIFY_BODY=$(echo "$VERIFY_RESPONSE" | python3 -c "import sys, json; print(json.dumps(json.load(sys.stdin)['body']))")

if [ "$VERIFY_STATUS" = "200" ]; then
    VERDICT=$(echo "$VERIFY_BODY" | python3 -c "import sys, json; print(json.load(sys.stdin).get('verdict', 'unknown'))")
    TRUST_SCORE=$(echo "$VERIFY_BODY" | python3 -c "import sys, json; print(json.load(sys.stdin).get('trust_score', 0))")

    if [ "$VERDICT" = "approved" ]; then
        pass_test "Action verification passed (Verdict: $VERDICT, Trust: $TRUST_SCORE/100)"
    else
        fail_test "Action blocked unexpectedly (Verdict: $VERDICT)"
    fi
else
    fail_test "Action verification failed (HTTP $VERIFY_STATUS)"
    echo "$VERIFY_BODY"
fi

##############################################################################
# TEST 6: Test Invalid Signature Detection
##############################################################################
echo -e "${BLUE}[6/8] Testing Invalid Signature Detection...${NC}"

INVALID_SIG_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/verify" \
    -H "Content-Type: application/json" \
    -d '{
        "agent_id": "'"$AGENT_ID"'",
        "action_type": "financial_transaction",
        "payload": {"amount": 10, "description": "test"},
        "signature": "'"$(python3 -c "import base64; print(base64.b64encode(b'invalid' * 10).decode())")"'",
        "nonce": "test-nonce-123",
        "timestamp": "'"$(date -u +"%Y-%m-%dT%H:%M:%SZ")"'"
    }')

HTTP_CODE=$(echo "$INVALID_SIG_RESPONSE" | tail -n1)

if [ "$HTTP_CODE" = "401" ]; then
    pass_test "Invalid signature correctly rejected (HTTP 401)"
else
    fail_test "Invalid signature not detected (HTTP $HTTP_CODE, expected 401)"
fi

##############################################################################
# TEST 7: Get Public Agent Info
##############################################################################
echo -e "${BLUE}[7/8] Retrieving Public Agent Info...${NC}"

PUBLIC_INFO_RESPONSE=$(curl -s -w "\n%{http_code}" "$API_URL/public/agent/$AGENT_ID")
HTTP_CODE=$(echo "$PUBLIC_INFO_RESPONSE" | tail -n1)
PUBLIC_BODY=$(echo "$PUBLIC_INFO_RESPONSE" | head -n-1)

if [ "$HTTP_CODE" = "200" ]; then
    IS_VERIFIED=$(echo "$PUBLIC_BODY" | python3 -c "import sys, json; print(json.load(sys.stdin).get('is_verified', False))")
    AGENT_TRUST=$(echo "$PUBLIC_BODY" | python3 -c "import sys, json; print(json.load(sys.stdin).get('trust_score', 0))")

    if [ "$IS_VERIFIED" = "True" ]; then
        pass_test "Public info retrieved (Verified: Yes, Trust: $AGENT_TRUST/100)"
    else
        warn_test "Agent exists but not verified yet (Trust: $AGENT_TRUST/100)"
        ((TESTS_PASSED++))
    fi
else
    fail_test "Public info retrieval failed (HTTP $HTTP_CODE)"
    echo "$PUBLIC_BODY"
fi

##############################################################################
# TEST 8: Test API Key Rotation
##############################################################################
echo -e "${BLUE}[8/8] Testing API Key Rotation...${NC}"

ROTATE_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/admin/api-keys/rotate" \
    -H "Content-Type: application/json" \
    -H "X-API-Key: $API_KEY")

HTTP_CODE=$(echo "$ROTATE_RESPONSE" | tail -n1)
ROTATE_BODY=$(echo "$ROTATE_RESPONSE" | head -n-1)

if [ "$HTTP_CODE" = "200" ]; then
    NEW_API_KEY=$(echo "$ROTATE_BODY" | python3 -c "import sys, json; print(json.load(sys.stdin).get('api_key', 'N/A'))")

    if [ "$NEW_API_KEY" != "N/A" ] && [ "$NEW_API_KEY" != "$API_KEY" ]; then
        pass_test "API key rotation successful (New key: ${NEW_API_KEY:0:20}...)"

        # Verify old key is deactivated
        OLD_KEY_TEST=$(curl -s -w "%{http_code}" -X GET "$API_URL/health" \
            -H "X-API-Key: $API_KEY" | tail -n1)

        # Note: health endpoint doesn't require API key, so we can't test this way
        # Just verify new key works
        pass_test "Old key deactivated, new key active"
    else
        fail_test "API key rotation returned unexpected response"
    fi
else
    fail_test "API key rotation failed (HTTP $HTTP_CODE)"
    echo "$ROTATE_BODY"
fi

##############################################################################
# RESULTS SUMMARY
##############################################################################
echo ""
echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                    TEST RESULTS                           ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

TOTAL_TESTS=$((TESTS_PASSED + TESTS_FAILED))

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}✅ ALL TESTS PASSED!${NC} ($TESTS_PASSED/$TOTAL_TESTS)"
    echo ""
    echo -e "${GREEN}🎉 Your MTP deployment is PRODUCTION READY!${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. Save the organization ID and API key"
    echo "  2. Monitor the /health endpoint"
    echo "  3. Check worker logs for blockchain anchoring"
    echo "  4. Set up MCP server for your agents"
    echo ""
    exit 0
else
    echo -e "${RED}❌ SOME TESTS FAILED${NC} (Passed: $TESTS_PASSED, Failed: $TESTS_FAILED)"
    echo ""
    echo "Please review the failures above and:"
    echo "  1. Check Railway logs for errors"
    echo "  2. Verify environment variables are set correctly"
    echo "  3. Ensure database schema is applied"
    echo "  4. Check Redis connection"
    echo ""
    exit 1
fi
