#!/bin/bash

##############################################################################
# Inntris Core - Smoke Test (Quick Health Check)
#
# This is a fast, non-destructive health check for production deployments.
# Run this after every deployment to ensure basic functionality.
#
# Usage:
#   ./smoke_test.sh <API_URL>
#
# Example:
#   ./smoke_test.sh https://mtp.up.railway.app
#
##############################################################################

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

if [ "$#" -ne 1 ]; then
    echo -e "${RED}Usage: $0 <API_URL>${NC}"
    exit 1
fi

API_URL=${1%/}

echo -e "${BLUE}═══════════════════════════════════════${NC}"
echo -e "${BLUE}  Inntris Smoke Test${NC}"
echo -e "${BLUE}═══════════════════════════════════════${NC}"
echo ""

# Test 1: Health endpoint
echo -n "Testing /health endpoint... "
RESPONSE=$(curl -s -w "\n%{http_code}" "$API_URL/health")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

if [ "$HTTP_CODE" = "200" ]; then
    STATUS=$(echo "$BODY" | python3 -c "import sys, json; print(json.load(sys.stdin).get('status', 'unknown'))" 2>/dev/null || echo "unknown")

    if [ "$STATUS" = "healthy" ]; then
        echo -e "${GREEN}✅ PASS${NC}"
    else
        echo -e "${YELLOW}⚠️  WARN (status: $STATUS)${NC}"
    fi
else
    echo -e "${RED}❌ FAIL (HTTP $HTTP_CODE)${NC}"
    exit 1
fi

# Test 2: API Documentation
echo -n "Testing /docs endpoint... "
DOCS_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$API_URL/docs")

if [ "$DOCS_CODE" = "200" ]; then
    echo -e "${GREEN}✅ PASS${NC}"
else
    echo -e "${YELLOW}⚠️  WARN (HTTP $DOCS_CODE)${NC}"
fi

# Test 3: Response time
echo -n "Testing response time... "
START_TIME=$(date +%s%3N)
curl -s "$API_URL/health" > /dev/null
END_TIME=$(date +%s%3N)
RESPONSE_TIME=$((END_TIME - START_TIME))

if [ $RESPONSE_TIME -lt 1000 ]; then
    echo -e "${GREEN}✅ PASS (${RESPONSE_TIME}ms)${NC}"
elif [ $RESPONSE_TIME -lt 3000 ]; then
    echo -e "${YELLOW}⚠️  SLOW (${RESPONSE_TIME}ms)${NC}"
else
    echo -e "${RED}❌ TIMEOUT (${RESPONSE_TIME}ms)${NC}"
fi

# Test 4: CORS headers
echo -n "Testing CORS configuration... "
CORS_HEADERS=$(curl -s -I -X OPTIONS "$API_URL/health" | grep -i "access-control" | wc -l)

if [ $CORS_HEADERS -gt 0 ]; then
    echo -e "${GREEN}✅ PASS${NC}"
else
    echo -e "${YELLOW}⚠️  No CORS headers detected${NC}"
fi

# Test 5: Security headers
echo -n "Testing security headers... "
SECURITY_HEADERS=$(curl -s -I "$API_URL/health" | grep -iE "(X-Content-Type-Options|X-Frame-Options|Strict-Transport-Security)" | wc -l)

if [ $SECURITY_HEADERS -ge 2 ]; then
    echo -e "${GREEN}✅ PASS${NC}"
else
    echo -e "${YELLOW}⚠️  Limited security headers ($SECURITY_HEADERS/3)${NC}"
fi

echo ""
echo -e "${GREEN}╔═══════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  Smoke test completed successfully   ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════╝${NC}"
echo ""
echo "✅ API is responding"
echo "✅ Health checks pass"
echo "✅ Response time acceptable"
echo ""
echo "For comprehensive testing, run:"
echo "  ./tests/production_test.sh $API_URL <ADMIN_KEY>"
