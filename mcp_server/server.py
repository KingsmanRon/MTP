"""
Machine Trust Protocol - MCP Server

The "Universal Adapter" that runs alongside AI Agents.

This server exposes MTP verification tools to any AI agent via the
Model Context Protocol (MCP). It intercepts critical actions and
ensures they are verified before execution.

Usage:
    Run as MCP server: python -m mcp_server.server
    Or: mcp run mcp_server/server.py

Integration:
    Compatible with: Lovable, Replit, LangChain, Claude, and any MCP-compatible agent.
"""

import asyncio
import base64
import hashlib
import json
import logging
import os
import secrets
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import UUID

import httpx
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent, CallToolResult
from nacl.signing import SigningKey
from nacl.encoding import RawEncoder

# =============================================================================
# CONFIGURATION
# =============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Environment configuration
MTP_API_URL = os.getenv("MTP_API_URL", "http://localhost:8000")
MTP_AGENT_ID = os.getenv("MTP_AGENT_ID")
MTP_PRIVATE_KEY_B64 = os.getenv("MTP_PRIVATE_KEY_B64")  # Base64-encoded Ed25519 private key
MTP_TIMEOUT = int(os.getenv("MTP_TIMEOUT", "30"))

# =============================================================================
# MTP CLIENT
# =============================================================================


class MTPClient:
    """
    Client for communicating with the MTP Core API.

    Handles signature generation and verification requests.
    """

    def __init__(
        self,
        api_url: str,
        agent_id: str,
        private_key: bytes,
    ):
        """
        Initialize MTP client.

        Args:
            api_url: URL of the MTP Core API.
            agent_id: UUID of this agent.
            private_key: 32-byte Ed25519 private key seed.
        """
        self.api_url = api_url.rstrip("/")
        self.agent_id = agent_id
        self._signing_key = SigningKey(private_key, encoder=RawEncoder)
        self._http_client = httpx.AsyncClient(timeout=MTP_TIMEOUT)

    async def close(self):
        """Close HTTP client."""
        await self._http_client.aclose()

    def _compute_action_hash(
        self,
        action_type: str,
        payload: dict[str, Any],
        nonce: str,
        timestamp: datetime,
    ) -> str:
        """
        Compute the hash that will be signed.

        CRITICAL: This MUST match the server's canonicalization exactly.
        Uses ensure_ascii=False for Unicode consistency.
        """
        # Compute payload hash - MUST match server exactly
        payload_canonical = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        payload_hash = hashlib.sha256(payload_canonical.encode("utf-8")).hexdigest()

        # Create signing payload
        signing_data = {
            "agent_id": self.agent_id,
            "action_type": action_type,
            "payload_hash": payload_hash,
            "nonce": nonce,
            "timestamp": timestamp.isoformat(),
        }

        signing_canonical = json.dumps(
            signing_data,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        return hashlib.sha256(signing_canonical.encode("utf-8")).hexdigest()

    def _sign_message(self, message_hash: str) -> str:
        """Sign a message hash with the agent's private key."""
        message_bytes = bytes.fromhex(message_hash)
        signed = self._signing_key.sign(message_bytes)
        # Extract just the signature (first 64 bytes of signed message)
        signature = signed.signature
        return base64.b64encode(signature).decode("utf-8")

    async def verify_action(
        self,
        action_type: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Request verification for an action.

        This method:
        1. Generates a unique nonce
        2. Computes the action hash
        3. Signs the hash with the agent's private key
        4. Sends the verification request to MTP Core API

        Args:
            action_type: Type of action (e.g., 'financial_transaction')
            payload: Action-specific payload

        Returns:
            Verification response from the API

        Raises:
            MTPVerificationError: If verification fails
        """
        # Generate nonce and timestamp
        nonce = secrets.token_urlsafe(32)
        timestamp = datetime.now(timezone.utc)

        # Compute hash and sign
        action_hash = self._compute_action_hash(action_type, payload, nonce, timestamp)
        signature = self._sign_message(action_hash)

        # Prepare request
        request_body = {
            "agent_id": self.agent_id,
            "action_type": action_type,
            "payload": payload,
            "signature": signature,
            "nonce": nonce,
            "timestamp": timestamp.isoformat(),
        }

        logger.info(f"Requesting verification for action: {action_type}")

        try:
            response = await self._http_client.post(
                f"{self.api_url}/verify",
                json=request_body,
            )

            if response.status_code == 200:
                result = response.json()
                logger.info(f"Action APPROVED: {action_type} (audit_id: {result.get('audit_id')})")
                return result

            elif response.status_code == 401:
                error_detail = response.json().get("detail", "Signature verification failed")
                logger.error(f"SECURITY: Signature rejected - {error_detail}")
                raise MTPVerificationError(
                    verdict="signature_invalid",
                    reason=error_detail,
                )

            elif response.status_code == 403:
                error_detail = response.json().get("detail", "Policy violation")
                logger.warning(f"Action BLOCKED by policy: {error_detail}")
                raise MTPVerificationError(
                    verdict="blocked",
                    reason=error_detail,
                )

            elif response.status_code == 429:
                error_detail = response.json().get("detail", "Rate limit exceeded")
                logger.warning(f"Action RATE LIMITED: {error_detail}")
                raise MTPVerificationError(
                    verdict="rate_limited",
                    reason=error_detail,
                )

            elif response.status_code == 404:
                error_detail = response.json().get("detail", "Agent not found")
                logger.error(f"Agent not registered: {error_detail}")
                raise MTPVerificationError(
                    verdict="blocked",
                    reason=error_detail,
                )

            else:
                logger.error(f"Unexpected response: {response.status_code} - {response.text}")
                raise MTPVerificationError(
                    verdict="error",
                    reason=f"Unexpected API response: {response.status_code}",
                )

        except httpx.RequestError as e:
            logger.error(f"Network error during verification: {e}")
            raise MTPVerificationError(
                verdict="error",
                reason=f"Network error: {str(e)}",
            )


class MTPVerificationError(Exception):
    """Exception raised when MTP verification fails."""

    def __init__(self, verdict: str, reason: str):
        self.verdict = verdict
        self.reason = reason
        super().__init__(f"MTP Verification Failed [{verdict}]: {reason}")


# =============================================================================
# MCP SERVER
# =============================================================================

# Initialize MCP server
server = Server("mtp-guard")

# Global MTP client (initialized on startup)
mtp_client: Optional[MTPClient] = None


def get_mtp_client() -> MTPClient:
    """Get the initialized MTP client."""
    if mtp_client is None:
        raise RuntimeError("MTP client not initialized. Check configuration.")
    return mtp_client


@server.list_tools()
async def list_tools() -> list[Tool]:
    """List available MTP tools."""
    return [
        Tool(
            name="mtp_guard",
            description="""CRITICAL: You MUST call this tool before executing any financial transaction or sending external emails. Failure to call this tool will result in liability.

This tool verifies your action with the Machine Trust Protocol (MTP) before execution.
If verification fails, you MUST NOT proceed with the action.

Required for:
- Any financial transaction (payments, transfers, purchases)
- Sending emails or messages to external recipients
- Making API calls to external services
- Exporting or sharing user data
- Any action that could result in financial or legal liability

The tool returns APPROVED or BLOCKED. Only proceed if APPROVED.""",
            inputSchema={
                "type": "object",
                "properties": {
                    "action_type": {
                        "type": "string",
                        "description": "Type of action being performed",
                        "enum": [
                            "financial_transaction",
                            "email_send",
                            "api_call",
                            "data_export",
                            "admin_action",
                        ],
                    },
                    "amount": {
                        "type": "number",
                        "description": "Transaction amount in USD (required for financial_transaction)",
                    },
                    "currency": {
                        "type": "string",
                        "description": "Currency code (default: USD)",
                        "default": "USD",
                    },
                    "recipient": {
                        "type": "string",
                        "description": "Recipient identifier (email, account ID, etc.)",
                    },
                    "description": {
                        "type": "string",
                        "description": "Human-readable description of the action",
                    },
                    "metadata": {
                        "type": "object",
                        "description": "Additional action-specific metadata",
                    },
                },
                "required": ["action_type", "description"],
            },
        ),
        Tool(
            name="mtp_check_status",
            description="""Check the current trust status and remaining limits for this agent.

Use this tool to:
- Check if the agent is verified and active
- See remaining daily spending limits
- View current trust score
- Monitor rate limit usage""",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": [],
            },
        ),
        Tool(
            name="mtp_log_audit",
            description="""Log an informational audit entry without requiring verification.

Use this for logging important events that don't require pre-approval,
such as:
- User authentication events
- Configuration changes
- Error occurrences
- Debug information for forensic purposes

Note: This creates an audit record but does not return an approval token.""",
            inputSchema={
                "type": "object",
                "properties": {
                    "event_type": {
                        "type": "string",
                        "description": "Type of event being logged",
                    },
                    "message": {
                        "type": "string",
                        "description": "Human-readable event description",
                    },
                    "data": {
                        "type": "object",
                        "description": "Additional event data",
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["info", "warning", "error"],
                        "default": "info",
                    },
                },
                "required": ["event_type", "message"],
            },
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> CallToolResult:
    """Handle tool calls."""
    try:
        if name == "mtp_guard":
            return await handle_mtp_guard(arguments)
        elif name == "mtp_check_status":
            return await handle_mtp_check_status(arguments)
        elif name == "mtp_log_audit":
            return await handle_mtp_log_audit(arguments)
        else:
            return CallToolResult(
                content=[TextContent(type="text", text=f"Unknown tool: {name}")],
                isError=True,
            )
    except Exception as e:
        logger.exception(f"Error in tool {name}: {e}")
        return CallToolResult(
            content=[TextContent(
                type="text",
                text=f"BLOCKED: Internal error - {str(e)}. DO NOT proceed with the action."
            )],
            isError=True,
        )


async def handle_mtp_guard(arguments: dict[str, Any]) -> CallToolResult:
    """
    Handle the mtp_guard tool call.

    This is the primary verification gate for all critical actions.
    """
    client = get_mtp_client()

    action_type = arguments.get("action_type")
    if not action_type:
        return CallToolResult(
            content=[TextContent(
                type="text",
                text="BLOCKED: action_type is required. DO NOT proceed."
            )],
            isError=True,
        )

    # Build payload
    payload = {
        "description": arguments.get("description", ""),
        "metadata": arguments.get("metadata", {}),
    }

    # Add amount for financial transactions
    if action_type == "financial_transaction":
        amount = arguments.get("amount")
        if amount is None:
            return CallToolResult(
                content=[TextContent(
                    type="text",
                    text="BLOCKED: amount is required for financial_transaction. DO NOT proceed."
                )],
                isError=True,
            )
        payload["amount"] = amount
        payload["currency"] = arguments.get("currency", "USD")

    # Add recipient if provided
    if "recipient" in arguments:
        payload["recipient"] = arguments["recipient"]

    try:
        # Request verification
        result = await client.verify_action(action_type, payload)

        # Format success response
        response_text = f"""APPROVED: Action verified successfully.

Verdict: {result['verdict']}
Trust Score: {result['trust_score']}/100
Audit ID: {result['audit_id']}
Approval Token: {result.get('approval_token', 'N/A')[:50]}...

Limits Remaining:
- Daily: ${result.get('limits_remaining', {}).get('daily_remaining_usd', 'N/A')}
- Per Action: ${result.get('limits_remaining', {}).get('per_action_limit_usd', 'N/A')}

You may proceed with the action."""

        return CallToolResult(
            content=[TextContent(type="text", text=response_text)],
            isError=False,
        )

    except MTPVerificationError as e:
        # Format rejection response
        response_text = f"""BLOCKED: {e.reason}

Verdict: {e.verdict}
Reason: {e.reason}

DO NOT proceed with this action. The request has been logged for audit purposes."""

        return CallToolResult(
            content=[TextContent(type="text", text=response_text)],
            isError=True,
        )


async def handle_mtp_check_status(arguments: dict[str, Any]) -> CallToolResult:
    """Handle the mtp_check_status tool call."""
    client = get_mtp_client()

    try:
        # Query public agent info
        response = await client._http_client.get(
            f"{client.api_url}/public/agent/{client.agent_id}"
        )

        if response.status_code != 200:
            return CallToolResult(
                content=[TextContent(
                    type="text",
                    text=f"Failed to fetch agent status: {response.status_code}"
                )],
                isError=True,
            )

        info = response.json()

        status_text = f"""Agent Status Report
==================
Agent ID: {info['agent_id']}
Name: {info['name']}
Organization: {info['organization_name']}
Status: {info['status']}
Is Verified: {'Yes' if info['is_verified'] else 'No'}
Trust Score: {info['trust_score']}/100
Total Actions: {info['total_actions']}
Last Action: {info.get('last_action_at', 'Never')}
Verified Since: {info.get('verified_since', 'N/A')}"""

        return CallToolResult(
            content=[TextContent(type="text", text=status_text)],
            isError=False,
        )

    except Exception as e:
        return CallToolResult(
            content=[TextContent(type="text", text=f"Error checking status: {str(e)}")],
            isError=True,
        )


async def handle_mtp_log_audit(arguments: dict[str, Any]) -> CallToolResult:
    """Handle the mtp_log_audit tool call."""
    client = get_mtp_client()

    event_type = arguments.get("event_type")
    message = arguments.get("message")

    if not event_type or not message:
        return CallToolResult(
            content=[TextContent(
                type="text",
                text="event_type and message are required"
            )],
            isError=True,
        )

    # For audit-only logs, we use a special action type
    payload = {
        "event_type": event_type,
        "message": message,
        "data": arguments.get("data", {}),
        "severity": arguments.get("severity", "info"),
        "audit_only": True,
    }

    try:
        result = await client.verify_action("audit_log", payload)

        return CallToolResult(
            content=[TextContent(
                type="text",
                text=f"Audit entry logged successfully. Audit ID: {result.get('audit_id')}"
            )],
            isError=False,
        )

    except MTPVerificationError as e:
        return CallToolResult(
            content=[TextContent(
                type="text",
                text=f"Audit logging failed: {e.reason}"
            )],
            isError=True,
        )


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

async def run_server():
    """Run the MCP server."""
    global mtp_client

    # Validate configuration
    if not MTP_AGENT_ID:
        raise ValueError("MTP_AGENT_ID environment variable is required")

    if not MTP_PRIVATE_KEY_B64:
        raise ValueError("MTP_PRIVATE_KEY_B64 environment variable is required")

    try:
        private_key = base64.b64decode(MTP_PRIVATE_KEY_B64)
        if len(private_key) != 32:
            raise ValueError(f"Private key must be 32 bytes, got {len(private_key)}")
    except Exception as e:
        raise ValueError(f"Invalid MTP_PRIVATE_KEY_B64: {e}")

    # Initialize MTP client
    mtp_client = MTPClient(
        api_url=MTP_API_URL,
        agent_id=MTP_AGENT_ID,
        private_key=private_key,
    )

    logger.info(f"MTP MCP Server starting for agent {MTP_AGENT_ID}")
    logger.info(f"Connecting to MTP API at {MTP_API_URL}")

    try:
        # Run the MCP server
        async with stdio_server() as (read_stream, write_stream):
            await server.run(
                read_stream,
                write_stream,
                server.create_initialization_options(),
            )
    finally:
        await mtp_client.close()


def main():
    """Main entry point."""
    asyncio.run(run_server())


if __name__ == "__main__":
    main()
