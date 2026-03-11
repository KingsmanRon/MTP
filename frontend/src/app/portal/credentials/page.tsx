"use client";

import { useState, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { LoadingState } from "@/components/loading-state";
import { EmptyState } from "@/components/empty-state";
import { copyToClipboard } from "@/lib/utils";
import { useAgents, useAgent } from "@/lib/hooks";
import { Key, Copy, Check, Download, AlertTriangle, RefreshCw, Bot } from "lucide-react";

// Helper to get selected agent from localStorage
function getStoredAgentId(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem("portal_agent_id");
}

export default function CredentialsPage() {
  const [copied, setCopied] = useState<string | null>(null);
  const [selectedAgentId, setSelectedAgentId] = useState<string | null>(null);

  // Load stored agent ID on mount
  useEffect(() => {
    const stored = getStoredAgentId();
    if (stored) setSelectedAgentId(stored);
  }, []);

  // Fetch list of agents for fallback
  const { data: agents, isLoading: agentsLoading } = useAgents();

  // Auto-select first agent if none selected
  useEffect(() => {
    if (!selectedAgentId && agents && agents.length > 0) {
      setSelectedAgentId(agents[0].id);
    }
  }, [agents, selectedAgentId]);

  // Fetch agent details
  const { data: agent, isLoading: agentLoading } = useAgent(selectedAgentId || "");

  const handleCopy = async (text: string, id: string) => {
    await copyToClipboard(text);
    setCopied(id);
    setTimeout(() => setCopied(null), 2000);
  };

  const handleDownloadKeys = () => {
    if (!agent) return;
    const keyContent = `# Inntris Agent Credentials
# Agent ID: ${agent.id}
# Agent Name: ${agent.name}
# Generated: ${agent.created_at}

# Public Key Fingerprint (stored on server):
${agent.public_key_fingerprint}

# Note: Your private key should be stored securely.
# Only the public key fingerprint is stored on our servers.
# If you need to retrieve your full public key, check your local key storage.
`;
    const blob = new Blob([keyContent], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `inntris-agent-${agent.name.toLowerCase().replace(/\s+/g, "-")}-credentials.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (agentsLoading || agentLoading) {
    return <LoadingState message="Loading credentials..." />;
  }

  if (!agents || agents.length === 0) {
    return (
      <EmptyState
        icon={Bot}
        title="No Agents Found"
        description="Register an agent in the Admin Console first."
        action={
          <a href="/admin/agents" className="text-sm font-medium underline">
            Go to Admin Console
          </a>
        }
      />
    );
  }

  if (!agent) {
    return (
      <EmptyState
        icon={Key}
        title="Agent Not Found"
        description="Could not load agent credentials."
      />
    );
  }

  const integrationCode = `import hashlib
import json
import base64
import uuid
from datetime import datetime
from nacl.signing import SigningKey

# Your private key (keep this secure!)
private_key_b64 = "your-private-key-base64"
private_key = base64.b64decode(private_key_b64)

# Create the signing key
signing_key = SigningKey(private_key)

# Prepare the action
payload = {
    "amount": 100.00,
    "currency": "USD",
    "recipient": "user@example.com"
}

# Compute the action hash
nonce = str(uuid.uuid4())
timestamp = datetime.utcnow().isoformat() + "Z"

signing_data = {
    "agent_id": "${agent.id}",
    "action_type": "financial_transaction",
    "payload_hash": hashlib.sha256(
        json.dumps(payload, sort_keys=True).encode()
    ).hexdigest(),
    "nonce": nonce,
    "timestamp": timestamp,
}

message_hash = hashlib.sha256(
    json.dumps(signing_data, sort_keys=True).encode()
).hexdigest()

# Sign the hash
signature = signing_key.sign(message_hash.encode())
signature_b64 = base64.b64encode(signature.signature).decode()

# Send to Inntris API
import requests
response = requests.post(
    "https://api.inntris.com/verify",
    json={
        "agent_id": "${agent.id}",
        "action_type": "financial_transaction",
        "payload": payload,
        "signature": signature_b64,
        "nonce": nonce,
        "timestamp": timestamp,
    }
)`;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Credentials</h1>
        <p className="text-muted-foreground">
          Manage your agent&apos;s cryptographic credentials and keys
        </p>
      </div>

      {/* Warning Banner */}
      <Card className="border-yellow-500/50 bg-yellow-500/5">
        <CardContent className="flex items-center gap-4 py-4">
          <AlertTriangle className="h-5 w-5 text-yellow-500" />
          <div>
            <p className="font-medium">Keep your private key secure</p>
            <p className="text-sm text-muted-foreground">
              Your private key should never be shared or stored in version control.
              Only the public key fingerprint is stored on our servers.
            </p>
          </div>
        </CardContent>
      </Card>

      {/* Agent ID */}
      <Card>
        <CardHeader>
          <CardTitle>Agent ID</CardTitle>
          <CardDescription>Your unique agent identifier used for all API requests</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-2 p-3 bg-muted rounded-lg">
            <code className="flex-1 font-mono text-sm">{agent.id}</code>
            <Button
              variant="ghost"
              size="icon"
              onClick={() => handleCopy(agent.id, "agent_id")}
            >
              {copied === "agent_id" ? (
                <Check className="h-4 w-4 text-green-500" />
              ) : (
                <Copy className="h-4 w-4" />
              )}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Public Key Fingerprint */}
      <Card>
        <CardHeader>
          <CardTitle>Public Key Fingerprint</CardTitle>
          <CardDescription>
            The SHA-256 fingerprint of your Ed25519 public key (stored on server)
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center gap-2 p-3 bg-muted rounded-lg">
            <code className="flex-1 font-mono text-sm break-all">
              {agent.public_key_fingerprint}
            </code>
            <Button
              variant="ghost"
              size="icon"
              onClick={() => handleCopy(agent.public_key_fingerprint, "fingerprint")}
            >
              {copied === "fingerprint" ? (
                <Check className="h-4 w-4 text-green-500" />
              ) : (
                <Copy className="h-4 w-4" />
              )}
            </Button>
          </div>
          <p className="text-xs text-muted-foreground">
            This fingerprint uniquely identifies your public key. Your full public key
            should be stored securely in your local environment.
          </p>
        </CardContent>
      </Card>

      {/* Integration Code */}
      <Card>
        <CardHeader>
          <CardTitle>Integration Example</CardTitle>
          <CardDescription>Example code for signing and verifying actions</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="relative">
            <pre className="p-4 bg-muted rounded-lg overflow-x-auto text-sm">
              <code>{integrationCode}</code>
            </pre>
            <Button
              variant="ghost"
              size="icon"
              className="absolute top-2 right-2"
              onClick={() => handleCopy(integrationCode, "code")}
            >
              {copied === "code" ? (
                <Check className="h-4 w-4 text-green-500" />
              ) : (
                <Copy className="h-4 w-4" />
              )}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Actions */}
      <Card>
        <CardHeader>
          <CardTitle>Key Management</CardTitle>
          <CardDescription>Download credentials or rotate to a new key pair</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex gap-4">
            <Button variant="outline" onClick={handleDownloadKeys}>
              <Download className="h-4 w-4 mr-2" />
              Download Credentials
            </Button>
            <Button variant="destructive" disabled>
              <RefreshCw className="h-4 w-4 mr-2" />
              Rotate Keys
            </Button>
          </div>
          <p className="text-xs text-muted-foreground mt-4">
            Key rotation will invalidate your current keys. Make sure to update your applications.
            Contact support to rotate keys.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
