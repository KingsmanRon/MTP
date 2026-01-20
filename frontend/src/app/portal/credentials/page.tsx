"use client";

import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { copyToClipboard } from "@/lib/utils";
import { Key, Copy, Check, Download, AlertTriangle, Eye, EyeOff, RefreshCw } from "lucide-react";

// Mock data
const mockCredentials = {
  agent_id: "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  public_key: "MCowBQYDK2VwAyEAn9B7d8K1xY2Z3a4B5c6D7e8F9g0H1i2J3k4L5m6N7o8=",
  public_key_fingerprint: "sha256:a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0",
  created_at: "2024-01-15T10:30:00Z",
};

export default function CredentialsPage() {
  const [copied, setCopied] = useState<string | null>(null);
  const [showPublicKey, setShowPublicKey] = useState(false);

  const handleCopy = async (text: string, id: string) => {
    await copyToClipboard(text);
    setCopied(id);
    setTimeout(() => setCopied(null), 2000);
  };

  const handleDownloadKeys = () => {
    // In production, this would download the actual key file
    const keyContent = `# MTP Agent Keys
# Agent ID: ${mockCredentials.agent_id}
# Generated: ${mockCredentials.created_at}

Public Key (Base64):
${mockCredentials.public_key}

Public Key Fingerprint:
${mockCredentials.public_key_fingerprint}
`;
    const blob = new Blob([keyContent], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "mtp-agent-keys.txt";
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Credentials</h1>
        <p className="text-muted-foreground">
          Manage your agent's cryptographic credentials and keys
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
              Only the public key is stored on our servers.
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
            <code className="flex-1 font-mono text-sm">{mockCredentials.agent_id}</code>
            <Button
              variant="ghost"
              size="icon"
              onClick={() => handleCopy(mockCredentials.agent_id, "agent_id")}
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

      {/* Public Key */}
      <Card>
        <CardHeader>
          <CardTitle>Public Key</CardTitle>
          <CardDescription>
            Your Ed25519 public key used to verify your signatures
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <label className="text-sm font-medium">Base64-encoded Public Key</label>
            <div className="flex items-center gap-2 mt-2 p-3 bg-muted rounded-lg">
              {showPublicKey ? (
                <code className="flex-1 font-mono text-sm break-all">
                  {mockCredentials.public_key}
                </code>
              ) : (
                <code className="flex-1 font-mono text-sm text-muted-foreground">
                  ••••••••••••••••••••••••••••••••••••••••••••••••
                </code>
              )}
              <Button
                variant="ghost"
                size="icon"
                onClick={() => setShowPublicKey(!showPublicKey)}
              >
                {showPublicKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </Button>
              <Button
                variant="ghost"
                size="icon"
                onClick={() => handleCopy(mockCredentials.public_key, "public_key")}
              >
                {copied === "public_key" ? (
                  <Check className="h-4 w-4 text-green-500" />
                ) : (
                  <Copy className="h-4 w-4" />
                )}
              </Button>
            </div>
          </div>

          <div>
            <label className="text-sm font-medium">Fingerprint</label>
            <div className="flex items-center gap-2 mt-2 p-3 bg-muted rounded-lg">
              <code className="flex-1 font-mono text-sm">
                {mockCredentials.public_key_fingerprint}
              </code>
              <Button
                variant="ghost"
                size="icon"
                onClick={() => handleCopy(mockCredentials.public_key_fingerprint, "fingerprint")}
              >
                {copied === "fingerprint" ? (
                  <Check className="h-4 w-4 text-green-500" />
                ) : (
                  <Copy className="h-4 w-4" />
                )}
              </Button>
            </div>
          </div>
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
              <code>{`import hashlib
import json
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
    "agent_id": "${mockCredentials.agent_id}",
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

# Send to MTP API
response = requests.post(
    "https://api.mtp.dev/verify",
    json={
        "agent_id": "${mockCredentials.agent_id}",
        "action_type": "financial_transaction",
        "payload": payload,
        "signature": signature_b64,
        "nonce": nonce,
        "timestamp": timestamp,
    }
)`}</code>
            </pre>
            <Button
              variant="ghost"
              size="icon"
              className="absolute top-2 right-2"
              onClick={() => handleCopy("code", "code")}
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
          <CardDescription>Download keys or rotate to a new key pair</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex gap-4">
            <Button variant="outline" onClick={handleDownloadKeys}>
              <Download className="h-4 w-4 mr-2" />
              Download Keys
            </Button>
            <Button variant="destructive">
              <RefreshCw className="h-4 w-4 mr-2" />
              Rotate Keys
            </Button>
          </div>
          <p className="text-xs text-muted-foreground mt-4">
            Key rotation will invalidate your current keys. Make sure to update your applications.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
