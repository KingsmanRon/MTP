"use client";

import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { copyToClipboard } from "@/lib/utils";
import {
  Shield,
  Search,
  CheckCircle,
  XCircle,
  ExternalLink,
  Copy,
  Check,
  Loader2,
  AlertTriangle,
} from "lucide-react";

export default function VerifyPage() {
  const [auditId, setAuditId] = useState("");
  const [isVerifying, setIsVerifying] = useState(false);
  const [verificationResult, setVerificationResult] = useState<{
    verified: boolean;
    log?: {
      id: string;
      agent_name: string;
      action_type: string;
      timestamp: string;
      verdict: string;
    };
    merkle?: {
      leaf: string;
      root: string;
      tx_hash: string;
      block_number: number;
      proof_path: string[];
    };
    error?: string;
  } | null>(null);
  const [copied, setCopied] = useState<string | null>(null);

  const handleVerify = async () => {
    if (!auditId) return;

    setIsVerifying(true);
    setVerificationResult(null);

    // Simulate verification
    await new Promise((resolve) => setTimeout(resolve, 2000));

    // Mock result
    if (auditId.toLowerCase().includes("invalid")) {
      setVerificationResult({
        verified: false,
        error: "Audit log not found or Merkle proof verification failed",
      });
    } else {
      setVerificationResult({
        verified: true,
        log: {
          id: auditId,
          agent_name: "PaymentBot",
          action_type: "financial_transaction",
          timestamp: new Date().toISOString(),
          verdict: "approved",
        },
        merkle: {
          leaf: "sha256:a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6",
          root: "sha256:root1234567890abcdef1234567890abcdef1234567890abcdef",
          tx_hash: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
          block_number: 12345678,
          proof_path: [
            "sha256:sibling1...",
            "sha256:sibling2...",
            "sha256:sibling3...",
          ],
        },
      });
    }

    setIsVerifying(false);
  };

  const handleCopy = async (text: string, id: string) => {
    await copyToClipboard(text);
    setCopied(id);
    setTimeout(() => setCopied(null), 2000);
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Verify Audit Log</h1>
        <p className="text-muted-foreground">
          Cryptographically verify an audit log against the blockchain anchor
        </p>
      </div>

      {/* Verification Input */}
      <Card>
        <CardHeader>
          <CardTitle>Enter Audit ID</CardTitle>
          <CardDescription>
            Paste an audit log ID or action hash to verify its authenticity
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex gap-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Enter audit ID or action hash..."
                value={auditId}
                onChange={(e) => setAuditId(e.target.value)}
                className="pl-10 font-mono"
              />
            </div>
            <Button onClick={handleVerify} disabled={!auditId || isVerifying}>
              {isVerifying ? (
                <>
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  Verifying...
                </>
              ) : (
                <>
                  <Shield className="h-4 w-4 mr-2" />
                  Verify
                </>
              )}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* How It Works */}
      {!verificationResult && !isVerifying && (
        <Card>
          <CardHeader>
            <CardTitle>How Verification Works</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid gap-6 md:grid-cols-3">
              <div className="text-center p-4">
                <div className="w-12 h-12 rounded-full bg-primary/10 flex items-center justify-center mx-auto mb-3">
                  <span className="text-lg font-bold text-primary">1</span>
                </div>
                <h4 className="font-medium mb-1">Retrieve Log</h4>
                <p className="text-sm text-muted-foreground">
                  Fetch the audit log entry from our database using the unique ID
                </p>
              </div>
              <div className="text-center p-4">
                <div className="w-12 h-12 rounded-full bg-primary/10 flex items-center justify-center mx-auto mb-3">
                  <span className="text-lg font-bold text-primary">2</span>
                </div>
                <h4 className="font-medium mb-1">Compute Proof</h4>
                <p className="text-sm text-muted-foreground">
                  Generate the Merkle proof from the log's position in the tree
                </p>
              </div>
              <div className="text-center p-4">
                <div className="w-12 h-12 rounded-full bg-primary/10 flex items-center justify-center mx-auto mb-3">
                  <span className="text-lg font-bold text-primary">3</span>
                </div>
                <h4 className="font-medium mb-1">Verify On-Chain</h4>
                <p className="text-sm text-muted-foreground">
                  Call the AnchorRegistry smart contract to verify the proof
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Verification Result */}
      {verificationResult && (
        <Card>
          <CardHeader>
            <div className="flex items-center gap-4">
              {verificationResult.verified ? (
                <div className="p-3 rounded-full bg-green-500/10">
                  <CheckCircle className="h-8 w-8 text-green-500" />
                </div>
              ) : (
                <div className="p-3 rounded-full bg-red-500/10">
                  <XCircle className="h-8 w-8 text-red-500" />
                </div>
              )}
              <div>
                <CardTitle>
                  {verificationResult.verified ? "Verification Successful" : "Verification Failed"}
                </CardTitle>
                <CardDescription>
                  {verificationResult.verified
                    ? "This audit log has been cryptographically verified on-chain"
                    : verificationResult.error}
                </CardDescription>
              </div>
            </div>
          </CardHeader>
          {verificationResult.verified && verificationResult.log && verificationResult.merkle && (
            <CardContent className="space-y-6">
              {/* Log Details */}
              <div>
                <h4 className="font-medium mb-3">Audit Log Details</h4>
                <div className="grid gap-4 md:grid-cols-2 p-4 bg-muted rounded-lg">
                  <div>
                    <p className="text-sm text-muted-foreground">Log ID</p>
                    <code className="text-sm">{verificationResult.log.id}</code>
                  </div>
                  <div>
                    <p className="text-sm text-muted-foreground">Agent</p>
                    <p className="text-sm font-medium">{verificationResult.log.agent_name}</p>
                  </div>
                  <div>
                    <p className="text-sm text-muted-foreground">Action Type</p>
                    <code className="text-sm">{verificationResult.log.action_type}</code>
                  </div>
                  <div>
                    <p className="text-sm text-muted-foreground">Verdict</p>
                    <Badge variant="outline" className="bg-green-500/10 text-green-500">
                      {verificationResult.log.verdict}
                    </Badge>
                  </div>
                </div>
              </div>

              {/* Merkle Proof */}
              <div>
                <h4 className="font-medium mb-3">Merkle Proof</h4>
                <div className="space-y-3">
                  <div className="flex items-center justify-between p-3 bg-muted rounded-lg">
                    <div>
                      <p className="text-sm text-muted-foreground">Leaf Hash</p>
                      <code className="text-xs break-all">{verificationResult.merkle.leaf}</code>
                    </div>
                    <Button
                      variant="ghost"
                      size="icon"
                      onClick={() => handleCopy(verificationResult.merkle!.leaf, "leaf")}
                    >
                      {copied === "leaf" ? (
                        <Check className="h-4 w-4 text-green-500" />
                      ) : (
                        <Copy className="h-4 w-4" />
                      )}
                    </Button>
                  </div>
                  <div className="flex items-center justify-between p-3 bg-muted rounded-lg">
                    <div>
                      <p className="text-sm text-muted-foreground">Merkle Root</p>
                      <code className="text-xs break-all">{verificationResult.merkle.root}</code>
                    </div>
                    <Button
                      variant="ghost"
                      size="icon"
                      onClick={() => handleCopy(verificationResult.merkle!.root, "root")}
                    >
                      {copied === "root" ? (
                        <Check className="h-4 w-4 text-green-500" />
                      ) : (
                        <Copy className="h-4 w-4" />
                      )}
                    </Button>
                  </div>
                </div>
              </div>

              {/* Proof Path */}
              <div>
                <h4 className="font-medium mb-3">
                  Proof Path ({verificationResult.merkle.proof_path.length} nodes)
                </h4>
                <div className="space-y-2">
                  {verificationResult.merkle.proof_path.map((node, index) => (
                    <div key={index} className="flex items-center gap-2 p-2 bg-muted rounded">
                      <Badge variant="outline" className="w-8 justify-center">
                        {index + 1}
                      </Badge>
                      <code className="text-xs text-muted-foreground flex-1">{node}</code>
                    </div>
                  ))}
                </div>
              </div>

              {/* Blockchain Reference */}
              <div>
                <h4 className="font-medium mb-3">Blockchain Reference</h4>
                <div className="p-4 bg-muted rounded-lg space-y-3">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm text-muted-foreground">Transaction Hash</p>
                      <code className="text-xs">{verificationResult.merkle.tx_hash}</code>
                    </div>
                    <a
                      href={`https://basescan.org/tx/${verificationResult.merkle.tx_hash}`}
                      target="_blank"
                      rel="noopener noreferrer"
                    >
                      <Button variant="ghost" size="icon">
                        <ExternalLink className="h-4 w-4" />
                      </Button>
                    </a>
                  </div>
                  <div>
                    <p className="text-sm text-muted-foreground">Block Number</p>
                    <p className="text-sm font-mono">
                      {verificationResult.merkle.block_number.toLocaleString()}
                    </p>
                  </div>
                  <div>
                    <p className="text-sm text-muted-foreground">Network</p>
                    <Badge variant="secondary">Base L2 (Chain ID: 8453)</Badge>
                  </div>
                </div>
              </div>

              {/* View on Explorer */}
              <Button variant="outline" className="w-full" asChild>
                <a
                  href={`https://basescan.org/tx/${verificationResult.merkle.tx_hash}`}
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  <ExternalLink className="h-4 w-4 mr-2" />
                  View on BaseScan
                </a>
              </Button>
            </CardContent>
          )}
        </Card>
      )}
    </div>
  );
}
