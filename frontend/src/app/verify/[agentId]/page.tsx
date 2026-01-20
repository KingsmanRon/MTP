"use client";

import { useParams } from "next/navigation";
import Link from "next/link";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { TrustScore } from "@/components/trust-score";
import { formatDateTime, formatRelative, copyToClipboard } from "@/lib/utils";
import {
  Shield,
  CheckCircle,
  XCircle,
  Clock,
  Activity,
  Copy,
  Check,
  ExternalLink,
  AlertTriangle,
} from "lucide-react";
import { useState, useEffect } from "react";
import type { AgentStatus } from "@/lib/api";

// Mock data - would come from API
const mockAgentData = {
  agent_id: "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  name: "PaymentBot",
  organization_name: "Acme Corporation",
  trust_score: 85,
  status: "active" as AgentStatus,
  is_verified: true,
  verified_since: "2024-01-15T10:30:00Z",
  total_actions: 15234,
  approved_actions: 14567,
  blocked_actions: 667,
  last_action_at: new Date(Date.now() - 5 * 60 * 1000).toISOString(),
  public_key_fingerprint: "sha256:a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
};

export default function PublicVerifyPage() {
  const params = useParams();
  const agentId = params.agentId as string;
  const [copied, setCopied] = useState(false);
  const [loading, setLoading] = useState(true);
  const [agent, setAgent] = useState(mockAgentData);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    // Simulate API call
    const fetchAgent = async () => {
      setLoading(true);
      await new Promise((resolve) => setTimeout(resolve, 500));

      // Check if agent exists (mock check)
      if (agentId.includes("notfound")) {
        setError("Agent not found");
      } else {
        setAgent({ ...mockAgentData, agent_id: agentId });
      }
      setLoading(false);
    };
    fetchAgent();
  }, [agentId]);

  const handleCopy = async () => {
    await copyToClipboard(window.location.href);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-b from-background to-muted flex items-center justify-center">
        <div className="text-center">
          <Shield className="h-12 w-12 text-primary animate-pulse mx-auto mb-4" />
          <p className="text-muted-foreground">Verifying agent...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen bg-gradient-to-b from-background to-muted">
        <div className="container mx-auto px-4 py-20">
          <Card className="max-w-lg mx-auto">
            <CardContent className="pt-6">
              <div className="text-center">
                <div className="p-4 rounded-full bg-red-500/10 w-fit mx-auto mb-4">
                  <XCircle className="h-8 w-8 text-red-500" />
                </div>
                <h1 className="text-2xl font-bold mb-2">Agent Not Found</h1>
                <p className="text-muted-foreground mb-6">
                  The agent ID you're looking for doesn't exist or has been revoked.
                </p>
                <Link href="/">
                  <Button>Go Home</Button>
                </Link>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    );
  }

  const approvalRate = ((agent.approved_actions / agent.total_actions) * 100).toFixed(1);

  return (
    <div className="min-h-screen bg-gradient-to-b from-background to-muted">
      {/* Header */}
      <header className="border-b bg-background/80 backdrop-blur-sm sticky top-0 z-50">
        <div className="container mx-auto px-4 py-4 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-2">
            <Shield className="h-6 w-6 text-primary" />
            <span className="font-semibold">MTP</span>
          </Link>
          <Button variant="ghost" size="sm" onClick={handleCopy}>
            {copied ? <Check className="h-4 w-4 mr-2" /> : <Copy className="h-4 w-4 mr-2" />}
            {copied ? "Copied!" : "Share"}
          </Button>
        </div>
      </header>

      <main className="container mx-auto px-4 py-12">
        <div className="max-w-2xl mx-auto">
          {/* Main Verification Card */}
          <Card className="overflow-hidden">
            {/* Verification Banner */}
            <div
              className={`p-6 text-center ${
                agent.is_verified
                  ? "bg-gradient-to-r from-green-500/10 to-green-600/10"
                  : "bg-gradient-to-r from-yellow-500/10 to-yellow-600/10"
              }`}
            >
              <div className="flex items-center justify-center gap-3 mb-4">
                {agent.is_verified ? (
                  <div className="p-3 rounded-full bg-green-500/20">
                    <CheckCircle className="h-8 w-8 text-green-500" />
                  </div>
                ) : (
                  <div className="p-3 rounded-full bg-yellow-500/20">
                    <AlertTriangle className="h-8 w-8 text-yellow-500" />
                  </div>
                )}
              </div>
              <h1 className="text-2xl font-bold mb-1">
                {agent.is_verified ? "Verified Agent" : "Unverified Agent"}
              </h1>
              <p className="text-muted-foreground">
                {agent.is_verified
                  ? "This agent is verified by the Machine Trust Protocol"
                  : "This agent has not completed verification"}
              </p>
            </div>

            <CardContent className="p-6">
              {/* Agent Info */}
              <div className="flex items-center justify-between mb-6">
                <div>
                  <h2 className="text-xl font-bold">{agent.name}</h2>
                  <p className="text-muted-foreground">{agent.organization_name}</p>
                </div>
                <TrustScore score={agent.trust_score} size="md" />
              </div>

              {/* Status Badge */}
              <div className="flex items-center gap-2 mb-6">
                <Badge
                  variant="outline"
                  className={
                    agent.status === "active"
                      ? "bg-green-500/10 text-green-500"
                      : agent.status === "suspended"
                      ? "bg-yellow-500/10 text-yellow-500"
                      : "bg-red-500/10 text-red-500"
                  }
                >
                  {agent.status}
                </Badge>
                {agent.is_verified && (
                  <Badge variant="outline" className="bg-primary/10 text-primary">
                    <Shield className="h-3 w-3 mr-1" />
                    MTP Verified
                  </Badge>
                )}
              </div>

              {/* Stats Grid */}
              <div className="grid grid-cols-2 gap-4 mb-6">
                <div className="p-4 bg-muted rounded-lg">
                  <div className="flex items-center gap-2 mb-1">
                    <Activity className="h-4 w-4 text-muted-foreground" />
                    <span className="text-sm text-muted-foreground">Total Actions</span>
                  </div>
                  <p className="text-2xl font-bold">{agent.total_actions.toLocaleString()}</p>
                </div>
                <div className="p-4 bg-muted rounded-lg">
                  <div className="flex items-center gap-2 mb-1">
                    <CheckCircle className="h-4 w-4 text-muted-foreground" />
                    <span className="text-sm text-muted-foreground">Approval Rate</span>
                  </div>
                  <p className="text-2xl font-bold">{approvalRate}%</p>
                </div>
              </div>

              {/* Detailed Stats */}
              <div className="space-y-3">
                <div className="flex items-center justify-between py-2 border-b">
                  <span className="text-muted-foreground">Verified Since</span>
                  <span className="font-medium">
                    {agent.verified_since ? formatDateTime(agent.verified_since) : "Not verified"}
                  </span>
                </div>
                <div className="flex items-center justify-between py-2 border-b">
                  <span className="text-muted-foreground">Last Activity</span>
                  <span className="font-medium">{formatRelative(agent.last_action_at)}</span>
                </div>
                <div className="flex items-center justify-between py-2 border-b">
                  <span className="text-muted-foreground">Approved Actions</span>
                  <span className="font-medium text-green-500">
                    {agent.approved_actions.toLocaleString()}
                  </span>
                </div>
                <div className="flex items-center justify-between py-2 border-b">
                  <span className="text-muted-foreground">Blocked Actions</span>
                  <span className="font-medium text-red-500">
                    {agent.blocked_actions.toLocaleString()}
                  </span>
                </div>
                <div className="flex items-center justify-between py-2">
                  <span className="text-muted-foreground">Public Key Fingerprint</span>
                  <code className="text-xs text-muted-foreground">
                    {agent.public_key_fingerprint}
                  </code>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Embed Code */}
          <Card className="mt-6">
            <CardHeader>
              <CardTitle className="text-lg">Embed This Badge</CardTitle>
              <CardDescription>
                Add a verification badge to your website
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="p-3 bg-muted rounded-lg">
                <code className="text-xs break-all">
                  {`<script src="https://mtp.dev/badge.js" data-agent="${agent.agent_id}"></script>`}
                </code>
              </div>
            </CardContent>
          </Card>

          {/* Trust Score Explanation */}
          <Card className="mt-6">
            <CardHeader>
              <CardTitle className="text-lg">About Trust Scores</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4 text-sm text-muted-foreground">
                <p>
                  Trust scores range from 0-100 and represent the cumulative trustworthiness of an
                  agent based on its verification history.
                </p>
                <div className="grid grid-cols-3 gap-4">
                  <div className="text-center p-3 bg-green-500/10 rounded-lg">
                    <p className="font-bold text-green-500">70-100</p>
                    <p className="text-xs">High Trust</p>
                  </div>
                  <div className="text-center p-3 bg-yellow-500/10 rounded-lg">
                    <p className="font-bold text-yellow-500">40-69</p>
                    <p className="text-xs">Medium Trust</p>
                  </div>
                  <div className="text-center p-3 bg-red-500/10 rounded-lg">
                    <p className="font-bold text-red-500">0-39</p>
                    <p className="text-xs">Low Trust</p>
                  </div>
                </div>
                <p>
                  Trust scores are affected by verification outcomes, policy violations, and
                  signature failures. Learn more in our{" "}
                  <a href="#" className="text-primary hover:underline">
                    documentation
                  </a>
                  .
                </p>
              </div>
            </CardContent>
          </Card>
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t mt-20">
        <div className="container mx-auto px-4 py-8">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Shield className="h-5 w-5 text-muted-foreground" />
              <span className="text-muted-foreground">Machine Trust Protocol</span>
            </div>
            <p className="text-sm text-muted-foreground">
              Forensic-grade verification for AI agents
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}
