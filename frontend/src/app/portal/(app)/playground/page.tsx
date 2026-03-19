"use client";

import { useState, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Select } from "@/components/ui/select";
import { VerdictBadge } from "@/components/verdict-badge";
import { TrustScoreBadge } from "@/components/trust-score";
import { LoadingState } from "@/components/loading-state";
import { EmptyState } from "@/components/empty-state";
import { formatDateTime, copyToClipboard } from "@/lib/utils";
import { useAgents } from "@/lib/hooks";
import { createAuthenticatedApi, VerificationResult, ActionVerdict } from "@/lib/api";
import { Play, Copy, Check, AlertCircle, CheckCircle, Loader2, Bot, Zap } from "lucide-react";

const ACTION_TYPES = [
  { value: "financial_transaction", label: "Financial Transaction" },
  { value: "email_send", label: "Email Send" },
  { value: "api_call", label: "API Call" },
  { value: "data_export", label: "Data Export" },
  { value: "admin_action", label: "Admin Action" },
];

const SAMPLE_PAYLOADS: Record<string, object> = {
  financial_transaction: {
    amount: 150.0,
    currency: "USD",
    recipient: "user@example.com",
    description: "Order payment #12345",
  },
  email_send: {
    to: "customer@example.com",
    subject: "Your order has shipped",
    template: "shipping_notification",
  },
  api_call: {
    endpoint: "/api/v1/orders",
    method: "POST",
    resource: "orders",
  },
  data_export: {
    format: "csv",
    dataset: "user_analytics",
    date_range: "last_30_days",
  },
  admin_action: {
    action: "update_config",
    target: "rate_limits",
    changes: { max_requests: 100 },
  },
};

// Get API key from localStorage
function getApiKey(): string {
  if (typeof window !== "undefined") {
    const stored = localStorage.getItem("inntris_api_key");
    if (stored) return stored;
  }
  return process.env.NEXT_PUBLIC_API_KEY || "dev_test_key";
}

export default function PlaygroundPage() {
  const [selectedAgentId, setSelectedAgentId] = useState<string>("");
  const [actionType, setActionType] = useState("financial_transaction");
  const [payload, setPayload] = useState(JSON.stringify(SAMPLE_PAYLOADS.financial_transaction, null, 2));
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState<VerificationResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);

  // Fetch agents
  const { data: agents, isLoading: agentsLoading } = useAgents();

  // Auto-select first agent
  useEffect(() => {
    if (agents && agents.length > 0 && !selectedAgentId) {
      setSelectedAgentId(agents[0].id);
    }
  }, [agents, selectedAgentId]);

  const handleActionTypeChange = (newType: string) => {
    setActionType(newType);
    setPayload(JSON.stringify(SAMPLE_PAYLOADS[newType] || {}, null, 2));
    setResult(null);
    setError(null);
  };

  const handleTest = async () => {
    if (!selectedAgentId) {
      setError("Please select an agent");
      return;
    }

    setIsLoading(true);
    setError(null);
    setResult(null);

    // Validate JSON
    let parsedPayload;
    try {
      parsedPayload = JSON.parse(payload);
    } catch {
      setError("Invalid JSON payload");
      setIsLoading(false);
      return;
    }

    try {
      const api = createAuthenticatedApi(getApiKey());
      const response = await api.testVerify({
        agent_id: selectedAgentId,
        action_type: actionType,
        payload: parsedPayload,
      });
      setResult(response);
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : "Verification request failed";
      setError(errorMessage);
    } finally {
      setIsLoading(false);
    }
  };

  const handleCopy = async (text: string, id: string) => {
    await copyToClipboard(text);
    setCopied(id);
    setTimeout(() => setCopied(null), 2000);
  };

  if (agentsLoading) {
    return <LoadingState message="Loading agents..." />;
  }

  if (!agents || agents.length === 0) {
    return (
      <EmptyState
        icon={Bot}
        title="No Agents Found"
        description="Register an agent first to test verifications."
        action={
          <a href="/admin/agents" className="text-sm font-medium underline">
            Go to Agents
          </a>
        }
      />
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Verification Playground</h1>
        <p className="text-muted-foreground">
          Test verification requests against the live policy engine
        </p>
      </div>

      {/* Live API Badge */}
      <div className="flex items-center gap-2 p-3 bg-green-500/10 border border-green-500/20 rounded-lg">
        <Zap className="h-4 w-4 text-green-500" />
        <span className="text-sm text-green-700 dark:text-green-400">
          Connected to live API - Results reflect actual policy evaluation
        </span>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        {/* Request Panel */}
        <Card>
          <CardHeader>
            <CardTitle>Request</CardTitle>
            <CardDescription>Configure and test a verification request</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <label className="text-sm font-medium">Agent</label>
              <Select
                value={selectedAgentId}
                onChange={(e) => {
                  setSelectedAgentId(e.target.value);
                  setResult(null);
                }}
              >
                {agents.map((agent) => (
                  <option key={agent.id} value={agent.id}>
                    {agent.name} (Score: {agent.trust_score})
                  </option>
                ))}
              </Select>
            </div>

            <div className="space-y-2">
              <label className="text-sm font-medium">Action Type</label>
              <Select
                value={actionType}
                onChange={(e) => handleActionTypeChange(e.target.value)}
              >
                {ACTION_TYPES.map((type) => (
                  <option key={type.value} value={type.value}>
                    {type.label}
                  </option>
                ))}
              </Select>
            </div>

            <div className="space-y-2">
              <label className="text-sm font-medium">Payload (JSON)</label>
              <Textarea
                value={payload}
                onChange={(e) => setPayload(e.target.value)}
                className="font-mono text-sm h-48"
                placeholder='{"key": "value"}'
              />
            </div>

            {error && (
              <div className="flex items-center gap-2 p-3 bg-destructive/10 text-destructive rounded-lg">
                <AlertCircle className="h-4 w-4" />
                <span className="text-sm">{error}</span>
              </div>
            )}

            <Button onClick={handleTest} disabled={isLoading} className="w-full">
              {isLoading ? (
                <>
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  Verifying...
                </>
              ) : (
                <>
                  <Play className="h-4 w-4 mr-2" />
                  Test Verification
                </>
              )}
            </Button>
          </CardContent>
        </Card>

        {/* Response Panel */}
        <Card>
          <CardHeader>
            <CardTitle>Response</CardTitle>
            <CardDescription>Verification result from the policy engine</CardDescription>
          </CardHeader>
          <CardContent>
            {!result ? (
              <div className="flex flex-col items-center justify-center h-64 text-center">
                <div className="p-4 rounded-full bg-muted mb-4">
                  <Play className="h-8 w-8 text-muted-foreground" />
                </div>
                <p className="text-muted-foreground">
                  Run a test to see the verification response
                </p>
              </div>
            ) : (
              <div className="space-y-4">
                {/* Verdict */}
                <div className="flex items-center justify-between p-4 rounded-lg bg-muted">
                  <div>
                    <p className="text-sm text-muted-foreground">Verdict</p>
                    <div className="mt-1">
                      <VerdictBadge verdict={result.verdict} />
                    </div>
                  </div>
                  <div className="text-right">
                    <p className="text-sm text-muted-foreground">Trust Score</p>
                    <TrustScoreBadge score={result.trust_score} />
                  </div>
                </div>

                {/* Reason */}
                <div className="space-y-1">
                  <label className="text-sm font-medium">Reason</label>
                  <p className="text-sm text-muted-foreground">{result.verdict_reason}</p>
                </div>

                {/* Approval Token */}
                {result.approval_token && (
                  <div className="space-y-1">
                    <label className="text-sm font-medium">Approval Token</label>
                    <div className="flex items-center gap-2 p-2 bg-muted rounded-lg">
                      <code className="flex-1 text-xs break-all">{result.approval_token}</code>
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => handleCopy(result.approval_token!, "token")}
                      >
                        {copied === "token" ? (
                          <Check className="h-4 w-4 text-green-500" />
                        ) : (
                          <Copy className="h-4 w-4" />
                        )}
                      </Button>
                    </div>
                  </div>
                )}

                {/* Audit ID */}
                <div className="space-y-1">
                  <label className="text-sm font-medium">Audit ID</label>
                  <div className="flex items-center gap-2 p-2 bg-muted rounded-lg">
                    <code className="flex-1 text-xs">{result.audit_id}</code>
                    <Button
                      variant="ghost"
                      size="icon"
                      onClick={() => handleCopy(result.audit_id, "audit_id")}
                    >
                      {copied === "audit_id" ? (
                        <Check className="h-4 w-4 text-green-500" />
                      ) : (
                        <Copy className="h-4 w-4" />
                      )}
                    </Button>
                  </div>
                </div>

                {/* Limits Remaining */}
                {result.limits_remaining && (
                  <div className="space-y-2">
                    <label className="text-sm font-medium">Limits Remaining</label>
                    <div className="grid grid-cols-3 gap-2">
                      <div className="p-2 bg-muted rounded-lg text-center">
                        <p className="text-xs text-muted-foreground">Daily Remaining</p>
                        <p className="text-sm font-medium">
                          ${parseFloat(result.limits_remaining.daily_remaining_usd).toFixed(2)}
                        </p>
                      </div>
                      <div className="p-2 bg-muted rounded-lg text-center">
                        <p className="text-xs text-muted-foreground">Per Action Limit</p>
                        <p className="text-sm font-medium">
                          ${parseFloat(result.limits_remaining.per_action_limit_usd).toFixed(2)}
                        </p>
                      </div>
                      <div className="p-2 bg-muted rounded-lg text-center">
                        <p className="text-xs text-muted-foreground">Rate Limit</p>
                        <p className="text-sm font-medium">
                          {result.limits_remaining.rate_limit_used_this_minute}/{result.limits_remaining.rate_limit_per_minute}/min
                        </p>
                      </div>
                    </div>
                  </div>
                )}

                {/* Timestamp */}
                <div className="text-xs text-muted-foreground text-right">
                  {formatDateTime(result.timestamp)}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Test Scenarios */}
      <Card>
        <CardHeader>
          <CardTitle>Quick Test Scenarios</CardTitle>
          <CardDescription>Pre-configured tests to validate policy behavior</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-3">
            <button
              className="p-4 border rounded-lg text-left hover:bg-muted transition"
              onClick={() => {
                setActionType("financial_transaction");
                setPayload(JSON.stringify({ amount: 100, currency: "USD" }, null, 2));
                setResult(null);
              }}
            >
              <div className="flex items-center gap-2 mb-2">
                <CheckCircle className="h-4 w-4 text-green-500" />
                <span className="font-medium">Small Transaction</span>
              </div>
              <p className="text-xs text-muted-foreground">
                A $100 transaction within typical limits
              </p>
            </button>

            <button
              className="p-4 border rounded-lg text-left hover:bg-muted transition"
              onClick={() => {
                setActionType("financial_transaction");
                setPayload(JSON.stringify({ amount: 1000, currency: "USD" }, null, 2));
                setResult(null);
              }}
            >
              <div className="flex items-center gap-2 mb-2">
                <AlertCircle className="h-4 w-4 text-yellow-500" />
                <span className="font-medium">Large Transaction</span>
              </div>
              <p className="text-xs text-muted-foreground">
                A $1000 transaction that may exceed limits
              </p>
            </button>

            <button
              className="p-4 border rounded-lg text-left hover:bg-muted transition"
              onClick={() => {
                setActionType("admin_action");
                setPayload(JSON.stringify({ action: "delete_user", user_id: "123" }, null, 2));
                setResult(null);
              }}
            >
              <div className="flex items-center gap-2 mb-2">
                <AlertCircle className="h-4 w-4 text-red-500" />
                <span className="font-medium">Admin Action</span>
              </div>
              <p className="text-xs text-muted-foreground">
                May require higher trust score
              </p>
            </button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
