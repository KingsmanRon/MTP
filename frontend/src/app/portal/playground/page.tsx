"use client";

import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Select } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { VerdictBadge } from "@/components/verdict-badge";
import { TrustScoreBadge } from "@/components/trust-score";
import { formatDateTime, copyToClipboard } from "@/lib/utils";
import { Play, Copy, Check, AlertCircle, CheckCircle, Loader2 } from "lucide-react";
import type { ActionVerdict } from "@/lib/api";

interface VerificationResult {
  verdict: ActionVerdict;
  verdict_reason: string;
  approval_token?: string;
  trust_score: number;
  audit_id: string;
  timestamp: string;
  limits_remaining?: {
    daily_usd: number;
    per_action_usd: number;
    rate_limit: number;
  };
}

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

export default function PlaygroundPage() {
  const [actionType, setActionType] = useState("financial_transaction");
  const [payload, setPayload] = useState(JSON.stringify(SAMPLE_PAYLOADS.financial_transaction, null, 2));
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState<VerificationResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);

  const handleActionTypeChange = (newType: string) => {
    setActionType(newType);
    setPayload(JSON.stringify(SAMPLE_PAYLOADS[newType] || {}, null, 2));
    setResult(null);
    setError(null);
  };

  const handleTest = async () => {
    setIsLoading(true);
    setError(null);
    setResult(null);

    // Validate JSON
    try {
      JSON.parse(payload);
    } catch {
      setError("Invalid JSON payload");
      setIsLoading(false);
      return;
    }

    // Simulate API call
    await new Promise((resolve) => setTimeout(resolve, 1000));

    // Mock response based on action type and payload
    const parsedPayload = JSON.parse(payload);
    let mockResult: VerificationResult;

    // Simulate different scenarios
    if (actionType === "admin_action") {
      mockResult = {
        verdict: "blocked",
        verdict_reason: "Trust score 85 below required 70 for admin_action",
        trust_score: 85,
        audit_id: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        limits_remaining: {
          daily_usd: 7654.33,
          per_action_usd: 500,
          rate_limit: 58,
        },
      };
    } else if (actionType === "financial_transaction" && parsedPayload.amount > 500) {
      mockResult = {
        verdict: "blocked",
        verdict_reason: `Amount $${parsedPayload.amount} exceeds per-action limit of $500`,
        trust_score: 85,
        audit_id: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        limits_remaining: {
          daily_usd: 7654.33,
          per_action_usd: 500,
          rate_limit: 58,
        },
      };
    } else {
      mockResult = {
        verdict: "approved",
        verdict_reason: "All verification checks passed",
        approval_token: "mtp_" + crypto.randomUUID().replace(/-/g, ""),
        trust_score: 85,
        audit_id: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        limits_remaining: {
          daily_usd: actionType === "financial_transaction" ? 7654.33 - parsedPayload.amount : 7654.33,
          per_action_usd: 500,
          rate_limit: 57,
        },
      };
    }

    setResult(mockResult);
    setIsLoading(false);
  };

  const handleCopy = async (text: string, id: string) => {
    await copyToClipboard(text);
    setCopied(id);
    setTimeout(() => setCopied(null), 2000);
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Verification Playground</h1>
        <p className="text-muted-foreground">
          Test verification requests and see how MTP evaluates your actions
        </p>
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

            <p className="text-xs text-muted-foreground">
              Note: This is a simulated test. In production, requests would be cryptographically
              signed with your private key.
            </p>
          </CardContent>
        </Card>

        {/* Response Panel */}
        <Card>
          <CardHeader>
            <CardTitle>Response</CardTitle>
            <CardDescription>Verification result and details</CardDescription>
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
                        <p className="text-xs text-muted-foreground">Daily</p>
                        <p className="text-sm font-medium">
                          ${result.limits_remaining.daily_usd.toFixed(2)}
                        </p>
                      </div>
                      <div className="p-2 bg-muted rounded-lg text-center">
                        <p className="text-xs text-muted-foreground">Per Action</p>
                        <p className="text-sm font-medium">
                          ${result.limits_remaining.per_action_usd}
                        </p>
                      </div>
                      <div className="p-2 bg-muted rounded-lg text-center">
                        <p className="text-xs text-muted-foreground">Rate Limit</p>
                        <p className="text-sm font-medium">{result.limits_remaining.rate_limit}/min</p>
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
          <CardTitle>Test Scenarios</CardTitle>
          <CardDescription>Quick test different verification scenarios</CardDescription>
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
                <span className="font-medium">Approved Transaction</span>
              </div>
              <p className="text-xs text-muted-foreground">
                A $100 transaction within limits
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
                <AlertCircle className="h-4 w-4 text-red-500" />
                <span className="font-medium">Exceeds Limit</span>
              </div>
              <p className="text-xs text-muted-foreground">
                A $1000 transaction exceeding per-action limit
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
                <span className="font-medium">Insufficient Trust</span>
              </div>
              <p className="text-xs text-muted-foreground">
                An admin action requiring higher trust score
              </p>
            </button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
