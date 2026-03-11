"use client";

import { useParams } from "next/navigation";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { TrustScore } from "@/components/trust-score";
import { formatDateTime, formatRelative, copyToClipboard } from "@/lib/utils";
import { usePublicAgent } from "@/lib/hooks";
import {
  Shield,
  CheckCircle2,
  XCircle,
  Clock,
  Activity,
  Copy,
  Check,
  ExternalLink,
  AlertTriangle,
  Lock,
  FileCheck2,
  ChevronRight,
} from "lucide-react";
import { useState } from "react";

export default function PublicVerifyPage() {
  const params = useParams();
  const agentId = params.agentId as string;
  const [copied, setCopied] = useState(false);

  const { data: agent, isLoading: loading, error: queryError } = usePublicAgent(agentId);
  const error = queryError ? "Agent not found" : null;

  const handleCopy = async () => {
    await copyToClipboard(window.location.href);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Loading state
  if (loading) {
    return (
      <div className="min-h-screen bg-[#07111F] flex items-center justify-center">
        <div className="text-center">
          <Shield className="h-12 w-12 text-[#4C8DFF] animate-pulse mx-auto mb-4" />
          <p className="text-[#AAB7CC]">Verifying agent...</p>
        </div>
      </div>
    );
  }

  // Error state
  if (error || !agent) {
    return (
      <div className="min-h-screen bg-[#07111F] text-[#F5F7FB]">
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_top,rgba(76,141,255,0.14),transparent_32%)] pointer-events-none" />

        <header className="sticky top-0 z-20 border-b border-white/8 bg-[#07111F]/85 backdrop-blur">
          <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-4 lg:px-8">
            <Link href="/" className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-[#22314D] bg-[#0D1728]">
                <Shield className="h-5 w-5 text-[#8FB8FF]" />
              </div>
              <div className="text-lg font-semibold tracking-tight">Inntris</div>
            </Link>
          </div>
        </header>

        <main className="relative mx-auto max-w-lg px-6 py-20 text-center">
          <div className="rounded-[28px] border border-[#22314D] bg-[#0D1728] p-10">
            <div className="mx-auto mb-5 flex h-16 w-16 items-center justify-center rounded-full bg-[#ef4444]/15">
              <XCircle className="h-8 w-8 text-[#ef4444]" />
            </div>
            <h1 className="text-2xl font-bold mb-2">Agent not found</h1>
            <p className="text-[#AAB7CC] mb-8">
              The agent ID you&apos;re looking for doesn&apos;t exist or has been revoked.
            </p>
            <div className="flex flex-wrap items-center justify-center gap-3">
              <Link href="/verify">
                <Button className="bg-[#4C8DFF] text-white hover:bg-[#6AA2FF]">
                  Search agents
                </Button>
              </Link>
              <Link href="/">
                <Button
                  variant="outline"
                  className="border-[#22314D] bg-[#0D1728] text-[#F5F7FB] hover:bg-[#101C31] hover:text-white"
                >
                  Go home
                </Button>
              </Link>
            </div>
          </div>
        </main>
      </div>
    );
  }

  const isVerified = agent.is_verified;
  const statusColor =
    agent.status === "active"
      ? "bg-[#22c55e]/15 text-[#22c55e] border-[#22c55e]/30"
      : agent.status === "suspended"
      ? "bg-[#f59e0b]/15 text-[#f59e0b] border-[#f59e0b]/30"
      : "bg-[#ef4444]/15 text-[#ef4444] border-[#ef4444]/30";

  return (
    <div className="min-h-screen bg-[#07111F] text-[#F5F7FB]">
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_top,rgba(76,141,255,0.14),transparent_32%),radial-gradient(circle_at_80%_30%,rgba(143,184,255,0.08),transparent_24%)] pointer-events-none" />

      {/* Header */}
      <header className="sticky top-0 z-20 border-b border-white/8 bg-[#07111F]/85 backdrop-blur">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-4 lg:px-8">
          <Link href="/" className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-[#22314D] bg-[#0D1728] shadow-[0_0_0_1px_rgba(255,255,255,0.02)]">
              <Shield className="h-5 w-5 text-[#8FB8FF]" />
            </div>
            <div>
              <div className="text-lg font-semibold tracking-tight">Inntris</div>
              <div className="text-xs text-[#7F8CA3]">Verification record</div>
            </div>
          </Link>
          <div className="flex items-center gap-3">
            <Button
              variant="outline"
              size="sm"
              onClick={handleCopy}
              className="border-[#22314D] bg-[#0D1728] text-[#F5F7FB] hover:bg-[#101C31] hover:text-white"
            >
              {copied ? (
                <Check className="h-4 w-4 mr-2 text-[#28C281]" />
              ) : (
                <Copy className="h-4 w-4 mr-2" />
              )}
              {copied ? "Copied!" : "Share"}
            </Button>
            <Link href="/verify">
              <Button
                variant="outline"
                size="sm"
                className="hidden border-[#22314D] bg-[#0D1728] text-[#F5F7FB] hover:bg-[#101C31] hover:text-white md:inline-flex"
              >
                Verify another
              </Button>
            </Link>
          </div>
        </div>
      </header>

      <main className="relative mx-auto max-w-3xl px-6 py-12 lg:px-8">
        {/* Verification Banner */}
        <div
          className={`rounded-t-[28px] border border-b-0 p-8 text-center ${
            isVerified
              ? "border-[#22c55e]/20 bg-gradient-to-b from-[#22c55e]/8 to-[#0D1728]"
              : "border-[#f59e0b]/20 bg-gradient-to-b from-[#f59e0b]/8 to-[#0D1728]"
          }`}
        >
          <div className="flex items-center justify-center gap-3 mb-4">
            {isVerified ? (
              <div className="flex h-16 w-16 items-center justify-center rounded-full bg-[#22c55e]/15">
                <CheckCircle2 className="h-8 w-8 text-[#22c55e]" />
              </div>
            ) : (
              <div className="flex h-16 w-16 items-center justify-center rounded-full bg-[#f59e0b]/15">
                <AlertTriangle className="h-8 w-8 text-[#f59e0b]" />
              </div>
            )}
          </div>
          <h1 className="text-2xl font-bold mb-1">
            {isVerified ? "Inntris Verified" : "Unverified Agent"}
          </h1>
          <p className="text-[#AAB7CC]">
            {isVerified
              ? "This agent is cryptographically verified by Inntris Core"
              : "This agent has not completed verification"}
          </p>
        </div>

        {/* Main Card */}
        <div className="rounded-b-[28px] border border-[#22314D] bg-[#0D1728] p-6 shadow-2xl shadow-black/30 md:p-8">
          {/* Agent Identity */}
          <div className="flex items-start justify-between gap-4 mb-8">
            <div>
              <h2 className="text-2xl font-bold">{agent.name}</h2>
              <p className="mt-1 text-[#AAB7CC]">{agent.organization_name}</p>
              <div className="mt-3 flex flex-wrap items-center gap-2">
                <span
                  className={`inline-flex items-center rounded-full border px-3 py-1 text-xs font-medium ${statusColor}`}
                >
                  {agent.status}
                </span>
                {isVerified && (
                  <span className="inline-flex items-center gap-1 rounded-full border border-[#4C8DFF]/30 bg-[#4C8DFF]/10 px-3 py-1 text-xs font-medium text-[#8FB8FF]">
                    <Shield className="h-3 w-3" />
                    Inntris Verified
                  </span>
                )}
              </div>
            </div>
            <TrustScore score={agent.trust_score} size="lg" />
          </div>

          {/* Stats Grid */}
          <div className="grid grid-cols-2 gap-4 mb-8">
            <div className="rounded-2xl border border-white/6 bg-[#101C31]/70 p-5">
              <div className="flex items-center gap-2 mb-2">
                <Activity className="h-4 w-4 text-[#7F8CA3]" />
                <span className="text-sm text-[#7F8CA3]">Total actions</span>
              </div>
              <p className="text-3xl font-semibold tracking-tight">
                {agent.total_actions.toLocaleString()}
              </p>
            </div>
            <div className="rounded-2xl border border-white/6 bg-[#101C31]/70 p-5">
              <div className="flex items-center gap-2 mb-2">
                <Shield className="h-4 w-4 text-[#7F8CA3]" />
                <span className="text-sm text-[#7F8CA3]">Trust score</span>
              </div>
              <p className="text-3xl font-semibold tracking-tight">
                <span
                  className={
                    agent.trust_score >= 70
                      ? "text-[#22c55e]"
                      : agent.trust_score >= 40
                      ? "text-[#f59e0b]"
                      : "text-[#ef4444]"
                  }
                >
                  {agent.trust_score}
                </span>
                <span className="text-lg text-[#7F8CA3]">/100</span>
              </p>
            </div>
          </div>

          {/* Detail Rows */}
          <div className="space-y-0 divide-y divide-white/6">
            <div className="flex items-center justify-between py-4">
              <span className="text-sm text-[#7F8CA3]">Verified since</span>
              <span className="text-sm font-medium">
                {agent.verified_since ? formatDateTime(agent.verified_since) : "Not verified"}
              </span>
            </div>
            <div className="flex items-center justify-between py-4">
              <span className="text-sm text-[#7F8CA3]">Last activity</span>
              <span className="text-sm font-medium">
                {agent.last_action_at ? formatRelative(agent.last_action_at) : "Never"}
              </span>
            </div>
            <div className="flex items-center justify-between py-4">
              <span className="text-sm text-[#7F8CA3]">Total actions</span>
              <span className="text-sm font-medium">
                {agent.total_actions.toLocaleString()}
              </span>
            </div>
            <div className="flex items-center justify-between py-4">
              <span className="text-sm text-[#7F8CA3]">Agent ID</span>
              <code className="text-xs font-mono text-[#8FB8FF]">{agent.agent_id}</code>
            </div>
          </div>
        </div>

        {/* On-Chain Proof Section */}
        <div className="mt-6 rounded-[28px] border border-[#22314D] bg-[#0D1728] p-6 md:p-8">
          <div className="flex items-center gap-3 mb-5">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-[#22314D] bg-[#101C31] text-[#8FB8FF]">
              <Lock className="h-5 w-5" />
            </div>
            <div>
              <h3 className="text-lg font-semibold">On-chain proof</h3>
              <p className="text-xs text-[#7F8CA3]">
                Audit records are anchored to Base L2 via Merkle tree
              </p>
            </div>
          </div>
          <div className="space-y-3">
            <div className="flex items-center justify-between rounded-2xl border border-white/6 bg-[#101C31]/70 p-4">
              <div>
                <p className="text-xs text-[#7F8CA3]">Network</p>
                <p className="text-sm font-medium">Base L2 (Chain ID 8453)</p>
              </div>
              <div className="rounded-full border border-[#22314D] bg-[#101C31] px-3 py-1 text-xs text-[#8FB8FF]">
                Mainnet
              </div>
            </div>
            <div className="flex items-center justify-between rounded-2xl border border-white/6 bg-[#101C31]/70 p-4">
              <div>
                <p className="text-xs text-[#7F8CA3]">Anchoring interval</p>
                <p className="text-sm font-medium">Hourly</p>
              </div>
              <div className="rounded-full border border-[#22314D] bg-[#101C31] px-3 py-1 text-xs text-[#8FB8FF]">
                Merkle tree
              </div>
            </div>
            <div className="flex items-center justify-between rounded-2xl border border-white/6 bg-[#101C31]/70 p-4">
              <div>
                <p className="text-xs text-[#7F8CA3]">Signature scheme</p>
                <p className="text-sm font-medium font-mono">Ed25519</p>
              </div>
              <div className="rounded-full border border-[#22314D] bg-[#101C31] px-3 py-1 text-xs text-[#8FB8FF]">
                Cryptographic
              </div>
            </div>
          </div>
        </div>

        {/* Trust Score Explanation */}
        <div className="mt-6 rounded-[28px] border border-[#22314D] bg-[#0D1728] p-6 md:p-8">
          <h3 className="text-lg font-semibold mb-4">About trust scores</h3>
          <p className="text-sm text-[#AAB7CC] mb-5">
            Trust scores range from 0–100 and represent the cumulative
            trustworthiness of an agent based on its verification history.
          </p>
          <div className="grid grid-cols-3 gap-3">
            <div className="rounded-2xl bg-[#22c55e]/10 p-4 text-center">
              <p className="text-lg font-bold text-[#22c55e]">70–100</p>
              <p className="text-xs text-[#AAB7CC]">High trust</p>
            </div>
            <div className="rounded-2xl bg-[#f59e0b]/10 p-4 text-center">
              <p className="text-lg font-bold text-[#f59e0b]">40–69</p>
              <p className="text-xs text-[#AAB7CC]">Medium trust</p>
            </div>
            <div className="rounded-2xl bg-[#ef4444]/10 p-4 text-center">
              <p className="text-lg font-bold text-[#ef4444]">0–39</p>
              <p className="text-xs text-[#AAB7CC]">Low trust</p>
            </div>
          </div>
        </div>

        {/* Embed Badge */}
        <div className="mt-6 rounded-[28px] border border-[#22314D] bg-[#0D1728] p-6 md:p-8">
          <div className="flex items-center gap-3 mb-4">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-[#22314D] bg-[#101C31] text-[#8FB8FF]">
              <FileCheck2 className="h-5 w-5" />
            </div>
            <div>
              <h3 className="text-lg font-semibold">Embed this badge</h3>
              <p className="text-xs text-[#7F8CA3]">
                Add a verification badge to your website or README
              </p>
            </div>
          </div>
          <div className="rounded-2xl border border-white/6 bg-[#101C31]/70 p-4">
            <code className="text-xs text-[#8FB8FF] font-mono break-all leading-relaxed">
              {`<script src="https://inntris.com/badge.js" data-agent="${agent.agent_id}"></script>`}
            </code>
          </div>
        </div>

        {/* Flywheel CTA */}
        <div className="mt-8 rounded-[28px] border border-[#4C8DFF]/20 bg-gradient-to-b from-[#4C8DFF]/8 to-[#0D1728] p-8 text-center">
          <h2 className="text-2xl font-semibold tracking-tight">
            Want this for your repo?
          </h2>
          <p className="mx-auto mt-3 max-w-md text-base leading-7 text-[#AAB7CC]">
            Add <code className="font-mono text-[#8FB8FF]">inntris-verify</code> as a
            required status check. Every agent PR gets a cryptographic receipt.
          </p>
          <div className="mt-6 flex flex-wrap items-center justify-center gap-3">
            <a
              href="https://github.com/KingsmanRon/Inntris"
              target="_blank"
              rel="noopener noreferrer"
            >
              <Button className="bg-[#4C8DFF] px-6 text-white hover:bg-[#6AA2FF]">
                Install GitHub Action
                <ChevronRight className="ml-1 h-4 w-4" />
              </Button>
            </a>
            <Link href="/">
              <Button
                variant="outline"
                className="border-[#22314D] bg-[#0D1728] text-[#F5F7FB] hover:bg-[#101C31] hover:text-white"
              >
                Learn more
              </Button>
            </Link>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-white/8 mt-12">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-8 lg:px-8">
          <div className="flex items-center gap-2">
            <Shield className="h-5 w-5 text-[#7F8CA3]" />
            <span className="text-[#7F8CA3]">Inntris Core</span>
          </div>
          <p className="text-sm text-[#7F8CA3]">
            Cryptographic verification for AI agents
          </p>
        </div>
      </footer>
    </div>
  );
}
