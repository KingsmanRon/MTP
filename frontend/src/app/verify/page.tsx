"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import {
  Shield,
  Search,
  CheckCircle2,
  ExternalLink,
  Lock,
  FileCheck2,
  ChevronRight,
} from "lucide-react";

const exampleAgents = [
  { id: "a1b2c3d4-e5f6-7890-abcd-ef1234567890", name: "PaymentBot", org: "FinanceOps Inc.", score: 85 },
  { id: "b2c3d4e5-f6a7-8901-bcde-f12345678901", name: "DataExporter", org: "DataPipeline Co.", score: 72 },
  { id: "c3d4e5f6-a7b8-9012-cdef-123456789012", name: "EmailAgent", org: "CommsHub Ltd.", score: 91 },
];

const features = [
  {
    icon: CheckCircle2,
    title: "Instant verification",
    body: "Check any agent's trust status and policy compliance in real-time.",
  },
  {
    icon: Lock,
    title: "Cryptographic proof",
    body: "Every verification decision is signed and anchored to Base L2.",
  },
  {
    icon: FileCheck2,
    title: "Tamper-evident audit",
    body: "Merkle proofs let anyone independently verify the record.",
  },
];

export default function VerifyLandingPage() {
  const [agentId, setAgentId] = useState("");
  const router = useRouter();

  const handleVerify = () => {
    if (agentId.trim()) {
      router.push(`/verify/${agentId.trim()}`);
    }
  };

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
              <div className="text-xs text-[#7F8CA3]">Public verifier</div>
            </div>
          </Link>
          <nav className="flex items-center gap-3">
            <Link href="/admin">
              <Button
                variant="outline"
                className="hidden border-[#22314D] bg-[#0D1728] text-[#F5F7FB] hover:bg-[#101C31] hover:text-white md:inline-flex"
              >
                Admin Console
              </Button>
            </Link>
            <Link href="/audit">
              <Button
                variant="outline"
                className="hidden border-[#22314D] bg-[#0D1728] text-[#F5F7FB] hover:bg-[#101C31] hover:text-white md:inline-flex"
              >
                Audit Explorer
              </Button>
            </Link>
          </nav>
        </div>
      </header>

      <main className="relative">
        {/* Hero */}
        <section className="mx-auto max-w-3xl px-6 pb-16 pt-20 text-center lg:px-8 lg:pt-28">
          <div className="mb-6 inline-flex items-center gap-2 rounded-full border border-[#22314D] bg-[#0D1728]/90 px-3 py-1.5 text-sm text-[#AAB7CC]">
            <Shield className="h-4 w-4 text-[#28C281]" />
            Public, read-only verification
          </div>
          <h1 className="text-4xl font-semibold leading-tight tracking-tight md:text-5xl">
            Verify an AI agent.{" "}
            <span className="text-[#4C8DFF]">See the proof.</span>
          </h1>
          <p className="mx-auto mt-5 max-w-xl text-lg leading-8 text-[#C4CFDE]">
            Inspect the policy decision, verification details, and on-chain audit trail
            for any Inntris verification record.
          </p>
        </section>

        {/* Search */}
        <section className="mx-auto max-w-2xl px-6 pb-20 lg:px-8">
          <div className="rounded-[28px] border border-[#22314D] bg-[#0D1728] p-6 shadow-2xl shadow-black/30">
            <div className="flex gap-3">
              <div className="relative flex-1">
                <Search className="absolute left-4 top-1/2 h-5 w-5 -translate-y-1/2 text-[#7F8CA3]" />
                <input
                  type="text"
                  placeholder="Enter agent ID or transaction hash"
                  value={agentId}
                  onChange={(e) => setAgentId(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleVerify()}
                  className="h-14 w-full rounded-2xl border border-[#22314D] bg-[#101C31] pl-12 pr-4 text-base text-[#F5F7FB] placeholder-[#7F8CA3] outline-none transition focus:border-[#4C8DFF] focus:ring-1 focus:ring-[#4C8DFF]/30"
                />
              </div>
              <Button
                onClick={handleVerify}
                disabled={!agentId.trim()}
                className="h-14 rounded-2xl bg-[#4C8DFF] px-8 text-base font-medium text-white hover:bg-[#6AA2FF] disabled:opacity-40"
              >
                Verify
              </Button>
            </div>
          </div>
        </section>

        {/* Features */}
        <section className="mx-auto max-w-5xl px-6 pb-16 lg:px-8">
          <div className="grid gap-5 md:grid-cols-3">
            {features.map((item) => {
              const Icon = item.icon;
              return (
                <div
                  key={item.title}
                  className="rounded-[24px] border border-[#22314D] bg-[#0D1728] p-6"
                >
                  <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-2xl border border-[#22314D] bg-[#101C31] text-[#8FB8FF]">
                    <Icon className="h-6 w-6" />
                  </div>
                  <h3 className="text-lg font-semibold tracking-tight text-[#F5F7FB]">
                    {item.title}
                  </h3>
                  <p className="mt-2 text-[14px] leading-7 text-[#AAB7CC]">
                    {item.body}
                  </p>
                </div>
              );
            })}
          </div>
        </section>

        {/* Example Agents */}
        <section className="mx-auto max-w-3xl px-6 pb-20 lg:px-8">
          <div className="rounded-[28px] border border-[#22314D] bg-[#0D1728] p-6">
            <div className="mb-5">
              <h2 className="text-xl font-semibold tracking-tight">
                Example verified agents
              </h2>
              <p className="mt-1 text-sm text-[#AAB7CC]">
                Click to view verification details
              </p>
            </div>
            <div className="space-y-3">
              {exampleAgents.map((agent) => (
                <Link
                  key={agent.id}
                  href={`/verify/${agent.id}`}
                  className="group flex items-center justify-between rounded-2xl border border-white/6 bg-[#101C31]/70 p-5 transition hover:border-[#35507A] hover:bg-[#101C31]"
                >
                  <div className="flex items-center gap-4">
                    <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-[#28C281]/15">
                      <CheckCircle2 className="h-5 w-5 text-[#28C281]" />
                    </div>
                    <div>
                      <p className="font-medium text-[#F5F7FB]">{agent.name}</p>
                      <p className="mt-0.5 text-xs text-[#7F8CA3]">{agent.org}</p>
                      <code className="mt-1 block text-xs text-[#7F8CA3] font-mono">
                        {agent.id.slice(0, 16)}...
                      </code>
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <span
                      className={`text-lg font-semibold ${
                        agent.score >= 70
                          ? "text-[#22c55e]"
                          : agent.score >= 40
                          ? "text-[#f59e0b]"
                          : "text-[#ef4444]"
                      }`}
                    >
                      {agent.score}
                    </span>
                    <ChevronRight className="h-4 w-4 text-[#7F8CA3] transition group-hover:text-white" />
                  </div>
                </Link>
              ))}
            </div>
          </div>
        </section>

        {/* CTA — Flywheel */}
        <section className="mx-auto max-w-3xl px-6 pb-24 lg:px-8">
          <div className="rounded-[28px] border border-[#22314D] bg-[#0D1728] p-8 text-center">
            <h2 className="text-2xl font-semibold tracking-tight">
              Want this for your repo?
            </h2>
            <p className="mx-auto mt-3 max-w-md text-base leading-7 text-[#AAB7CC]">
              Add <code className="font-mono text-[#8FB8FF]">inntris-verify</code> to
              any GitHub repo in minutes. Every agent PR gets a cryptographic receipt
              anchored on Base L2.
            </p>
            <div className="mt-6 flex flex-wrap items-center justify-center gap-3">
              <a
                href="https://github.com/KingsmanRon/Inntris"
                target="_blank"
                rel="noopener noreferrer"
              >
                <Button className="bg-[#4C8DFF] px-6 text-white hover:bg-[#6AA2FF]">
                  Install GitHub Action
                </Button>
              </a>
              <Link href="/docs">
                <Button
                  variant="outline"
                  className="border-[#22314D] bg-[#0D1728] text-[#F5F7FB] hover:bg-[#101C31] hover:text-white"
                >
                  View Documentation
                </Button>
              </Link>
            </div>
          </div>
        </section>
      </main>

      {/* Footer */}
      <footer className="border-t border-white/8">
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
