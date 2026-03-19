"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import {
  Search,
  CheckCircle2,
  Lock,
  FileCheck2,
  Link2,
  Shield,
  Fingerprint,
  ChevronRight,
} from "lucide-react";
import { InntrisLogo } from "@/components/inntris-logo";

const features = [
  {
    icon: CheckCircle2,
    title: "Instant verification",
    body: "Check any verification record and inspect the policy decision in real time.",
  },
  {
    icon: Lock,
    title: "Cryptographic proof",
    body: "Every verification decision is signed with Ed25519 and can be anchored to Base L2.",
  },
  {
    icon: FileCheck2,
    title: "Tamper-evident audit",
    body: "Merkle proofs let anyone independently verify the integrity of the record.",
  },
];

const verificationFields = [
  { icon: Shield, label: "Verdict", value: "PASS or BLOCK with policy reason" },
  { icon: Fingerprint, label: "Agent identity", value: "Name, ID, trust score, signature" },
  { icon: FileCheck2, label: "Policy decision", value: "Risk level, violations, enforcement result" },
  { icon: Link2, label: "On-chain proof", value: "Transaction hash, Merkle root, Base L2 anchor" },
];

export default function VerifyLandingPage() {
  const [lookupValue, setLookupValue] = useState("");
  const router = useRouter();

  const handleVerify = () => {
    const value = lookupValue.trim();
    if (value) {
      router.push(`/verify/${value}`);
    }
  };

  return (
    <div className="min-h-screen bg-[#07111F] text-[#F5F7FB]">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_top,rgba(76,141,255,0.14),transparent_32%),radial-gradient(circle_at_80%_30%,rgba(143,184,255,0.08),transparent_24%)]" />

      <header className="sticky top-0 z-20 border-b border-white/8 bg-[#07111F]/85 backdrop-blur">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-4 lg:px-8">
          <Link href="/" className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-[#22314D] bg-[#0D1728] shadow-[0_0_0_1px_rgba(255,255,255,0.02)]">
              <InntrisLogo className="h-6 w-6" />
            </div>
            <div>
              <div className="text-lg font-semibold tracking-tight">Inntris</div>
              <div className="text-xs text-[#7F8CA3]">Public Verifier</div>
            </div>
          </Link>

          <nav className="flex items-center gap-3">
            <Link
              href="/audit"
              className="hidden rounded-lg border border-[#22314D] bg-[#0D1728] px-4 py-2 text-sm font-medium text-[#F5F7FB] transition hover:bg-[#101C31] hover:text-white md:inline-flex"
            >
              Explore Audit Explorer
            </Link>
            <Link
              href="/docs"
              className="hidden rounded-lg border border-[#22314D] bg-[#0D1728] px-4 py-2 text-sm font-medium text-[#F5F7FB] transition hover:bg-[#101C31] hover:text-white md:inline-flex"
            >
              Docs
            </Link>
          </nav>
        </div>
      </header>

      <main className="relative">
        <section className="mx-auto max-w-3xl px-6 pb-16 pt-20 text-center lg:px-8 lg:pt-28">
          <div className="mb-6 inline-flex items-center gap-2 rounded-full border border-[#22314D] bg-[#0D1728]/90 px-3 py-1.5 text-sm text-[#AAB7CC]">
            <InntrisLogo className="h-4 w-4" />
            Public, read-only verification
          </div>

          <h1 className="text-4xl font-semibold leading-tight tracking-tight md:text-5xl">
            Verify a decision.{" "}
            <span className="text-[#4C8DFF]">See the proof.</span>
          </h1>

          <p className="mx-auto mt-5 max-w-xl text-lg leading-8 text-[#C4CFDE]">
            Check the policy decision, verification details, and on-chain audit trail of
            any Inntris verification record.
          </p>
        </section>

        <section className="mx-auto max-w-2xl px-6 pb-20 lg:px-8">
          <div className="rounded-[28px] border border-[#22314D] bg-[#0D1728] p-6 shadow-2xl shadow-black/30">
            <div className="flex gap-3">
              <div className="relative flex-1">
                <Search className="absolute left-4 top-1/2 h-5 w-5 -translate-y-1/2 text-[#7F8CA3]" />
                <input
                  type="text"
                  placeholder="Enter verification record ID or transaction hash"
                  value={lookupValue}
                  onChange={(e) => setLookupValue(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleVerify()}
                  className="h-14 w-full rounded-2xl border border-[#22314D] bg-[#101C31] pl-12 pr-4 text-base text-[#F5F7FB] placeholder-[#7F8CA3] outline-none transition focus:border-[#4C8DFF] focus:ring-1 focus:ring-[#4C8DFF]/30"
                />
              </div>

              <Button
                onClick={handleVerify}
                disabled={!lookupValue.trim()}
                className="h-14 rounded-2xl bg-[#4C8DFF] px-8 text-base font-medium text-white hover:bg-[#6AA2FF] disabled:opacity-40"
              >
                Verify
              </Button>
            </div>
          </div>
        </section>

        {/* What each receipt contains */}
        <section className="mx-auto max-w-4xl px-6 pb-16 lg:px-8">
          <h2 className="mb-6 text-center text-lg font-semibold tracking-tight text-[#F5F7FB]">
            What a verification receipt contains
          </h2>
          <div className="grid gap-4 md:grid-cols-2">
            {verificationFields.map((field) => {
              const Icon = field.icon;
              return (
                <div
                  key={field.label}
                  className="flex gap-4 rounded-[20px] border border-[#22314D] bg-[#0D1728] p-5"
                >
                  <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-[#22314D] bg-[#101C31] text-[#8FB8FF]">
                    <Icon className="h-5 w-5" />
                  </div>
                  <div>
                    <h3 className="text-sm font-semibold text-[#F5F7FB]">{field.label}</h3>
                    <p className="mt-1 text-sm leading-6 text-[#AAB7CC]">{field.value}</p>
                  </div>
                </div>
              );
            })}
          </div>
        </section>

        <section className="mx-auto max-w-5xl px-6 pb-20 lg:px-8">
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

        <section className="mx-auto max-w-3xl px-6 pb-24 lg:px-8">
          <div className="rounded-[28px] border border-[#22314D] bg-[#0D1728] p-8 text-center">
            <h2 className="text-2xl font-semibold tracking-tight">
              Want this for your repo?
            </h2>

            <p className="mx-auto mt-3 max-w-md text-base leading-7 text-[#AAB7CC]">
              Add{" "}
              <code className="font-mono text-[#8FB8FF]">inntris-verify</code>{" "}
              to any GitHub repo in minutes. Every agent PR gets a cryptographic
              receipt anchored on Base L2.
            </p>

            <div className="mt-6 flex flex-wrap items-center justify-center gap-3">
              <a
                href="https://github.com/Inntris/agent-orchestrator-guardrails"
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

      <footer className="border-t border-white/8">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-8 lg:px-8">
          <div className="flex items-center gap-2">
            <InntrisLogo className="h-5 w-5" />
            <span className="text-[#7F8CA3]">Inntris Core</span>
          </div>
          <div className="flex items-center gap-6 text-[#7F8CA3]">
            <Link href="/docs" className="text-sm transition-colors hover:text-white">
              Docs
            </Link>
            <Link href="/" className="text-sm transition-colors hover:text-white">
              Home
            </Link>
          </div>
        </div>
      </footer>
    </div>
  );
}
