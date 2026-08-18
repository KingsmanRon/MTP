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
import { MobileMenu } from "@/components/mobile-menu";
import { SiteFooter } from "@/components/site-footer";

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
    <div className="min-h-screen bg-background text-foreground">
      <div className="pointer-events-none absolute inset-0 bg-gradient-to-b from-accent/50 via-transparent to-transparent" />

      <header className="sticky top-0 z-20 border-b border-tileLine bg-background/85 backdrop-blur">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-4 lg:px-8">
          <Link href="/" className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-tileLine bg-tile">
              <InntrisLogo className="h-6 w-6" />
            </div>
            <div>
              <div className="text-lg font-semibold tracking-tight">Inntris</div>
              <div className="text-xs text-muted-foreground">Public Verifier</div>
            </div>
          </Link>

          <nav className="hidden items-center gap-6 text-sm md:flex">
            <Link href="/admin" className="text-muted-foreground transition hover:text-foreground">Console</Link>
            <Link href="/portal" className="text-muted-foreground transition hover:text-foreground">Portal</Link>
            <Link href="/audit" className="text-muted-foreground transition hover:text-foreground">Audit</Link>
            <Link href="/docs" className="text-muted-foreground transition hover:text-foreground">Docs</Link>
          </nav>
          <MobileMenu
            links={[
              { href: "/admin", label: "Console" },
              { href: "/portal", label: "Portal" },
              { href: "/audit", label: "Audit" },
              { href: "/docs", label: "Docs" },
            ]}
          />
        </div>
      </header>

      <main className="relative">
        <section className="mx-auto max-w-3xl px-6 pb-16 pt-20 text-center lg:px-8 lg:pt-28">
          <div className="mb-6 inline-flex items-center gap-2 rounded-full border border-tileLine bg-tile/90 px-3 py-1.5 text-sm text-muted-foreground">
            <InntrisLogo className="h-4 w-4" />
            Public, read-only verification
          </div>

          <h1 className="text-4xl font-semibold leading-tight tracking-tight md:text-5xl">
            Verify a decision.{" "}
            <span className="text-primary">See the proof.</span>
          </h1>

          <p className="mx-auto mt-5 max-w-xl text-lg leading-8 text-muted-foreground">
            Check the policy decision, verification details, and on-chain audit trail of
            any Inntris verification record.
          </p>
        </section>

        <section className="mx-auto max-w-2xl px-6 pb-20 lg:px-8">
          <div className="rounded-[28px] border border-tileLine bg-tile p-6 shadow-2xl shadow-black/30">
            <div className="flex gap-3">
              <div className="relative flex-1">
                <Search className="absolute left-4 top-1/2 h-5 w-5 -translate-y-1/2 text-muted-foreground" />
                <input
                  type="text"
                  placeholder="Enter verification record ID or transaction hash"
                  value={lookupValue}
                  onChange={(e) => setLookupValue(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleVerify()}
                  className="h-14 w-full rounded-2xl border border-tileLine bg-card pl-12 pr-4 text-base text-foreground placeholder-muted-foreground outline-none transition focus:border-primary focus:ring-1 focus:ring-primary/30"
                />
              </div>

              <Button
                onClick={handleVerify}
                disabled={!lookupValue.trim()}
                className="h-14 rounded-2xl bg-primary px-8 text-base font-medium text-white hover:bg-brandInk disabled:opacity-40"
              >
                Verify
              </Button>
            </div>
          </div>
        </section>

        {/* What each receipt contains */}
        <section className="mx-auto max-w-4xl px-6 pb-16 lg:px-8">
          <h2 className="mb-6 text-center text-lg font-semibold tracking-tight text-foreground">
            What a verification receipt contains
          </h2>
          <div className="grid gap-4 md:grid-cols-2">
            {verificationFields.map((field) => {
              const Icon = field.icon;
              return (
                <div
                  key={field.label}
                  className="flex gap-4 rounded-[20px] border border-tileLine bg-tile p-5"
                >
                  <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-tileLine bg-card text-brandInk">
                    <Icon className="h-5 w-5" />
                  </div>
                  <div>
                    <h3 className="text-sm font-semibold text-foreground">{field.label}</h3>
                    <p className="mt-1 text-sm leading-6 text-muted-foreground">{field.value}</p>
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
                  className="rounded-[24px] border border-tileLine bg-tile p-6"
                >
                  <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-2xl border border-tileLine bg-card text-brandInk">
                    <Icon className="h-6 w-6" />
                  </div>

                  <h3 className="text-lg font-semibold tracking-tight text-foreground">
                    {item.title}
                  </h3>

                  <p className="mt-2 text-[14px] leading-7 text-muted-foreground">
                    {item.body}
                  </p>
                </div>
              );
            })}
          </div>
        </section>

        <section className="mx-auto max-w-3xl px-6 pb-24 lg:px-8">
          <div className="rounded-[28px] border border-tileLine bg-tile p-8 text-center">
            <h2 className="text-2xl font-semibold tracking-tight">
              Want PR protection for your repo?
            </h2>

            <p className="mx-auto mt-3 max-w-md text-base leading-7 text-muted-foreground">
              View the GitHub Actions example for PR protection. It shows how{" "}
              <code className="font-mono text-brandInk">inntris-verify</code>{" "}
              runs as a required status check and records a PASS or BLOCK receipt.
            </p>

            <div className="mt-6 flex flex-wrap items-center justify-center gap-3">
              <Link href="/ai-pr-protection">
                <Button
                  variant="outline"
                  className="border-tileLine bg-tile text-foreground hover:bg-card hover:text-foreground"
                >
                  See buyer page
                </Button>
              </Link>
            </div>
          </div>
        </section>
      </main>

      <SiteFooter className="border-tileLine" />
    </div>
  );
}
