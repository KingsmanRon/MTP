import Link from "next/link";
import { Shield, Lock, ShieldCheck, FileSearch } from "lucide-react";

export default function HomePage() {
  return (
    <div className="min-h-screen bg-gradient-to-b from-background to-muted">
      {/* Header */}
      <header className="border-b bg-background/80 backdrop-blur-sm sticky top-0 z-50">
        <div className="container mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Shield className="h-8 w-8 text-primary" />
            <span className="text-xl font-bold">Inntris</span>
          </div>
          <nav className="flex items-center gap-6">
            <Link href="/admin" className="text-muted-foreground hover:text-foreground transition">
              Admin Console
            </Link>
            <Link href="/portal" className="text-muted-foreground hover:text-foreground transition">
              Agent Portal
            </Link>
            <Link href="/audit" className="text-muted-foreground hover:text-foreground transition">
              Audit Explorer
            </Link>
            <Link
              href="/admin"
              className="bg-primary text-primary-foreground px-4 py-2 rounded-md hover:bg-primary/90 transition"
            >
              Get Started
            </Link>
          </nav>
        </div>
      </header>

      {/* Hero Section */}
      <main className="container mx-auto px-4 py-20">
        <div className="max-w-4xl mx-auto text-center">
          <h1 className="text-5xl font-bold tracking-tight mb-6">
            Your AI agents are writing production code.
            <br />
            <span className="text-primary">Prove what they actually did.</span>
          </h1>
          <p className="text-xl text-muted-foreground mb-8 max-w-3xl mx-auto">
            Cryptographic identity, policy enforcement, and tamper-proof audit —
            anchored on Base L2. Built for teams running AI agents in production.
          </p>
          <div className="flex gap-4 justify-center">
            <Link
              href="/verify"
              className="bg-primary text-primary-foreground px-6 py-3 rounded-lg font-medium hover:bg-primary/90 transition"
            >
              See a Live Verification
            </Link>
            <Link
              href="/admin"
              className="border border-border px-6 py-3 rounded-lg font-medium hover:bg-muted transition"
            >
              Open Admin Console
            </Link>
          </div>
        </div>

        {/* Problem Statement */}
        <div className="max-w-3xl mx-auto mt-20 text-center">
          <p className="text-2xl font-semibold text-foreground">
            AI agent frameworks can tell you what your agents claimed to do.
          </p>
          <p className="text-2xl font-semibold text-primary mt-2">
            None of them can prove it. Inntris can.
          </p>
        </div>

        {/* Three-Column Feature Section */}
        <div className="grid md:grid-cols-3 gap-8 mt-20">
          <div className="p-6 rounded-xl border bg-card">
            <div className="text-primary mb-4">
              <Lock className="h-8 w-8" />
            </div>
            <h3 className="font-semibold text-lg mb-2">Cryptographic Identity</h3>
            <p className="text-sm text-muted-foreground">
              Every agent signs every action with Ed25519.
              No key, no action. Identity is not optional.
            </p>
          </div>
          <div className="p-6 rounded-xl border bg-card">
            <div className="text-primary mb-4">
              <ShieldCheck className="h-8 w-8" />
            </div>
            <h3 className="font-semibold text-lg mb-2">Policy Before Execution</h3>
            <p className="text-sm text-muted-foreground">
              Block admin actions, financial operations,
              and data exports before they run — not after.
            </p>
          </div>
          <div className="p-6 rounded-xl border bg-card">
            <div className="text-primary mb-4">
              <FileSearch className="h-8 w-8" />
            </div>
            <h3 className="font-semibold text-lg mb-2">Tamper-Proof Audit</h3>
            <p className="text-sm text-muted-foreground">
              Merkle trees. Base L2. Hourly anchoring.
              Every decision independently verifiable.
            </p>
          </div>
        </div>

        {/* Stats Section */}
        <div className="mt-20 grid grid-cols-2 md:grid-cols-4 gap-8">
          <StatCard value="100%" label="Fail-Closed" />
          <StatCard value="Ed25519" label="Cryptographic Signing" />
          <StatCard value="Base L2" label="Blockchain Anchoring" />
          <StatCard value="< 100ms" label="Verification Latency" />
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t mt-20">
        <div className="container mx-auto px-4 py-8">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Shield className="h-5 w-5 text-muted-foreground" />
              <span className="text-muted-foreground">Inntris Core</span>
            </div>
            <p className="text-sm text-muted-foreground">
              Forensic-grade verification for the agentic era
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}

function StatCard({ value, label }: { value: string; label: string }) {
  return (
    <div className="text-center">
      <div className="text-3xl font-bold text-primary">{value}</div>
      <div className="text-sm text-muted-foreground mt-1">{label}</div>
    </div>
  );
}
