import Link from "next/link";
import { Shield, Users, FileSearch, Globe } from "lucide-react";

export default function HomePage() {
  return (
    <div className="min-h-screen bg-gradient-to-b from-background to-muted">
      {/* Header */}
      <header className="border-b bg-background/80 backdrop-blur-sm sticky top-0 z-50">
        <div className="container mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Shield className="h-8 w-8 text-primary" />
            <span className="text-xl font-bold">MTP</span>
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
            Machine Trust Protocol
          </h1>
          <p className="text-xl text-muted-foreground mb-8">
            The Security Assurance Layer for AI Agents. Cryptographic verification,
            forensic-grade audit logs, and blockchain-anchored proof — all in one protocol.
          </p>
          <div className="flex gap-4 justify-center">
            <Link
              href="/admin"
              className="bg-primary text-primary-foreground px-6 py-3 rounded-lg font-medium hover:bg-primary/90 transition"
            >
              Open Admin Console
            </Link>
            <Link
              href="/docs"
              className="border border-border px-6 py-3 rounded-lg font-medium hover:bg-muted transition"
            >
              Documentation
            </Link>
          </div>
        </div>

        {/* Feature Cards */}
        <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6 mt-20">
          <FeatureCard
            href="/admin"
            icon={<Users className="h-8 w-8" />}
            title="Admin Console"
            description="Manage organizations, agents, policies, and API keys. Monitor security alerts in real-time."
          />
          <FeatureCard
            href="/portal"
            icon={<Shield className="h-8 w-8" />}
            title="Agent Portal"
            description="Developer dashboard for managing agent credentials, testing verification, and monitoring usage."
          />
          <FeatureCard
            href="/audit"
            icon={<FileSearch className="h-8 w-8" />}
            title="Audit Explorer"
            description="Forensic-grade audit log search with Merkle proof verification and compliance exports."
          />
          <FeatureCard
            href="/verify"
            icon={<Globe className="h-8 w-8" />}
            title="Public Verify"
            description="Publicly verify any agent's trust status and verification history."
          />
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
              <span className="text-muted-foreground">Machine Trust Protocol</span>
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

function FeatureCard({
  href,
  icon,
  title,
  description,
}: {
  href: string;
  icon: React.ReactNode;
  title: string;
  description: string;
}) {
  return (
    <Link
      href={href}
      className="p-6 rounded-xl border bg-card hover:shadow-lg transition group"
    >
      <div className="text-primary mb-4 group-hover:scale-110 transition">
        {icon}
      </div>
      <h3 className="font-semibold text-lg mb-2">{title}</h3>
      <p className="text-sm text-muted-foreground">{description}</p>
    </Link>
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
