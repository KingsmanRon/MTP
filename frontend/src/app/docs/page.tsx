"use client";

import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { InntrisLogo } from "@/components/inntris-logo";
import {
  Shield,
  Lock,
  FileSearch,
  Zap,
  Globe,
  Building2,
  Bot,
  CheckCircle,
  ArrowRight,
  ExternalLink,
  Github,
  BookOpen,
  Code,
  Layers,
  Database,
  Key,
} from "lucide-react";

export default function DocsPage() {
  return (
    <div className="min-h-screen bg-gradient-to-b from-background to-muted/20">
      {/* Header */}
      <header className="border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60 sticky top-0 z-50">
        <div className="container mx-auto px-4 py-4 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-2">
            <InntrisLogo className="h-8 w-8" />
            <span className="text-xl font-bold">Inntris</span>
          </Link>
          <nav className="hidden md:flex items-center gap-6">
            <Link href="/docs" className="text-sm font-medium text-primary">
              Documentation
            </Link>
            <Link href="/verify" className="text-sm font-medium text-muted-foreground hover:text-foreground">
              Verify Agent
            </Link>
            <Link href="/admin" className="text-sm font-medium text-muted-foreground hover:text-foreground">
              Demo Console
            </Link>
          </nav>
        </div>
      </header>

      {/* Hero Section */}
      <section className="container mx-auto px-4 py-16 md:py-24">
        <div className="max-w-4xl mx-auto text-center">
          <Badge variant="secondary" className="mb-4">
            Documentation
          </Badge>
          <h1 className="text-4xl md:text-6xl font-bold tracking-tight mb-6">
            Inntris
          </h1>
          <p className="text-xl md:text-2xl text-muted-foreground mb-4">
            Runtime verification and cryptographic proof for AI agent actions.
          </p>
          <p className="text-lg text-muted-foreground max-w-2xl mx-auto mb-8">
            Inntris verifies agent actions before execution, signs decisions with agent identity,
            and produces a tamper-evident receipt for every decision.
          </p>
          <div className="flex flex-wrap justify-center gap-4">
            <Link href="#getting-started">
              <Button size="lg">
                Get Started
                <ArrowRight className="ml-2 h-4 w-4" />
              </Button>
            </Link>
            <Link href="/verify">
              <Button size="lg" variant="outline">
                See live verification
              </Button>
            </Link>
          </div>
        </div>
      </section>

      {/* What Inntris Is */}
      <section className="container mx-auto px-4 py-16 border-t">
        <div className="max-w-4xl mx-auto">
          <div className="text-center mb-12">
            <h2 className="text-3xl font-bold mb-4">What Inntris Is</h2>
            <p className="text-lg text-muted-foreground">
              A policy decision point and evidence system for AI agent actions
            </p>
          </div>

          <div className="prose prose-gray dark:prose-invert max-w-none">
            <Card className="mb-8">
              <CardContent className="pt-6">
                <p className="text-lg leading-relaxed mb-4">
                  Inntris is not observability, logging, or prompt guardrails. It is a policy decision
                  point and evidence system for AI agent actions.
                </p>
                <ul className="space-y-3 text-lg">
                  <li className="flex items-start gap-2">
                    <CheckCircle className="h-5 w-5 text-green-500 mt-1 flex-shrink-0" />
                    Verifies actions before execution — financial transactions, API calls, data access, and more
                  </li>
                  <li className="flex items-start gap-2">
                    <CheckCircle className="h-5 w-5 text-green-500 mt-1 flex-shrink-0" />
                    Signs every decision with verifiable agent identity (Ed25519)
                  </li>
                  <li className="flex items-start gap-2">
                    <CheckCircle className="h-5 w-5 text-green-500 mt-1 flex-shrink-0" />
                    Enforces spending limits, rate limits, and action type restrictions before an agent can act
                  </li>
                  <li className="flex items-start gap-2">
                    <CheckCircle className="h-5 w-5 text-green-500 mt-1 flex-shrink-0" />
                    Records tamper-evident evidence for every approval, block, and exception
                  </li>
                </ul>
                <p className="text-lg leading-relaxed mt-4 text-muted-foreground">
                  Built for teams that need stronger control and clearer proof than logs, screenshots,
                  or after-the-fact review.
                </p>
              </CardContent>
            </Card>
          </div>
        </div>
      </section>

      {/* What We Do */}
      <section className="container mx-auto px-4 py-16 bg-muted/30">
        <div className="max-w-6xl mx-auto">
          <div className="text-center mb-12">
            <h2 className="text-3xl font-bold mb-4">What We Do</h2>
            <p className="text-lg text-muted-foreground">
              Four pillars of trust for autonomous AI systems
            </p>
          </div>

          <div className="grid md:grid-cols-2 gap-6">
            <Card>
              <CardHeader>
                <div className="w-12 h-12 rounded-lg bg-primary/10 flex items-center justify-center mb-4">
                  <Key className="h-6 w-6 text-primary" />
                </div>
                <CardTitle>Cryptographic Identity</CardTitle>
                <CardDescription>
                  Every agent gets a unique Ed25519 keypair
                </CardDescription>
              </CardHeader>
              <CardContent>
                <ul className="space-y-2 text-sm text-muted-foreground">
                  <li className="flex items-start gap-2">
                    <CheckCircle className="h-4 w-4 text-green-500 mt-0.5 flex-shrink-0" />
                    Unforgeable digital signatures for every action
                  </li>
                  <li className="flex items-start gap-2">
                    <CheckCircle className="h-4 w-4 text-green-500 mt-0.5 flex-shrink-0" />
                    Nonce-based replay attack prevention
                  </li>
                  <li className="flex items-start gap-2">
                    <CheckCircle className="h-4 w-4 text-green-500 mt-0.5 flex-shrink-0" />
                    Automatic signature verification on every request
                  </li>
                </ul>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <div className="w-12 h-12 rounded-lg bg-primary/10 flex items-center justify-center mb-4">
                  <Shield className="h-6 w-6 text-primary" />
                </div>
                <CardTitle>Policy Enforcement</CardTitle>
                <CardDescription>
                  Configurable guardrails for every agent
                </CardDescription>
              </CardHeader>
              <CardContent>
                <ul className="space-y-2 text-sm text-muted-foreground">
                  <li className="flex items-start gap-2">
                    <CheckCircle className="h-4 w-4 text-green-500 mt-0.5 flex-shrink-0" />
                    Daily and per-action spending limits
                  </li>
                  <li className="flex items-start gap-2">
                    <CheckCircle className="h-4 w-4 text-green-500 mt-0.5 flex-shrink-0" />
                    Rate limiting to prevent runaway agents
                  </li>
                  <li className="flex items-start gap-2">
                    <CheckCircle className="h-4 w-4 text-green-500 mt-0.5 flex-shrink-0" />
                    Action type restrictions (allow/block lists)
                  </li>
                </ul>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <div className="w-12 h-12 rounded-lg bg-primary/10 flex items-center justify-center mb-4">
                  <FileSearch className="h-6 w-6 text-primary" />
                </div>
                <CardTitle>Tamper-Evident Audit Trail</CardTitle>
                <CardDescription>
                  Verifiable records of every agent decision
                </CardDescription>
              </CardHeader>
              <CardContent>
                <ul className="space-y-2 text-sm text-muted-foreground">
                  <li className="flex items-start gap-2">
                    <CheckCircle className="h-4 w-4 text-green-500 mt-0.5 flex-shrink-0" />
                    Append-only audit logs (immutable)
                  </li>
                  <li className="flex items-start gap-2">
                    <CheckCircle className="h-4 w-4 text-green-500 mt-0.5 flex-shrink-0" />
                    Complete payload capture with signatures
                  </li>
                  <li className="flex items-start gap-2">
                    <CheckCircle className="h-4 w-4 text-green-500 mt-0.5 flex-shrink-0" />
                    Designed for enterprise audit requirements
                  </li>
                </ul>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <div className="w-12 h-12 rounded-lg bg-primary/10 flex items-center justify-center mb-4">
                  <Database className="h-6 w-6 text-primary" />
                </div>
                <CardTitle>Blockchain Anchoring</CardTitle>
                <CardDescription>
                  Tamper-proof verification on Base L2
                </CardDescription>
              </CardHeader>
              <CardContent>
                <ul className="space-y-2 text-sm text-muted-foreground">
                  <li className="flex items-start gap-2">
                    <CheckCircle className="h-4 w-4 text-green-500 mt-0.5 flex-shrink-0" />
                    Merkle tree batching (hourly anchors)
                  </li>
                  <li className="flex items-start gap-2">
                    <CheckCircle className="h-4 w-4 text-green-500 mt-0.5 flex-shrink-0" />
                    On-chain proof verification
                  </li>
                  <li className="flex items-start gap-2">
                    <CheckCircle className="h-4 w-4 text-green-500 mt-0.5 flex-shrink-0" />
                    Independent auditability by anyone
                  </li>
                </ul>
              </CardContent>
            </Card>
          </div>
        </div>
      </section>

      {/* How It Works */}
      <section id="getting-started" className="container mx-auto px-4 py-16 border-t">
        <div className="max-w-4xl mx-auto">
          <div className="text-center mb-12">
            <h2 className="text-3xl font-bold mb-4">How It Works</h2>
            <p className="text-lg text-muted-foreground">
              Simple integration, powerful protection
            </p>
          </div>

          <div className="space-y-8">
            {/* Step 1 */}
            <div className="flex gap-6">
              <div className="flex-shrink-0">
                <div className="w-10 h-10 rounded-full bg-primary text-primary-foreground flex items-center justify-center font-bold">
                  1
                </div>
              </div>
              <div>
                <h3 className="text-xl font-semibold mb-2">Register Your Agent</h3>
                <p className="text-muted-foreground mb-4">
                  Create an organization and register your AI agent. Inntris generates a unique
                  Ed25519 keypair — you keep the private key, we store the public key.
                </p>
                <Card className="bg-muted/50">
                  <CardContent className="p-4">
                    <pre className="text-sm overflow-x-auto">
{`POST /admin/organizations
{
  "name": "Acme Corp",
  "contact_email": "security@acme.com"
}

POST /admin/agents
{
  "name": "PaymentBot",
  "description": "Handles customer refunds"
}`}
                    </pre>
                  </CardContent>
                </Card>
              </div>
            </div>

            {/* Step 2 */}
            <div className="flex gap-6">
              <div className="flex-shrink-0">
                <div className="w-10 h-10 rounded-full bg-primary text-primary-foreground flex items-center justify-center font-bold">
                  2
                </div>
              </div>
              <div>
                <h3 className="text-xl font-semibold mb-2">Configure Policies</h3>
                <p className="text-muted-foreground mb-4">
                  Set spending limits, rate limits, and allowed action types. These guardrails
                  protect you from runaway agents and unauthorized actions.
                </p>
                <Card className="bg-muted/50">
                  <CardContent className="p-4">
                    <pre className="text-sm overflow-x-auto">
{`PATCH /admin/agents/{agent_id}
{
  "daily_limit_usd": 10000,
  "per_action_limit_usd": 1000,
  "rate_limit_per_minute": 60,
  "allowed_actions": ["financial_transaction", "email_send"]
}`}
                    </pre>
                  </CardContent>
                </Card>
              </div>
            </div>

            {/* Step 3 */}
            <div className="flex gap-6">
              <div className="flex-shrink-0">
                <div className="w-10 h-10 rounded-full bg-primary text-primary-foreground flex items-center justify-center font-bold">
                  3
                </div>
              </div>
              <div>
                <h3 className="text-xl font-semibold mb-2">Integrate with MCP</h3>
                <p className="text-muted-foreground mb-4">
                  Add the Inntris MCP server to your AI agent. The <code className="bg-muted px-1 rounded">inntris_guard</code> tool
                  automatically intercepts critical actions and verifies them before execution.
                </p>
                <Card className="bg-muted/50">
                  <CardContent className="p-4">
                    <pre className="text-sm overflow-x-auto">
{`// claude_desktop_config.json
{
  "mcpServers": {
    "inntris": {
      "command": "python",
      "args": ["-m", "mcp_server.server"],
      "env": {
        "INNTRIS_API_URL": "https://api.inntris.com",
        "INNTRIS_API_KEY": "<your-api-key>",
        "INNTRIS_AGENT_ID": "<your-agent-id>"
      }
    }
  }
}`}
                    </pre>
                  </CardContent>
                </Card>
              </div>
            </div>

            {/* Step 4 */}
            <div className="flex gap-6">
              <div className="flex-shrink-0">
                <div className="w-10 h-10 rounded-full bg-primary text-primary-foreground flex items-center justify-center font-bold">
                  4
                </div>
              </div>
              <div>
                <h3 className="text-xl font-semibold mb-2">Verify & Audit</h3>
                <p className="text-muted-foreground mb-4">
                  Every action is cryptographically signed, verified against policies, and logged
                  to an immutable audit trail. Merkle roots are anchored to Base L2 hourly.
                </p>
                <div className="grid sm:grid-cols-3 gap-4">
                  <Card className="bg-green-500/10 border-green-500/20">
                    <CardContent className="p-4 text-center">
                      <CheckCircle className="h-8 w-8 text-green-500 mx-auto mb-2" />
                      <p className="font-medium text-green-700 dark:text-green-400">APPROVED</p>
                      <p className="text-xs text-muted-foreground">Action verified & logged</p>
                    </CardContent>
                  </Card>
                  <Card className="bg-red-500/10 border-red-500/20">
                    <CardContent className="p-4 text-center">
                      <Shield className="h-8 w-8 text-red-500 mx-auto mb-2" />
                      <p className="font-medium text-red-700 dark:text-red-400">BLOCKED</p>
                      <p className="text-xs text-muted-foreground">Policy violation</p>
                    </CardContent>
                  </Card>
                  <Card className="bg-yellow-500/10 border-yellow-500/20">
                    <CardContent className="p-4 text-center">
                      <Zap className="h-8 w-8 text-yellow-500 mx-auto mb-2" />
                      <p className="font-medium text-yellow-700 dark:text-yellow-400">RATE LIMITED</p>
                      <p className="text-xs text-muted-foreground">Too many requests</p>
                    </CardContent>
                  </Card>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Verification Receipt */}
      <section className="container mx-auto px-4 py-16 border-t">
        <div className="max-w-4xl mx-auto">
          <div className="text-center mb-12">
            <h2 className="text-3xl font-bold mb-4">Verification Receipt</h2>
            <p className="text-lg text-muted-foreground">
              Every decision produces a signed receipt you can inspect, share, or verify on-chain.
            </p>
          </div>

          <Card className="mb-8">
            <CardContent className="pt-6">
              <pre className="text-sm overflow-x-auto">
{`{
  "verdict": "approved",
  "agent_id": "uuid",
  "action_type": "financial_transaction",
  "approval_token": "base64_signed_token",
  "trust_score": 85,
  "audit_id": "uuid",
  "timestamp": "2025-01-15T10:30:01Z",
  "anchored": true,
  "transaction_hash": "0x517853a7400bffc3446fc73711a0cee2f45c82fc1b89d37e76aa3797eb951a77",
  "root_hash": "e56891f1de39aca50725f0e36ee4b1c4fe1c50966f69a1b368e1d691c2466149"
}`}
              </pre>
            </CardContent>
          </Card>

          <p className="text-muted-foreground mb-6">
            Receipts are stored in the tamper-evident audit trail and Merkle roots are anchored
            to Base L2 hourly. Any record can be independently verified by audit ID or transaction hash.
          </p>

          <Link href="/verify" className="text-primary hover:underline flex items-center gap-1">
            <ArrowRight className="h-4 w-4" />
            See live verification
          </Link>
        </div>
      </section>

      {/* Our Goal */}
      <section className="container mx-auto px-4 py-16 bg-muted/30">
        <div className="max-w-4xl mx-auto">
          <div className="text-center mb-12">
            <h2 className="text-3xl font-bold mb-4">Our Goal</h2>
            <p className="text-lg text-muted-foreground">
              Building the trust infrastructure for the agentic future
            </p>
          </div>

          <div className="grid md:grid-cols-2 gap-8">
            <Card>
              <CardHeader>
                <Globe className="h-8 w-8 text-primary mb-2" />
                <CardTitle>Universal Standard</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-muted-foreground">
                  We aim to become the universal verification standard for AI agents —
                  the "VISA network" for autonomous systems. Any agent, any platform,
                  one trust layer.
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <Building2 className="h-8 w-8 text-primary mb-2" />
                <CardTitle>Enterprise Ready</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-muted-foreground">
                  From startups to regulated enterprises, Inntris scales with your needs.
                  Built for auditability. Designed for enterprise control requirements.
                  Optional on-premise deployment available for compliance-heavy industries.
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <Lock className="h-8 w-8 text-primary mb-2" />
                <CardTitle>Liability Clarity</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-muted-foreground">
                  When an AI agent takes action, you need proof of what happened and whether
                  it was authorised. Inntris gives you a signed, verifiable record for every
                  decision — before the action runs, not reconstructed after the fact.
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <Bot className="h-8 w-8 text-primary mb-2" />
                <CardTitle>Agent Ecosystem</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-muted-foreground">
                  Compatible with Claude, GPT, Gemini, and any MCP-compatible agent.
                  Native integration with the Model Context Protocol for seamless
                  verification.
                </p>
              </CardContent>
            </Card>
          </div>
        </div>
      </section>

      {/* Start Here */}
      <section className="container mx-auto px-4 py-16 border-t">
        <div className="max-w-4xl mx-auto">
          <div className="text-center mb-12">
            <h2 className="text-3xl font-bold mb-4">Start Here</h2>
            <p className="text-lg text-muted-foreground">
              The fastest path to verification coverage is pull request verification.
            </p>
          </div>

          <Card>
            <CardContent className="pt-6">
              <p className="text-lg leading-relaxed mb-4">
                Add <code className="bg-muted px-1 rounded">inntris-verify</code> to any GitHub repo.
                Every agent-generated PR gets a cryptographic receipt — signed by agent identity and
                anchored to Base L2.
              </p>
              <div className="flex flex-wrap gap-4 mb-4">
                <a
                  href="https://github.com/Inntris/agent-orchestrator-guardrails"
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  <Button>
                    Install GitHub Action
                    <ArrowRight className="ml-2 h-4 w-4" />
                  </Button>
                </a>
                <Link href="/verify">
                  <Button variant="outline">
                    See live verification
                    <ArrowRight className="ml-2 h-4 w-4" />
                  </Button>
                </Link>
              </div>
              <p className="text-sm text-muted-foreground">
                Works with GitHub PR workflows, MCP-compatible agent systems, and custom agent stacks
                via direct API integration.
              </p>
            </CardContent>
          </Card>
        </div>
      </section>

      {/* Quick Links */}
      <section className="container mx-auto px-4 py-16 border-t">
        <div className="max-w-4xl mx-auto">
          <div className="text-center mb-12">
            <h2 className="text-3xl font-bold mb-4">Explore Inntris</h2>
            <p className="text-lg text-muted-foreground">
              Get started with the platform
            </p>
          </div>

          <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <Link href="/verify">
              <Card className="hover:border-primary transition-colors cursor-pointer h-full">
                <CardContent className="p-6 text-center">
                  <Shield className="h-8 w-8 mx-auto mb-3 text-primary" />
                  <h3 className="font-semibold mb-1">Public Verify</h3>
                  <p className="text-sm text-muted-foreground">Inspect a live receipt</p>
                </CardContent>
              </Card>
            </Link>

            <Link href="/admin">
              <Card className="hover:border-primary transition-colors cursor-pointer h-full">
                <CardContent className="p-6 text-center">
                  <Layers className="h-8 w-8 mx-auto mb-3 text-primary" />
                  <h3 className="font-semibold mb-1">Admin Console</h3>
                  <p className="text-sm text-muted-foreground">Demo &middot; Manage agents & policies</p>
                </CardContent>
              </Card>
            </Link>

            <Link href="/portal">
              <Card className="hover:border-primary transition-colors cursor-pointer h-full">
                <CardContent className="p-6 text-center">
                  <Code className="h-8 w-8 mx-auto mb-3 text-primary" />
                  <h3 className="font-semibold mb-1">Agent Portal</h3>
                  <p className="text-sm text-muted-foreground">Demo &middot; Developer tools & testing</p>
                </CardContent>
              </Card>
            </Link>

            <Link href="/audit">
              <Card className="hover:border-primary transition-colors cursor-pointer h-full">
                <CardContent className="p-6 text-center">
                  <FileSearch className="h-8 w-8 mx-auto mb-3 text-primary" />
                  <h3 className="font-semibold mb-1">Audit Explorer</h3>
                  <p className="text-sm text-muted-foreground">Demo &middot; Search & verify logs</p>
                </CardContent>
              </Card>
            </Link>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t bg-muted/30">
        <div className="container mx-auto px-4 py-10">
          <div className="flex flex-col items-center gap-5">
            <div className="flex items-center gap-2.5">
              <InntrisLogo className="h-5 w-5" />
              <span className="text-sm font-semibold tracking-tight">Inntris</span>
            </div>
            <p className="text-sm text-muted-foreground text-center">
              Cryptographic verification for AI agents.
            </p>
            <div className="flex items-center gap-5">
              <a
                href="https://github.com/Inntris/agent-orchestrator-guardrails"
                target="_blank"
                rel="noopener noreferrer"
                className="text-muted-foreground hover:text-foreground transition-colors"
              >
                <Github className="h-4.5 w-4.5" />
              </a>
            </div>
            <p className="text-xs text-muted-foreground/60">
              &copy; {new Date().getFullYear()} Inntris INC
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}
