"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Shield, Search, ExternalLink, CheckCircle } from "lucide-react";

export default function VerifyLandingPage() {
  const [agentId, setAgentId] = useState("");
  const router = useRouter();

  const handleVerify = () => {
    if (agentId) {
      router.push(`/verify/${agentId}`);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-b from-background to-muted">
      {/* Header */}
      <header className="border-b bg-background/80 backdrop-blur-sm sticky top-0 z-50">
        <div className="container mx-auto px-4 py-4 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-2">
            <Shield className="h-6 w-6 text-primary" />
            <span className="font-semibold">MTP</span>
          </Link>
          <nav className="flex items-center gap-4">
            <Link href="/admin" className="text-sm text-muted-foreground hover:text-foreground">
              Admin Console
            </Link>
            <Link href="/audit" className="text-sm text-muted-foreground hover:text-foreground">
              Audit Explorer
            </Link>
          </nav>
        </div>
      </header>

      <main className="container mx-auto px-4 py-20">
        <div className="max-w-2xl mx-auto text-center">
          {/* Hero */}
          <div className="mb-12">
            <div className="flex justify-center mb-6">
              <div className="p-4 rounded-full bg-primary/10">
                <Shield className="h-12 w-12 text-primary" />
              </div>
            </div>
            <h1 className="text-4xl font-bold mb-4">Verify an AI Agent</h1>
            <p className="text-xl text-muted-foreground">
              Check the trust status and verification history of any MTP-registered agent
            </p>
          </div>

          {/* Search Card */}
          <Card className="mb-12">
            <CardContent className="pt-6">
              <div className="flex gap-4">
                <div className="relative flex-1">
                  <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                  <Input
                    placeholder="Enter agent ID (e.g., a1b2c3d4-e5f6-7890-abcd-ef1234567890)"
                    value={agentId}
                    onChange={(e) => setAgentId(e.target.value)}
                    onKeyDown={(e) => e.key === "Enter" && handleVerify()}
                    className="pl-10 h-12 text-lg"
                  />
                </div>
                <Button onClick={handleVerify} disabled={!agentId} size="lg">
                  Verify
                </Button>
              </div>
            </CardContent>
          </Card>

          {/* Features */}
          <div className="grid md:grid-cols-3 gap-6 mb-12">
            <Card>
              <CardContent className="pt-6 text-center">
                <div className="p-3 rounded-full bg-primary/10 w-fit mx-auto mb-4">
                  <CheckCircle className="h-6 w-6 text-primary" />
                </div>
                <h3 className="font-semibold mb-2">Instant Verification</h3>
                <p className="text-sm text-muted-foreground">
                  Check any agent's trust status in real-time
                </p>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-6 text-center">
                <div className="p-3 rounded-full bg-primary/10 w-fit mx-auto mb-4">
                  <Shield className="h-6 w-6 text-primary" />
                </div>
                <h3 className="font-semibold mb-2">Trust Scores</h3>
                <p className="text-sm text-muted-foreground">
                  View cumulative trust based on verification history
                </p>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-6 text-center">
                <div className="p-3 rounded-full bg-primary/10 w-fit mx-auto mb-4">
                  <ExternalLink className="h-6 w-6 text-primary" />
                </div>
                <h3 className="font-semibold mb-2">On-Chain Proof</h3>
                <p className="text-sm text-muted-foreground">
                  Verify audit logs cryptographically on Base L2
                </p>
              </CardContent>
            </Card>
          </div>

          {/* Example Agents */}
          <Card>
            <CardHeader>
              <CardTitle>Example Verified Agents</CardTitle>
              <CardDescription>Click to view verification details</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {[
                  { id: "a1b2c3d4-e5f6-7890-abcd-ef1234567890", name: "PaymentBot", score: 85 },
                  { id: "b2c3d4e5-f6a7-8901-bcde-f12345678901", name: "DataExporter", score: 72 },
                  { id: "c3d4e5f6-a7b8-9012-cdef-123456789012", name: "EmailAgent", score: 91 },
                ].map((agent) => (
                  <Link
                    key={agent.id}
                    href={`/verify/${agent.id}`}
                    className="flex items-center justify-between p-4 rounded-lg border hover:bg-muted transition"
                  >
                    <div className="flex items-center gap-3">
                      <div className="p-2 rounded-full bg-green-500/10">
                        <CheckCircle className="h-4 w-4 text-green-500" />
                      </div>
                      <div className="text-left">
                        <p className="font-medium">{agent.name}</p>
                        <code className="text-xs text-muted-foreground">{agent.id.slice(0, 16)}...</code>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <span
                        className={`text-sm font-medium ${
                          agent.score >= 70
                            ? "text-green-500"
                            : agent.score >= 40
                            ? "text-yellow-500"
                            : "text-red-500"
                        }`}
                      >
                        {agent.score}
                      </span>
                      <ExternalLink className="h-4 w-4 text-muted-foreground" />
                    </div>
                  </Link>
                ))}
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
