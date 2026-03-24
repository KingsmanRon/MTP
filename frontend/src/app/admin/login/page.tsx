"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Key, Loader2, AlertCircle, ArrowRight } from "lucide-react";
import { InntrisLogo } from "@/components/inntris-logo";

export default function AdminLoginPage() {
  const router = useRouter();
  const [apiKey, setApiKey] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!apiKey.trim()) {
      setError("Please enter an API key");
      return;
    }

    setIsLoading(true);
    setError(null);

    try {
      const res = await fetch("/api/admin/session", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ api_key: apiKey.trim() }),
      });

      if (res.ok) {
        router.push("/admin");
        return;
      }

      const data = await res.json().catch(() => ({}));

      if (res.status === 401) {
        setError("Invalid API key. Please check your key and try again.");
      } else if (res.status === 502) {
        setError("Cannot connect to the backend API. Please try again later.");
      } else {
        setError(
          typeof data.error === "string"
            ? data.error
            : "Authentication failed. Please try again."
        );
      }
    } catch {
      setError("Network error. Please check your connection and try again.");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-[#07111F] p-4">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_top,rgba(76,141,255,0.10),transparent_40%)]" />
      <Card className="relative w-full max-w-md border-[#22314D] bg-[#0D1728]">
        <CardHeader className="text-center">
          <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-2xl border border-[#22314D] bg-[#101C31]">
            <InntrisLogo className="h-8 w-8" />
          </div>
          <CardTitle className="text-xl text-[#F5F7FB]">Admin Console</CardTitle>
          <CardDescription className="text-[#7F8CA3]">
            Enter your admin API key to continue
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <label htmlFor="apiKey" className="text-sm font-medium text-[#C4CFDE]">
                API Key
              </label>
              <div className="relative">
                <Key className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[#7F8CA3]" />
                <Input
                  id="apiKey"
                  type="password"
                  placeholder="ink_..."
                  value={apiKey}
                  onChange={(e) => setApiKey(e.target.value)}
                  className="border-[#22314D] bg-[#101C31] pl-10 text-[#F5F7FB] placeholder:text-[#4A5568]"
                  autoComplete="off"
                  autoFocus
                />
              </div>
            </div>

            {error && (
              <div className="flex items-center gap-2 rounded-lg bg-red-500/10 p-3 text-red-400">
                <AlertCircle className="h-4 w-4 flex-shrink-0" />
                <span className="text-sm">{error}</span>
              </div>
            )}

            <Button
              type="submit"
              className="w-full bg-[#4C8DFF] text-white hover:bg-[#3A7AEE]"
              disabled={isLoading}
            >
              {isLoading ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Verifying...
                </>
              ) : (
                <>
                  Sign In
                  <ArrowRight className="ml-2 h-4 w-4" />
                </>
              )}
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
