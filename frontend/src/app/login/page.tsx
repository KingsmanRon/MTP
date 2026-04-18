"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Key, Loader2, AlertCircle, ArrowRight } from "lucide-react";
import { InntrisLogo } from "@/components/inntris-logo";

export default function LoginPage() {
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
        cache: "no-store",
      });

      if (res.ok) {
        router.push("/admin/dashboard");
        return;
      }

      const data = await res.json().catch(() => ({}));
      const message = typeof data.error === "string" ? data.error : "";

      if (res.status === 401) {
        setError("Invalid API key. Please check your key and try again.");
      } else if (res.status === 429) {
        setError(message || "Too many login attempts. Try again later.");
      } else if (res.status === 502) {
        setError("Cannot connect to API server. Please check if the backend is running.");
      } else if (res.status === 503) {
        setError(
          message ||
            "Authentication service temporarily unavailable. Please try again shortly."
        );
      } else {
        setError(message || `Sign in failed (${res.status})`);
      }
    } catch {
      setError("Network error. Please try again.");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-background to-muted p-4">
      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <div className="mx-auto mb-4 p-3 rounded-full bg-primary/10 w-fit">
            <InntrisLogo className="h-8 w-8" />
          </div>
          <CardTitle className="text-2xl">Welcome to Inntris</CardTitle>
          <CardDescription>
            Enter your API key to access the admin console
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <label htmlFor="apiKey" className="text-sm font-medium">
                API Key
              </label>
              <div className="relative">
                <Key className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                  id="apiKey"
                  type="password"
                  placeholder="ink_..."
                  value={apiKey}
                  onChange={(e) => setApiKey(e.target.value)}
                  className="pl-10"
                  autoComplete="off"
                  autoFocus
                />
              </div>
              <p className="text-xs text-muted-foreground">
                Your API key can be found in your organization settings or provided by your admin.
              </p>
            </div>

            {error && (
              <div className="flex items-center gap-2 p-3 bg-destructive/10 text-destructive rounded-lg">
                <AlertCircle className="h-4 w-4 flex-shrink-0" />
                <span className="text-sm">{error}</span>
              </div>
            )}

            <Button type="submit" className="w-full" disabled={isLoading}>
              {isLoading ? (
                <>
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  Verifying...
                </>
              ) : (
                <>
                  Sign In
                  <ArrowRight className="h-4 w-4 ml-2" />
                </>
              )}
            </Button>
          </form>

          <div className="mt-6 pt-6 border-t">
            <p className="text-sm text-muted-foreground text-center">
              For development, you can use{" "}
              <code className="px-1 py-0.5 bg-muted rounded text-xs">dev_test_key</code>
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
