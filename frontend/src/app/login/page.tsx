"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Shield, Key, Loader2, AlertCircle, ArrowRight } from "lucide-react";
import { createAuthenticatedApi } from "@/lib/api";

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
      // Validate the API key by calling the organization endpoint
      const api = createAuthenticatedApi(apiKey.trim());
      await api.getOrganization();

      // Success - store the key and redirect
      localStorage.setItem("inntris_api_key", apiKey.trim());
      router.push("/admin");
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Invalid API key";
      if (message.includes("401") || message.includes("403") || message.includes("Unauthorized")) {
        setError("Invalid API key. Please check your key and try again.");
      } else if (message.includes("Failed to fetch") || message.includes("Network")) {
        setError("Cannot connect to API server. Please check if the backend is running.");
      } else {
        setError(message);
      }
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-background to-muted p-4">
      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <div className="mx-auto mb-4 p-3 rounded-full bg-primary/10 w-fit">
            <Shield className="h-8 w-8 text-primary" />
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
