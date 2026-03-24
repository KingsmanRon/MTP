"use client";

import { useState, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { LoadingState } from "@/components/loading-state";
import { formatCurrency } from "@/lib/utils";
import { useOrganization } from "@/lib/hooks";
import { Building2, CreditCard, Bell, Shield, AlertCircle } from "lucide-react";

const tierFeatures = {
  free: { agents: 2, verifications: "1K/month", support: "Community" },
  starter: { agents: 10, verifications: "50K/month", support: "Email" },
  professional: { agents: 50, verifications: "500K/month", support: "Priority" },
  enterprise: { agents: "Unlimited", verifications: "Unlimited", support: "24/7 Dedicated" },
};

export default function SettingsPage() {
  const { data: organization, isLoading, error } = useOrganization();

  const [orgName, setOrgName] = useState("");
  const [contactEmail, setContactEmail] = useState("");
  const [webhookUrl, setWebhookUrl] = useState("");

  useEffect(() => {
    if (organization) {
      setOrgName(organization.name);
      setContactEmail(organization.contact_email);
      setWebhookUrl(organization.webhook_url || "");
    }
  }, [organization]);

  if (isLoading) {
    return <LoadingState message="Loading settings..." />;
  }

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center py-12">
        <AlertCircle className="h-12 w-12 text-destructive mb-4" />
        <h2 className="text-xl font-semibold mb-2">Failed to load settings</h2>
        <p className="text-muted-foreground">Please check your API connection and try again.</p>
      </div>
    );
  }

  const currentTier = (organization?.billing_tier || "free") as keyof typeof tierFeatures;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Settings</h1>
        <p className="text-muted-foreground">
          Manage your organization settings and preferences
        </p>
      </div>

      <Tabs defaultValue="general">
        <TabsList>
          <TabsTrigger value="general">
            <Building2 className="h-4 w-4 mr-2" />
            General
          </TabsTrigger>
          <TabsTrigger value="billing">
            <CreditCard className="h-4 w-4 mr-2" />
            Billing
          </TabsTrigger>
          <TabsTrigger value="notifications">
            <Bell className="h-4 w-4 mr-2" />
            Notifications
          </TabsTrigger>
          <TabsTrigger value="security">
            <Shield className="h-4 w-4 mr-2" />
            Security
          </TabsTrigger>
        </TabsList>

        <TabsContent value="general">
          <Card>
            <CardHeader>
              <CardTitle>Organization Details</CardTitle>
              <CardDescription>Basic information about your organization</CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-2">
                  <label className="text-sm font-medium">Organization Name</label>
                  <Input
                    value={orgName}
                    onChange={(e) => setOrgName(e.target.value)}
                  />
                </div>
                <div className="space-y-2">
                  <label className="text-sm font-medium">Organization ID</label>
                  <Input value={organization?.id || ""} disabled className="font-mono" />
                </div>
              </div>
              <div className="space-y-2">
                <label className="text-sm font-medium">Contact Email</label>
                <Input
                  type="email"
                  value={contactEmail}
                  onChange={(e) => setContactEmail(e.target.value)}
                />
              </div>
              <div className="flex justify-end">
                <Button>Save Changes</Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="billing">
          <div className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle>Current Plan</CardTitle>
                <CardDescription>Your subscription and usage limits</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="flex items-center justify-between p-4 bg-muted rounded-lg mb-6">
                  <div>
                    <div className="flex items-center gap-2">
                      <h3 className="text-xl font-bold capitalize">{currentTier}</h3>
                      <Badge variant="secondary">Current Plan</Badge>
                    </div>
                    <p className="text-sm text-muted-foreground mt-1">
                      {tierFeatures[currentTier].verifications} verifications per month
                    </p>
                  </div>
                  <Button variant="outline">Upgrade Plan</Button>
                </div>
                <div className="grid gap-4 md:grid-cols-3">
                  <div className="p-4 border rounded-lg">
                    <p className="text-sm text-muted-foreground">Max Agents</p>
                    <p className="text-2xl font-bold">{tierFeatures[currentTier].agents}</p>
                  </div>
                  <div className="p-4 border rounded-lg">
                    <p className="text-sm text-muted-foreground">Daily Limit</p>
                    <p className="text-2xl font-bold">{formatCurrency(organization?.daily_limit_usd || 0)}</p>
                  </div>
                  <div className="p-4 border rounded-lg">
                    <p className="text-sm text-muted-foreground">Monthly Limit</p>
                    <p className="text-2xl font-bold">{formatCurrency(organization?.monthly_limit_usd || 0)}</p>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Plan Comparison</CardTitle>
                <CardDescription>Compare available plans</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid gap-4 md:grid-cols-4">
                  {Object.entries(tierFeatures).map(([tier, features]) => (
                    <div
                      key={tier}
                      className={`p-4 border rounded-lg ${tier === currentTier ? "border-primary bg-primary/5" : ""}`}
                    >
                      <h4 className="font-semibold capitalize mb-2">{tier}</h4>
                      <ul className="text-sm space-y-1 text-muted-foreground">
                        <li>{features.agents} agents</li>
                        <li>{features.verifications}</li>
                        <li>{features.support} support</li>
                      </ul>
                      {tier !== currentTier && tier !== "free" && (
                        <Button variant="outline" size="sm" className="mt-4 w-full">
                          {Object.keys(tierFeatures).indexOf(tier) > Object.keys(tierFeatures).indexOf(currentTier)
                            ? "Upgrade"
                            : "Downgrade"}
                        </Button>
                      )}
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="notifications">
          <Card>
            <CardHeader>
              <CardTitle>Webhook Configuration</CardTitle>
              <CardDescription>Configure webhooks for real-time event notifications</CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="space-y-2">
                <label className="text-sm font-medium">Webhook URL</label>
                <Input
                  type="url"
                  placeholder="https://your-server.com/webhooks/inntris"
                  value={webhookUrl}
                  onChange={(e) => setWebhookUrl(e.target.value)}
                />
                <p className="text-xs text-muted-foreground">
                  {"We'll send POST requests to this URL for security events"}
                </p>
              </div>
              <div className="space-y-4">
                <label className="text-sm font-medium">Event Types</label>
                <div className="grid gap-2 md:grid-cols-2">
                  {[
                    { id: "signature_invalid", label: "Invalid Signature Detected" },
                    { id: "rate_limit_exceeded", label: "Rate Limit Exceeded" },
                    { id: "trust_score_drop", label: "Trust Score Drop" },
                    { id: "agent_suspended", label: "Agent Suspended" },
                    { id: "daily_limit_reached", label: "Daily Limit Reached" },
                    { id: "verification_blocked", label: "Verification Blocked" },
                  ].map((event) => (
                    <label key={event.id} className="flex items-center gap-2 p-3 border rounded-lg cursor-pointer hover:bg-muted">
                      <input type="checkbox" defaultChecked className="rounded" />
                      <span className="text-sm">{event.label}</span>
                    </label>
                  ))}
                </div>
              </div>
              <div className="flex justify-end gap-2">
                <Button variant="outline">Test Webhook</Button>
                <Button>Save Configuration</Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="security">
          <div className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle>Security Policies</CardTitle>
                <CardDescription>Configure organization-wide security settings</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <label className="flex items-center justify-between p-4 border rounded-lg">
                  <div>
                    <p className="font-medium">Require Trust Score Threshold</p>
                    <p className="text-sm text-muted-foreground">
                      Block all actions from agents with trust score below threshold
                    </p>
                  </div>
                  <Input type="number" className="w-20" defaultValue={30} />
                </label>
                <label className="flex items-center justify-between p-4 border rounded-lg">
                  <div>
                    <p className="font-medium">Auto-suspend on Signature Failure</p>
                    <p className="text-sm text-muted-foreground">
                      Automatically suspend agents after multiple signature failures
                    </p>
                  </div>
                  <input type="checkbox" defaultChecked className="rounded" />
                </label>
                <label className="flex items-center justify-between p-4 border rounded-lg">
                  <div>
                    <p className="font-medium">IP Allowlisting</p>
                    <p className="text-sm text-muted-foreground">
                      Only allow API requests from specified IP addresses
                    </p>
                  </div>
                  <input type="checkbox" className="rounded" />
                </label>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Audit Log Retention</CardTitle>
                <CardDescription>Configure how long audit logs are retained</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="flex items-center gap-4">
                  <select 
                    className="flex h-10 w-48 rounded-md border border-input bg-background px-3 py-2 text-sm"
                    defaultValue="365"
                  >
                    <option value="30">30 days</option>
                    <option value="90">90 days</option>
                    <option value="365">1 year</option>
                    <option value="730">2 years</option>
                    <option value="unlimited">Unlimited</option>
                  </select>
                  <p className="text-sm text-muted-foreground">
                    Logs older than this will be archived to cold storage
                  </p>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}
