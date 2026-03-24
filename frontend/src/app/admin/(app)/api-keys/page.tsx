"use client";

import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { EmptyState } from "@/components/empty-state";
import { LoadingState } from "@/components/loading-state";
import { formatDateTime, formatRelative, copyToClipboard } from "@/lib/utils";
import { useApiKeys, useCreateApiKey, useRevokeApiKey } from "@/lib/hooks";
import {
  Key,
  Plus,
  Copy,
  Check,
  Trash2,
  RefreshCw,
  AlertTriangle,
  AlertCircle,
  Eye,
  EyeOff,
} from "lucide-react";

export default function APIKeysPage() {
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [showNewKeyDialog, setShowNewKeyDialog] = useState(false);
  const [newKeyName, setNewKeyName] = useState("");
  const [generatedKey, setGeneratedKey] = useState("");
  const [copied, setCopied] = useState(false);
  const [showRotateDialog, setShowRotateDialog] = useState(false);

  const { data: apiKeys, isLoading, error } = useApiKeys();
  const createApiKey = useCreateApiKey();
  const revokeApiKey = useRevokeApiKey();

  const handleCreateKey = async () => {
    try {
      const result = await createApiKey.mutateAsync({
        name: newKeyName,
        scopes: ["read", "write", "verify"],
      });
      setGeneratedKey(result.api_key);
      setShowCreateDialog(false);
      setShowNewKeyDialog(true);
      setNewKeyName("");
    } catch (err) {
      console.error("Failed to create API key:", err);
    }
  };

  const handleRevokeKey = async (keyPrefix: string) => {
    try {
      await revokeApiKey.mutateAsync(keyPrefix);
    } catch (err) {
      console.error("Failed to revoke API key:", err);
    }
  };

  if (isLoading) {
    return <LoadingState message="Loading API keys..." />;
  }

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center py-12">
        <AlertCircle className="h-12 w-12 text-destructive mb-4" />
        <h2 className="text-xl font-semibold mb-2">Failed to load API keys</h2>
        <p className="text-muted-foreground">Please check your API connection and try again.</p>
      </div>
    );
  }

  const keys = apiKeys || [];

  const handleCopyKey = async () => {
    await copyToClipboard(generatedKey);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">API Keys</h1>
          <p className="text-muted-foreground">
            Manage API keys for accessing the Inntris API
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => setShowRotateDialog(true)}>
            <RefreshCw className="h-4 w-4 mr-2" />
            Rotate All
          </Button>
          <Button onClick={() => setShowCreateDialog(true)}>
            <Plus className="h-4 w-4 mr-2" />
            Create Key
          </Button>
        </div>
      </div>

      {/* Warning Banner */}
      <Card className="border-yellow-500/50 bg-yellow-500/5">
        <CardContent className="flex items-center gap-4 py-4">
          <AlertTriangle className="h-5 w-5 text-yellow-500" />
          <div>
            <p className="font-medium">Keep your API keys secure</p>
            <p className="text-sm text-muted-foreground">
              API keys grant access to your Inntris organization. Never share them publicly or commit them to version control.
            </p>
          </div>
        </CardContent>
      </Card>

      {/* API Keys Table */}
      <Card>
        <CardHeader>
          <CardTitle>Active Keys</CardTitle>
          <CardDescription>
            {keys.length} API key{keys.length !== 1 ? "s" : ""} configured
          </CardDescription>
        </CardHeader>
        <CardContent>
          {keys.length === 0 ? (
            <EmptyState
              icon={Key}
              title="No API keys"
              description="Create your first API key to start using the Inntris API."
              action={
                <Button onClick={() => setShowCreateDialog(true)}>
                  <Plus className="h-4 w-4 mr-2" />
                  Create Key
                </Button>
              }
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Key</TableHead>
                  <TableHead>Scopes</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Last Used</TableHead>
                  <TableHead>Expires</TableHead>
                  <TableHead className="w-[100px]"></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {keys.map((key) => (
                  <TableRow key={key.id}>
                    <TableCell className="font-medium">{key.name}</TableCell>
                    <TableCell>
                      <code className="text-sm text-muted-foreground">
                        {key.key_prefix}_••••••••
                      </code>
                    </TableCell>
                    <TableCell>
                      <div className="flex gap-1">
                        {key.scopes.map((scope) => (
                          <Badge key={scope} variant="secondary" className="text-xs">
                            {scope}
                          </Badge>
                        ))}
                      </div>
                    </TableCell>
                    <TableCell>
                      {key.is_active ? (
                        <Badge variant="outline" className="bg-green-500/10 text-green-500">
                          Active
                        </Badge>
                      ) : (
                        <Badge variant="outline" className="bg-red-500/10 text-red-500">
                          Revoked
                        </Badge>
                      )}
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {formatRelative(key.last_used_at)}
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {key.expires_at ? formatDateTime(key.expires_at) : "Never"}
                    </TableCell>
                    <TableCell>
                      {key.is_active && (
                        <Button
                          variant="ghost"
                          size="icon"
                          className="text-destructive"
                          onClick={() => handleRevokeKey(key.key_prefix)}
                          disabled={revokeApiKey.isPending}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Create Key Dialog */}
      <Dialog open={showCreateDialog} onOpenChange={setShowCreateDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create API Key</DialogTitle>
            <DialogDescription>
              Create a new API key for accessing the Inntris API. The key will only be shown once.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <label className="text-sm font-medium">Key Name</label>
              <Input
                placeholder="e.g., Production API Key"
                value={newKeyName}
                onChange={(e) => setNewKeyName(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">Scopes</label>
              <div className="flex gap-2">
                <Badge variant="secondary">read</Badge>
                <Badge variant="secondary">write</Badge>
                <Badge variant="secondary">verify</Badge>
              </div>
              <p className="text-xs text-muted-foreground">
                All scopes will be enabled for this key
              </p>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowCreateDialog(false)}>
              Cancel
            </Button>
            <Button onClick={handleCreateKey} disabled={!newKeyName || createApiKey.isPending}>
              {createApiKey.isPending ? "Creating..." : "Create Key"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* New Key Display Dialog */}
      <Dialog open={showNewKeyDialog} onOpenChange={setShowNewKeyDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>API Key Created</DialogTitle>
            <DialogDescription>
              <p className="text-destructive">
               {"Copy your API key now. You won't be able to see it again!"}
              </p>
            </DialogDescription>
          </DialogHeader>
          <div className="py-4">
            <div className="flex items-center gap-2 p-3 bg-muted rounded-lg">
              <code className="flex-1 text-sm break-all">{generatedKey}</code>
              <Button variant="ghost" size="icon" onClick={handleCopyKey}>
                {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
              </Button>
            </div>
            <p className="text-xs text-muted-foreground mt-2">
              Store this key securely. It will not be shown again.
            </p>
          </div>
          <DialogFooter>
            <Button onClick={() => setShowNewKeyDialog(false)}>Done</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Rotate Keys Dialog */}
      <Dialog open={showRotateDialog} onOpenChange={setShowRotateDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Rotate All API Keys</DialogTitle>
            <DialogDescription>
              This will revoke all existing API keys and generate a new primary key.
              Make sure to update your applications with the new key.
            </DialogDescription>
          </DialogHeader>
          <div className="py-4">
            <div className="p-4 bg-destructive/10 rounded-lg">
              <p className="text-sm text-destructive font-medium">
                Warning: This action cannot be undone
              </p>
              <p className="text-xs text-muted-foreground mt-1">
                All existing keys will stop working immediately.
              </p>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowRotateDialog(false)}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={() => setShowRotateDialog(false)}>
              Rotate All Keys
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
