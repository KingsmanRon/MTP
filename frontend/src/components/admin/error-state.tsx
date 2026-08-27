"use client";

import { AlertTriangle, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";

export function AdminErrorState({
  message = "Failed to load data",
  detail,
  onRetry,
}: {
  message?: string;
  detail?: string;
  onRetry?: () => void;
}) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-center">
      <div className="mb-4 rounded-full bg-destructive-surface p-4">
        <AlertTriangle className="h-8 w-8 text-destructive-ink" />
      </div>
      <p className="mb-1 text-sm font-medium text-foreground">{message}</p>
      {detail && (
        <p className="mb-4 max-w-md text-xs text-muted-foreground">{detail}</p>
      )}
      {onRetry && (
        <Button variant="outline" size="sm" onClick={onRetry}>
          <RefreshCw className="mr-2 h-3 w-3" />
          Retry
        </Button>
      )}
    </div>
  );
}
