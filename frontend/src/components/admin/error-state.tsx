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
      <div className="mb-4 rounded-full bg-red-500/10 p-4">
        <AlertTriangle className="h-8 w-8 text-red-400" />
      </div>
      <p className="mb-1 text-sm font-medium text-[#F5F7FB]">{message}</p>
      {detail && (
        <p className="mb-4 max-w-md text-xs text-[#7F8CA3]">{detail}</p>
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
