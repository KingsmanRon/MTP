import { cn, getVerdictBadgeStyles } from "@/lib/utils";
import { CheckCircle, XCircle, Clock, AlertTriangle } from "lucide-react";
import type { ActionVerdict } from "@/lib/api";

interface VerdictBadgeProps {
  verdict: ActionVerdict;
  showIcon?: boolean;
}

export function VerdictBadge({ verdict, showIcon = true }: VerdictBadgeProps) {
  const icons = {
    approved: CheckCircle,
    blocked: XCircle,
    rate_limited: Clock,
    signature_invalid: AlertTriangle,
  };

  const labels = {
    approved: "PASS",
    blocked: "BLOCK",
    rate_limited: "ESCALATE",
    signature_invalid: "BLOCK",
  };

  const Icon = icons[verdict];

  return (
    <span
      className={cn(
        "inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-full border px-2 py-0.5 text-xs font-medium",
        getVerdictBadgeStyles(verdict)
      )}
    >
      {showIcon && <Icon className="w-3 h-3" />}
      {labels[verdict]}
    </span>
  );
}
