import { cn, getVerdictBadgeStyles } from "@/lib/utils";
import { verdictLabel } from "@/lib/verdict";
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

  const Icon = icons[verdict];

  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium border",
        getVerdictBadgeStyles(verdict)
      )}
    >
      {showIcon && <Icon className="w-3 h-3" />}
      {verdictLabel(verdict)}
    </span>
  );
}
