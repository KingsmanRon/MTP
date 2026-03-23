import { cn, getVerdictBadgeStyles } from "@/lib/utils";
import { CheckCircle, XCircle, Clock, AlertTriangle } from "lucide-react";
import type { ActionVerdict } from "@/lib/admin/types";

const icons: Record<ActionVerdict, typeof CheckCircle> = {
  approved: CheckCircle,
  blocked: XCircle,
  rate_limited: Clock,
  signature_invalid: AlertTriangle,
};

const labels: Record<ActionVerdict, string> = {
  approved: "Approved",
  blocked: "Blocked",
  rate_limited: "Rate Limited",
  signature_invalid: "Invalid Signature",
};

export function AdminVerdictBadge({
  verdict,
  showIcon = true,
}: {
  verdict: string;
  showIcon?: boolean;
}) {
  const isKnown = verdict in icons;
  const Icon = isKnown ? icons[verdict as ActionVerdict] : AlertTriangle;
  const label = isKnown ? labels[verdict as ActionVerdict] : verdict;

  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs font-medium",
        isKnown
          ? getVerdictBadgeStyles(verdict)
          : "border-border bg-muted text-muted-foreground"
      )}
    >
      {showIcon && <Icon className="h-3 w-3" />}
      {label}
    </span>
  );
}
