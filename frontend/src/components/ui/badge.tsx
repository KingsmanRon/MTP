import * as React from "react";
import { cn } from "@/lib/utils";

export interface BadgeProps extends React.HTMLAttributes<HTMLDivElement> {
  variant?: "default" | "secondary" | "destructive" | "outline" | "success" | "warning";
}

function Badge({ className, variant = "default", ...props }: BadgeProps) {
  // Status variants use surface + line + ink rather than a low-alpha wash of
  // a mid palette shade. The old `bg-warning-surface text-warning-ink` measured
  // 1.92:1 on the white ground this app renders by default; these clear AA.
  const variants = {
    default: "border-transparent bg-primary text-primary-foreground",
    secondary: "border-border bg-secondary text-secondary-foreground",
    destructive: "border-transparent bg-destructive text-destructive-foreground",
    outline: "border-border text-foreground",
    success: "border-success-line bg-success-surface text-success-ink",
    warning: "border-warning-line bg-warning-surface text-warning-ink",
  };

  return (
    <div
      className={cn(
        "inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2",
        variants[variant],
        className
      )}
      {...props}
    />
  );
}

export { Badge };
