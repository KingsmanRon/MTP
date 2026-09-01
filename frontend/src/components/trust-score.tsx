"use client";

import { cn, getTrustScoreColor, getTrustScoreBgColor } from "@/lib/utils";

interface TrustScoreProps {
  score: number;
  size?: "sm" | "md" | "lg";
  showLabel?: boolean;
}

export function TrustScore({ score, size = "md", showLabel = true }: TrustScoreProps) {
  const sizes = {
    sm: { container: "w-10 h-10", text: "text-xs", label: "text-[10px]" },
    md: { container: "w-16 h-16", text: "text-lg", label: "text-xs" },
    lg: { container: "w-24 h-24", text: "text-2xl", label: "text-sm" },
  };

  const circumference = 2 * Math.PI * 45;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  return (
    <div className="flex flex-col items-center gap-1">
      <div className={cn("relative", sizes[size].container)}>
        <svg className="w-full h-full -rotate-90" viewBox="0 0 100 100">
          {/* Background circle */}
          <circle
            cx="50"
            cy="50"
            r="45"
            fill="none"
            stroke="currentColor"
            strokeWidth="8"
            className="text-tileLine"
          />
          {/* Progress circle */}
          <circle
            cx="50"
            cy="50"
            r="45"
            fill="none"
            stroke="currentColor"
            strokeWidth="8"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            className={getTrustScoreColor(score)}
          />
        </svg>
        <div className="absolute inset-0 flex items-center justify-center">
          <span className={cn("font-bold", sizes[size].text, getTrustScoreColor(score))}>
            {score}
          </span>
        </div>
      </div>
      {showLabel && (
        <span className={cn("text-muted-foreground", sizes[size].label)}>Trust Score</span>
      )}
    </div>
  );
}

interface TrustScoreBadgeProps {
  score: number;
}

export function TrustScoreBadge({ score }: TrustScoreBadgeProps) {
  return (
    <span
      className={cn(
        "inline-flex shrink-0 items-center justify-center whitespace-nowrap rounded-full px-2 py-0.5 text-xs font-medium tabular-nums",
        getTrustScoreBgColor(score),
        getTrustScoreColor(score)
      )}
    >
      {score}
    </span>
  );
}
