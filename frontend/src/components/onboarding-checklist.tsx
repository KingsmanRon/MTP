"use client";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  CheckCircle2,
  Circle,
  Bot,
  Key,
  Shield,
  PlayCircle,
  FileSearch,
  ArrowRight,
  Sparkles,
} from "lucide-react";
import Link from "next/link";

interface OnboardingStep {
  id: string;
  title: string;
  description: string;
  href: string;
  icon: React.ElementType;
  completed: boolean;
}

interface OnboardingChecklistProps {
  hasAgents: boolean;
  hasApiKeys: boolean;
  hasVerifications: boolean;
  onDismiss?: () => void;
}

export function OnboardingChecklist({
  hasAgents,
  hasApiKeys,
  hasVerifications,
  onDismiss,
}: OnboardingChecklistProps) {
  const steps: OnboardingStep[] = [
    {
      id: "register-agent",
      title: "Register your first agent",
      description: "Create an AI agent with cryptographic identity",
      href: "/admin/agents",
      icon: Bot,
      completed: hasAgents,
    },
    {
      id: "create-api-key",
      title: "Create an API key",
      description: "Generate keys for API authentication",
      href: "/admin/api-keys",
      icon: Key,
      completed: hasApiKeys,
    },
    {
      id: "test-verification",
      title: "Test a verification",
      description: "Use the playground to test your integration",
      href: "/portal/playground",
      icon: PlayCircle,
      completed: hasVerifications,
    },
    {
      id: "review-audit",
      title: "Review audit logs",
      description: "See your verification history",
      href: "/audit",
      icon: FileSearch,
      completed: hasVerifications,
    },
  ];

  const completedCount = steps.filter((s) => s.completed).length;
  const progressPercent = (completedCount / steps.length) * 100;
  const isComplete = completedCount === steps.length;

  if (isComplete && onDismiss) {
    return null;
  }

  return (
    <Card className="border-primary/20 bg-gradient-to-br from-primary/5 to-transparent">
      <CardHeader>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-primary/10">
              <Sparkles className="h-5 w-5 text-primary" />
            </div>
            <div>
              <CardTitle>Getting Started with Inntris</CardTitle>
              <CardDescription>Complete these steps to set up your deployment</CardDescription>
            </div>
          </div>
          <Badge variant="secondary" className="text-sm">
            {completedCount}/{steps.length} complete
          </Badge>
        </div>
        {/* Progress Bar */}
        <div className="mt-4">
          <div className="h-2 bg-muted rounded-full overflow-hidden">
            <div
              className="h-full bg-primary transition-all duration-500"
              style={{ width: `${progressPercent}%` }}
            />
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <div className="space-y-3">
          {steps.map((step, index) => (
            <Link
              key={step.id}
              href={step.href}
              className={`flex items-center gap-4 p-3 rounded-lg transition-colors ${
                step.completed
                  ? "bg-green-500/5 hover:bg-green-500/10"
                  : "bg-muted/50 hover:bg-muted"
              }`}
            >
              <div className="flex-shrink-0">
                {step.completed ? (
                  <CheckCircle2 className="h-6 w-6 text-green-500" />
                ) : (
                  <div className="relative">
                    <Circle className="h-6 w-6 text-muted-foreground" />
                    <span className="absolute inset-0 flex items-center justify-center text-xs font-medium">
                      {index + 1}
                    </span>
                  </div>
                )}
              </div>
              <div className="flex-1 min-w-0">
                <p className={`font-medium ${step.completed ? "text-green-700 dark:text-green-400" : ""}`}>
                  {step.title}
                </p>
                <p className="text-sm text-muted-foreground">{step.description}</p>
              </div>
              <step.icon className={`h-5 w-5 flex-shrink-0 ${
                step.completed ? "text-green-500" : "text-muted-foreground"
              }`} />
              {!step.completed && (
                <ArrowRight className="h-4 w-4 text-muted-foreground" />
              )}
            </Link>
          ))}
        </div>

        {isComplete && (
          <div className="mt-4 p-4 rounded-lg bg-green-500/10 border border-green-500/20">
            <div className="flex items-center gap-3">
              <CheckCircle2 className="h-5 w-5 text-green-500" />
              <div>
                <p className="font-medium text-green-700 dark:text-green-400">
                  Setup Complete!
                </p>
                <p className="text-sm text-muted-foreground">
                  Your Inntris deployment is ready to use.
                </p>
              </div>
              {onDismiss && (
                <Button variant="ghost" size="sm" className="ml-auto" onClick={onDismiss}>
                  Dismiss
                </Button>
              )}
            </div>
          </div>
        )}

        {!isComplete && (
          <div className="mt-4 flex items-center justify-between">
            <p className="text-sm text-muted-foreground">
              Need help? Check out the{" "}
              <Link href="/docs" className="text-primary hover:underline">
                documentation
              </Link>
            </p>
            {!hasAgents && (
              <Button asChild>
                <Link href="/admin/agents">
                  Get Started
                  <ArrowRight className="h-4 w-4 ml-2" />
                </Link>
              </Button>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
