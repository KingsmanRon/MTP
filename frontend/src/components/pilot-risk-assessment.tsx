"use client";

import { useMemo, useState } from "react";
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Loader2,
  ShieldCheck,
} from "lucide-react";
import {
  assessPilotRisk,
  PILOT_RISK_SIGNALS,
  PilotRiskSignalId,
} from "@/lib/pilot-risk";

const FORMSPREE_ENDPOINT = "https://formspree.io/f/mpqjkbre";

const levelStyles = {
  observe: {
    badge: "border-[#4C8DFF]/30 bg-[#4C8DFF]/10 text-[#8FB8FF]",
    icon: ShieldCheck,
  },
  candidate: {
    badge: "border-[#F59E0B]/30 bg-[#F59E0B]/10 text-[#FBBF24]",
    icon: AlertTriangle,
  },
  priority: {
    badge: "border-[#28C281]/30 bg-[#28C281]/10 text-[#28C281]",
    icon: CheckCircle2,
  },
};

export function PilotRiskAssessment() {
  const [selected, setSelected] = useState<PilotRiskSignalId[]>([]);
  const [form, setForm] = useState({ name: "", email: "", company: "", context: "" });
  const [status, setStatus] = useState<"idle" | "submitting" | "success" | "error">("idle");
  const assessment = useMemo(() => assessPilotRisk(selected), [selected]);
  const resultStyle = levelStyles[assessment.level];
  const ResultIcon = resultStyle.icon;

  const toggleSignal = (id: PilotRiskSignalId) => {
    setSelected((current) =>
      current.includes(id) ? current.filter((item) => item !== id) : [...current, id],
    );
  };

  const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setStatus("submitting");

    try {
      const response = await fetch(FORMSPREE_ENDPOINT, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify({
          ...form,
          subject: `14-day pilot request: ${assessment.recommendedWorkflow}`,
          source: "pilot-risk-assessment",
          risk_score: `${assessment.score}/${assessment.maxScore}`,
          qualification: assessment.label,
          recommended_workflow: assessment.recommendedWorkflow,
          selected_risk_signals: assessment.selectedSignals.join(" | "),
        }),
      });

      setStatus(response.ok ? "success" : "error");
    } catch {
      setStatus("error");
    }
  };

  return (
    <section id="assessment" className="mx-auto max-w-7xl px-6 py-20 lg:px-8">
      <div className="mb-10 max-w-3xl">
        <p className="text-sm font-medium uppercase tracking-[0.18em] text-[#8FB8FF]">
          Pilot qualification
        </p>
        <h2 className="mt-3 text-3xl font-semibold tracking-tight md:text-5xl">
          Find the action worth protecting first.
        </h2>
        <p className="mt-4 text-lg leading-8 text-[#AAB7CC]">
          Select what is true today. Inntris will recommend the highest-value workflow for a
          focused pilot.
        </p>
      </div>

      <div className="grid gap-6 lg:grid-cols-[1.08fr_0.92fr]">
        <div className="grid gap-3 sm:grid-cols-2">
          {PILOT_RISK_SIGNALS.map((signal) => {
            const isSelected = selected.includes(signal.id);
            return (
              <label
                key={signal.id}
                className={`cursor-pointer rounded-2xl border p-5 transition ${
                  isSelected
                    ? "border-[#4C8DFF] bg-[#4C8DFF]/10"
                    : "border-[#22314D] bg-[#0D1728] hover:border-[#35507A]"
                }`}
              >
                <input
                  type="checkbox"
                  className="sr-only"
                  checked={isSelected}
                  onChange={() => toggleSignal(signal.id)}
                />
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <p className="font-medium leading-6 text-[#F5F7FB]">{signal.question}</p>
                    <p className="mt-2 text-sm leading-6 text-[#7F8CA3]">{signal.detail}</p>
                  </div>
                  <span
                    className={`mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full border text-xs ${
                      isSelected
                        ? "border-[#4C8DFF] bg-[#4C8DFF] text-white"
                        : "border-[#35507A] text-transparent"
                    }`}
                  >
                    <CheckCircle2 className="h-4 w-4" />
                  </span>
                </div>
              </label>
            );
          })}
        </div>

        <aside className="h-fit rounded-[24px] border border-[#22314D] bg-[#0D1728] p-6 lg:sticky lg:top-24">
          <div className="flex items-center justify-between gap-4">
            <span className={`rounded-full border px-3 py-1 text-xs font-medium ${resultStyle.badge}`}>
              {assessment.label}
            </span>
            <span className="font-mono text-sm text-[#AAB7CC]">
              {assessment.score}/{assessment.maxScore}
            </span>
          </div>

          <div className="mt-6 flex gap-4">
            <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl bg-[#101C31] text-[#8FB8FF]">
              <ResultIcon className="h-5 w-5" />
            </div>
            <div>
              <p className="text-xs font-semibold uppercase tracking-[0.16em] text-[#7F8CA3]">
                Recommended pilot workflow
              </p>
              <h3 className="mt-2 text-xl font-semibold text-[#F5F7FB]">
                {assessment.recommendedWorkflow}
              </h3>
              <p className="mt-3 text-sm leading-6 text-[#AAB7CC]">{assessment.summary}</p>
            </div>
          </div>

          <div className="my-6 border-t border-[#22314D]" />

          {status === "success" ? (
            <div className="rounded-2xl border border-[#28C281]/30 bg-[#28C281]/10 p-5">
              <p className="font-medium text-[#28C281]">Pilot request received.</p>
              <p className="mt-2 text-sm leading-6 text-[#C4CFDE]">
                We will use this risk profile to prepare a focused workflow review and reply
                within 24 hours.
              </p>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <p className="font-medium text-[#F5F7FB]">Request a 14-day pilot scope</p>
                <p className="mt-1 text-sm leading-6 text-[#7F8CA3]">
                  We will review one workflow, define its policy boundary, and show the
                  PASS/BLOCK receipt path.
                </p>
              </div>
              <div className="grid gap-3 sm:grid-cols-2">
                <input
                  required
                  aria-label="Name"
                  placeholder="Name"
                  value={form.name}
                  onChange={(event) => setForm({ ...form, name: event.target.value })}
                  className="rounded-xl border border-[#22314D] bg-[#101C31] px-4 py-3 text-sm text-[#F5F7FB] outline-none placeholder:text-[#7F8CA3] focus:border-[#4C8DFF]"
                />
                <input
                  required
                  type="email"
                  aria-label="Work email"
                  placeholder="Work email"
                  value={form.email}
                  onChange={(event) => setForm({ ...form, email: event.target.value })}
                  className="rounded-xl border border-[#22314D] bg-[#101C31] px-4 py-3 text-sm text-[#F5F7FB] outline-none placeholder:text-[#7F8CA3] focus:border-[#4C8DFF]"
                />
              </div>
              <input
                required
                aria-label="Company"
                placeholder="Company"
                value={form.company}
                onChange={(event) => setForm({ ...form, company: event.target.value })}
                className="w-full rounded-xl border border-[#22314D] bg-[#101C31] px-4 py-3 text-sm text-[#F5F7FB] outline-none placeholder:text-[#7F8CA3] focus:border-[#4C8DFF]"
              />
              <textarea
                aria-label="Workflow context"
                placeholder="What action are you preparing to put into production?"
                rows={3}
                value={form.context}
                onChange={(event) => setForm({ ...form, context: event.target.value })}
                className="w-full resize-none rounded-xl border border-[#22314D] bg-[#101C31] px-4 py-3 text-sm text-[#F5F7FB] outline-none placeholder:text-[#7F8CA3] focus:border-[#4C8DFF]"
              />
              {status === "error" && (
                <p className="text-sm text-[#F87171]">
                  Submission failed. Email sales@inntris.com with your workflow.
                </p>
              )}
              <button
                type="submit"
                disabled={status === "submitting"}
                className="inline-flex w-full items-center justify-center rounded-xl bg-[#28C281] px-5 py-3 text-sm font-medium text-white transition hover:opacity-90 disabled:opacity-60"
              >
                {status === "submitting" ? (
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                ) : (
                  <ArrowRight className="mr-2 h-4 w-4" />
                )}
                {status === "submitting" ? "Sending risk profile..." : "Request pilot scope"}
              </button>
            </form>
          )}

          <p className="mt-4 text-xs leading-5 text-[#7F8CA3]">
            This assessment qualifies a pilot workflow. It is not a security certification.
          </p>
        </aside>
      </div>
    </section>
  );
}
