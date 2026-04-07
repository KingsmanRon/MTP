"use client";

import { useState, useRef, useEffect } from "react";

const FORMSPREE_ENDPOINT = "https://formspree.io/f/mpqjkbre";

const initialForm = {
  name: "",
  email: "",
  framework: "",
  risk: "",
  subject: "",
  message: "",
};

/* ── Custom dropdown ────────────────────────────────────────────── */

interface DropdownOption {
  value: string;
  label: string;
}

function Dropdown({
  id,
  name,
  value,
  placeholder,
  options,
  onChange,
}: {
  id: string;
  name: string;
  value: string;
  placeholder: string;
  options: DropdownOption[];
  onChange: (name: string, value: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  // close on outside click
  useEffect(() => {
    function handle(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    }
    document.addEventListener("mousedown", handle);
    return () => document.removeEventListener("mousedown", handle);
  }, []);

  // close on Escape
  useEffect(() => {
    function handle(e: KeyboardEvent) {
      if (e.key === "Escape") setOpen(false);
    }
    if (open) {
      document.addEventListener("keydown", handle);
      return () => document.removeEventListener("keydown", handle);
    }
  }, [open]);

  const selected = options.find((o) => o.value === value);

  return (
    <div ref={ref} className="relative" id={id}>
      {/* trigger */}
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center justify-between rounded-[12px] px-4 py-3 font-sans text-sm outline-none transition-all duration-200 hover:border-[#35507A] focus:border-[#4C8DFF] focus:ring-2 focus:ring-[#4C8DFF]/20"
        style={{
          background: "#0D1728",
          border: open ? "1px solid #4C8DFF" : "1px solid #22314D",
          color: selected ? "#F5F7FB" : "#7F8CA3",
        }}
        aria-haspopup="listbox"
        aria-expanded={open}
      >
        <span>{selected ? selected.label : placeholder}</span>
        <svg
          width="16"
          height="16"
          viewBox="0 0 16 16"
          fill="none"
          className="shrink-0 transition-transform duration-200"
          style={{ transform: open ? "rotate(180deg)" : "rotate(0deg)" }}
        >
          <path d="M4 6L8 10L12 6" stroke="#7F8CA3" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </button>

      {/* dropdown list */}
      {open && (
        <ul
          role="listbox"
          aria-activedescendant={value ? `${id}-opt-${value}` : undefined}
          className="absolute left-0 right-0 z-50 mt-1 overflow-hidden rounded-[12px] py-1"
          style={{
            background: "#0D1728",
            border: "1px solid #22314D",
            boxShadow: "0 12px 32px rgba(0,0,0,0.45)",
          }}
        >
          {options.map((opt) => {
            const isSelected = opt.value === value;
            return (
              <li
                key={opt.value}
                id={`${id}-opt-${opt.value}`}
                role="option"
                aria-selected={isSelected}
                onClick={() => {
                  onChange(name, opt.value);
                  setOpen(false);
                }}
                className="flex cursor-pointer items-center justify-between px-4 py-2.5 font-sans text-sm transition-colors duration-100"
                style={{
                  color: isSelected ? "#F5F7FB" : "#AAB7CC",
                  background: isSelected ? "rgba(76,141,255,0.10)" : "transparent",
                }}
                onMouseEnter={(e) => {
                  if (!isSelected) {
                    e.currentTarget.style.background = "rgba(76,141,255,0.06)";
                    e.currentTarget.style.color = "#F5F7FB";
                  }
                }}
                onMouseLeave={(e) => {
                  if (!isSelected) {
                    e.currentTarget.style.background = "transparent";
                    e.currentTarget.style.color = "#AAB7CC";
                  }
                }}
              >
                <span>{opt.label}</span>
                {isSelected && (
                  <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                    <path d="M3.5 8.5L6.5 11.5L12.5 4.5" stroke="#4C8DFF" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                  </svg>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}

/* ── Options data ───────────────────────────────────────────────── */

const frameworkOptions: DropdownOption[] = [
  { value: "claude", label: "Claude / Anthropic" },
  { value: "langchain", label: "LangChain / LangGraph" },
  { value: "crewai", label: "CrewAI" },
  { value: "autogen", label: "AutoGen" },
  { value: "composio", label: "Composio" },
  { value: "custom", label: "Custom / in-house" },
  { value: "other", label: "Other" },
];

const riskOptions: DropdownOption[] = [
  { value: "code", label: "Writing / executing code" },
  { value: "data", label: "Accessing sensitive data" },
  { value: "api", label: "Calling external APIs / tools" },
  { value: "finance", label: "Financial or payment operations" },
  { value: "multiple", label: "Multiple of the above" },
];

/* ── Contact section ────────────────────────────────────────────── */

export default function ContactSection() {
  const [status, setStatus] = useState<"idle" | "submitting" | "success" | "error">("idle");
  const [form, setForm] = useState(initialForm);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
    const { name, value } = e.target;
    setForm((prev) => ({ ...prev, [name]: value }));
  };

  const handleDropdown = (name: string, value: string) => {
    setForm((prev) => ({ ...prev, [name]: value }));
  };

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setStatus("submitting");

    try {
      const res = await fetch(FORMSPREE_ENDPOINT, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify(form),
      });

      if (res.ok) {
        setStatus("success");
        setForm(initialForm);
      } else {
        setStatus("error");
      }
    } catch {
      setStatus("error");
    }
  };

  const inputStyles = {
    background: "#0D1728",
    border: "1px solid #22314D",
    color: "#F5F7FB",
  };

  return (
    <section id="contact" className="px-6 py-24" style={{ background: "#07111F" }}>
      <div className="mx-auto max-w-5xl">
        <p
          className="mb-3 font-mono text-xs uppercase tracking-widest"
          style={{ color: "#4C8DFF" }}
        >
          Get in touch
        </p>

        <h2
          className="mb-12 font-sans text-3xl font-semibold"
          style={{ color: "#F5F7FB" }}
        >
          Talk to us about your agents.
        </h2>

        <div className="grid grid-cols-1 gap-12 md:grid-cols-[1.2fr_0.8fr]">
          <div>
            {status === "success" ? (
              <div
                className="flex flex-col gap-4 rounded-[24px] p-8 shadow-[0_20px_60px_rgba(0,0,0,0.25)]"
                style={{
                  background:
                    "linear-gradient(180deg, rgba(40,194,129,0.10) 0%, rgba(13,23,40,1) 40%)",
                  border: "1px solid rgba(40,194,129,0.35)",
                }}
                aria-live="polite"
              >
                <div className="flex items-center gap-3">
                  <div
                    className="flex h-10 w-10 items-center justify-center rounded-full"
                    style={{
                      background: "rgba(40,194,129,0.14)",
                      border: "1px solid rgba(40,194,129,0.28)",
                      color: "#28C281",
                    }}
                  >
                    ✓
                  </div>
                  <div>
                    <p
                      className="font-sans text-base font-semibold"
                      style={{ color: "#F5F7FB" }}
                    >
                      Message received
                    </p>
                    <p className="font-sans text-sm" style={{ color: "#AAB7CC" }}>
                      Thanks for reaching out. We will reply within 24 hours using the email
                      you provided.
                    </p>
                  </div>
                </div>

                <div
                  className="rounded-[16px] px-4 py-3"
                  style={{
                    background: "rgba(13,23,40,0.78)",
                    border: "1px solid rgba(40,194,129,0.18)",
                  }}
                >
                  <p className="font-sans text-sm leading-relaxed" style={{ color: "#C4CFDE" }}>
                    This inbox is used for design partner enquiries, technical questions, and
                    integration conversations. If your workflow is a fit, we will guide the
                    next step directly.
                  </p>
                </div>

                <button
                  type="button"
                  onClick={() => setStatus("idle")}
                  className="mt-1 w-fit text-sm font-sans underline underline-offset-4 transition-colors hover:opacity-90"
                  style={{ color: "#4C8DFF" }}
                >
                  Send another message
                </button>
              </div>
            ) : (
              <form onSubmit={handleSubmit} className="flex flex-col gap-5">
                <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                  <div className="flex flex-col gap-1.5">
                    <label
                      htmlFor="contact-name"
                      className="font-mono text-xs tracking-wide"
                      style={{ color: "#7F8CA3" }}
                    >
                      Name
                    </label>
                    <input
                      id="contact-name"
                      type="text"
                      name="name"
                      value={form.name}
                      onChange={handleChange}
                      required
                      placeholder="Your name"
                      className="rounded-[12px] px-4 py-3 font-sans text-sm outline-none transition-all duration-200 hover:border-[#35507A] focus:border-[#4C8DFF] focus:ring-2 focus:ring-[#4C8DFF]/20"
                      style={inputStyles}
                    />
                  </div>

                  <div className="flex flex-col gap-1.5">
                    <label
                      htmlFor="contact-email"
                      className="font-mono text-xs tracking-wide"
                      style={{ color: "#7F8CA3" }}
                    >
                      Email
                    </label>
                    <input
                      id="contact-email"
                      type="email"
                      name="email"
                      value={form.email}
                      onChange={handleChange}
                      required
                      placeholder="you@company.com"
                      className="rounded-[12px] px-4 py-3 font-sans text-sm outline-none transition-all duration-200 hover:border-[#35507A] focus:border-[#4C8DFF] focus:ring-2 focus:ring-[#4C8DFF]/20"
                      style={inputStyles}
                    />
                  </div>
                </div>

                <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                  <div className="flex flex-col gap-1.5">
                    <label
                      htmlFor="contact-framework"
                      className="font-mono text-xs tracking-wide"
                      style={{ color: "#7F8CA3" }}
                    >
                      Agent framework
                    </label>
                    <Dropdown
                      id="contact-framework"
                      name="framework"
                      value={form.framework}
                      placeholder="Select one"
                      options={frameworkOptions}
                      onChange={handleDropdown}
                    />
                  </div>

                  <div className="flex flex-col gap-1.5">
                    <label
                      htmlFor="contact-risk"
                      className="font-mono text-xs tracking-wide"
                      style={{ color: "#7F8CA3" }}
                    >
                      What are your agents doing?
                    </label>
                    <Dropdown
                      id="contact-risk"
                      name="risk"
                      value={form.risk}
                      placeholder="Select one"
                      options={riskOptions}
                      onChange={handleDropdown}
                    />
                  </div>
                </div>

                <div className="flex flex-col gap-1.5">
                  <label
                    htmlFor="contact-subject"
                    className="font-mono text-xs tracking-wide"
                    style={{ color: "#7F8CA3" }}
                  >
                    Subject
                  </label>
                  <input
                    id="contact-subject"
                    type="text"
                    name="subject"
                    value={form.subject}
                    onChange={handleChange}
                    required
                    placeholder="e.g. Design partner inquiry / Technical question"
                    className="rounded-[12px] px-4 py-3 font-sans text-sm outline-none transition-all duration-200 hover:border-[#35507A] focus:border-[#4C8DFF] focus:ring-2 focus:ring-[#4C8DFF]/20"
                    style={inputStyles}
                  />
                </div>

                <div className="flex flex-col gap-1.5">
                  <label
                    htmlFor="contact-message"
                    className="font-mono text-xs tracking-wide"
                    style={{ color: "#7F8CA3" }}
                  >
                    Message
                  </label>
                  <textarea
                    id="contact-message"
                    name="message"
                    value={form.message}
                    onChange={handleChange}
                    required
                    rows={5}
                    placeholder="Tell us about your agent stack, your use case, or any questions..."
                    className="resize-none rounded-[12px] px-4 py-3 font-sans text-sm outline-none transition-all duration-200 hover:border-[#35507A] focus:border-[#4C8DFF] focus:ring-2 focus:ring-[#4C8DFF]/20"
                    style={inputStyles}
                  />
                </div>

                {status === "error" && (
                  <p className="font-sans text-sm" style={{ color: "#ef4444" }}>
                    Something went wrong. Email us directly at sales@inntris.com
                  </p>
                )}

                <button
                  type="submit"
                  disabled={status === "submitting"}
                  className="w-fit rounded-[12px] px-6 py-3 font-sans text-sm font-medium transition-all duration-200 hover:opacity-95 disabled:cursor-not-allowed disabled:opacity-50"
                  style={{
                    background: "#4C8DFF",
                    color: "#F5F7FB",
                    boxShadow: "0 10px 30px rgba(76, 141, 255, 0.18)",
                  }}
                >
                  {status === "submitting" ? "Sending..." : "Send message"}
                </button>
              </form>
            )}
          </div>

          <div className="flex flex-col">
            {/* Spacer to align tile with input boxes (matches label + gap height) */}
            <div className="hidden md:block">
              <p className="font-mono text-xs tracking-wide opacity-0" aria-hidden="true">
                &nbsp;
              </p>
              <div className="h-1.5" />
            </div>
            <div
              className="h-fit rounded-[12px] px-5 py-4"
              style={{ background: "#0D1728", border: "1px solid #22314D" }}
            >
            <p className="font-sans text-sm leading-relaxed" style={{ color: "#AAB7CC" }}>
              Whether you&apos;re exploring design partner opportunities, have technical
              questions, or want to know how Inntris fits your agent stack, we respond
              within 24 hours.
            </p>

            <div className="mt-3 flex flex-col gap-4">
              <div className="flex flex-col gap-1">
                <p
                  className="font-mono text-xs uppercase tracking-wide"
                  style={{ color: "#7F8CA3" }}
                >
                  Email
                </p>
                <a
                  href="mailto:sales@inntris.com"
                  className="w-fit font-mono text-sm underline-offset-4 transition-all duration-200 hover:underline focus:outline-none focus:ring-2 focus:ring-[#4C8DFF]/20"
                  style={{ color: "#4C8DFF" }}
                >
                  sales@inntris.com
                </a>
              </div>

              <div className="flex flex-col gap-1">
                <p
                  className="font-mono text-xs uppercase tracking-wide"
                  style={{ color: "#7F8CA3" }}
                >
                  Response time
                </p>
                <p className="font-sans text-sm" style={{ color: "#C4CFDE" }}>
                  Within 24 hours
                </p>
              </div>
            </div>
          </div>
          </div>
        </div>

        <div
          className="mt-10 pt-6"
          style={{ borderTop: "1px solid #22314D" }}
        >
          <p className="text-center font-sans text-sm leading-relaxed" style={{ color: "#7F8CA3" }}>
            We respond within 24 hours. If you&apos;re running agents against code, data,
            or financial operations — that&apos;s our sweet spot.
          </p>
          <p className="mt-3 text-center font-sans text-sm leading-relaxed" style={{ color: "#7F8CA3" }}>
            For design partner discussions, platform reviews, and production agent
            deployments, contact{" "}
            <a
              href="mailto:sales@inntris.com"
              className="font-mono underline-offset-4 hover:underline"
              style={{ color: "#4C8DFF" }}
            >
              sales@inntris.com
            </a>
            .
          </p>
        </div>
      </div>
    </section>
  );
}
