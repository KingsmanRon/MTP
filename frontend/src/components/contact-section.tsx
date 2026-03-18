"use client";

import { useState } from "react";

const FORMSPREE_ENDPOINT = "https://formspree.io/f/mpqjkbre";

const initialForm = {
  name: "",
  email: "",
  framework: "",
  risk: "",
  subject: "",
  message: "",
};

export default function ContactSection() {
  const [status, setStatus] = useState<"idle" | "submitting" | "success" | "error">("idle");
  const [form, setForm] = useState(initialForm);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => {
    const { name, value } = e.target;
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
                    <select
                      id="contact-framework"
                      name="framework"
                      value={form.framework}
                      onChange={handleChange}
                      className="rounded-[12px] px-4 py-3 font-sans text-sm outline-none transition-all duration-200 hover:border-[#35507A] focus:border-[#4C8DFF] focus:ring-2 focus:ring-[#4C8DFF]/20"
                      style={inputStyles}
                    >
                      <option value="">Select one</option>
                      <option value="claude">Claude / Anthropic</option>
                      <option value="langchain">LangChain / LangGraph</option>
                      <option value="crewai">CrewAI</option>
                      <option value="autogen">AutoGen</option>
                      <option value="composio">Composio</option>
                      <option value="custom">Custom / in-house</option>
                      <option value="other">Other</option>
                    </select>
                  </div>

                  <div className="flex flex-col gap-1.5">
                    <label
                      htmlFor="contact-risk"
                      className="font-mono text-xs tracking-wide"
                      style={{ color: "#7F8CA3" }}
                    >
                      What are your agents doing?
                    </label>
                    <select
                      id="contact-risk"
                      name="risk"
                      value={form.risk}
                      onChange={handleChange}
                      className="rounded-[12px] px-4 py-3 font-sans text-sm outline-none transition-all duration-200 hover:border-[#35507A] focus:border-[#4C8DFF] focus:ring-2 focus:ring-[#4C8DFF]/20"
                      style={inputStyles}
                    >
                      <option value="">Select one</option>
                      <option value="code">Writing / executing code</option>
                      <option value="data">Accessing sensitive data</option>
                      <option value="api">Calling external APIs / tools</option>
                      <option value="finance">Financial or payment operations</option>
                      <option value="multiple">Multiple of the above</option>
                    </select>
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
                    Something went wrong. Email us directly at applications@inntris.com
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
                  href="mailto:applications@inntris.com"
                  className="w-fit font-mono text-sm underline-offset-4 transition-all duration-200 hover:underline focus:outline-none focus:ring-2 focus:ring-[#4C8DFF]/20"
                  style={{ color: "#4C8DFF" }}
                >
                  applications@inntris.com
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
        </div>
      </div>
    </section>
  );
}
