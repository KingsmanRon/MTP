"use client";

import { useState, useRef, useEffect } from "react";
import { cn } from "@/lib/utils";

const FORMSPREE_ENDPOINT = "https://formspree.io/f/mpqjkbre";

const initialForm = {
  name: "",
  email: "",
  company: "",
  rail: "",
  framework: "",
  purchases: "",
  policy: "",
  message: "",
};

/** Shared focus treatment, matching the landing page primitives. */
const focusRing =
  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background";

const fieldClasses =
  "rounded-md border border-input bg-card px-4 py-3 font-sans text-sm text-foreground outline-none transition-colors placeholder:text-muted-foreground hover:border-primary/40 focus:border-primary focus:ring-2 focus:ring-ring/20";

const labelClasses = "font-mono text-xs tracking-wide text-muted-foreground";

const errorFieldClasses =
  "border-destructive hover:border-destructive focus:border-destructive focus:ring-destructive/20";

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
    <div ref={ref} className="relative">
      {/* trigger */}
      <button
        id={id}
        type="button"
        onClick={() => setOpen((o) => !o)}
        className={cn(
          "flex w-full items-center justify-between rounded-md border bg-card px-4 py-3 font-sans text-sm transition-colors hover:border-primary/40",
          open ? "border-primary" : "border-input",
          selected ? "text-foreground" : "text-muted-foreground",
          focusRing,
        )}
        aria-haspopup="listbox"
        aria-expanded={open}
      >
        <span>{selected ? selected.label : placeholder}</span>
        <svg
          width="16"
          height="16"
          viewBox="0 0 16 16"
          fill="none"
          aria-hidden="true"
          className="shrink-0 text-muted-foreground transition-transform duration-200"
          style={{ transform: open ? "rotate(180deg)" : "rotate(0deg)" }}
        >
          <path d="M4 6L8 10L12 6" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </button>

      {/* dropdown list */}
      {open && (
        <ul
          role="listbox"
          aria-activedescendant={value ? `${id}-opt-${value}` : undefined}
          className="absolute left-0 right-0 z-50 mt-1 overflow-hidden rounded-md border border-tileLine bg-card py-1 shadow-lg"
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
                className={cn(
                  "flex cursor-pointer items-center justify-between px-4 py-2.5 font-sans text-sm transition-colors",
                  isSelected
                    ? "bg-accent text-foreground"
                    : "text-muted-foreground hover:bg-tile hover:text-foreground",
                )}
              >
                <span>{opt.label}</span>
                {isSelected && (
                  <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true" className="text-primary">
                    <path d="M3.5 8.5L6.5 11.5L12.5 4.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
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

/* Payment rails and providers, not generic risk categories. The question the
   page needs answered is which system actually moves the money. */
const railOptions: DropdownOption[] = [
  { value: "stripe", label: "Stripe" },
  { value: "x402", label: "x402 / stablecoin" },
  { value: "card", label: "Card issuer or virtual cards" },
  { value: "bank", label: "Bank transfer / ACH / SEPA" },
  { value: "internal", label: "Internal ledger or wallet" },
  { value: "undecided", label: "Not decided yet" },
  { value: "other", label: "Other" },
];

/* ── Contact section ────────────────────────────────────────────── */

/* ── Inline validation ──────────────────────────────────────────── */

function FieldError({ id, message }: { id: string; message: string | null }) {
  if (!message) return null;
  return (
    <p id={id} role="alert" className="font-sans text-xs text-destructive">
      {message}
    </p>
  );
}

/**
 * Validation runs on blur, so a reader is told about a malformed email while
 * they are still looking at the field — not after they have committed to
 * sending and had the whole form bounced back at them.
 */
function fieldError(name: string, value: string): string | null {
  const trimmed = value.trim();
  if (name === "name" && !trimmed) return "Tell us who you are.";
  if (name === "company" && !trimmed) return "Which company are you writing from?";
  if (name === "message" && !trimmed) return "A sentence or two is enough.";
  if (name === "email") {
    if (!trimmed) return "We need an address to reply to.";
    // Deliberately permissive: reject what is obviously not an address, and
    // let the server be the authority on the rest. A clever regex here mostly
    // succeeds at rejecting real addresses.
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmed)) {
      return "That does not look like an email address.";
    }
  }
  return null;
}

/** The four fields that make up the default view. */
const REQUIRED_FIELDS = ["name", "email", "company", "message"] as const;

export default function ContactSection() {
  const [status, setStatus] = useState<"idle" | "submitting" | "success" | "error">("idle");
  const [form, setForm] = useState(initialForm);
  const [errors, setErrors] = useState<Record<string, string | null>>({});
  // Progressive disclosure. The common path is four fields; the payment rail,
  // agent framework and the two policy questions are qualification detail and
  // sit one level deeper. Everything still submits — see handleSubmit.
  const [showTechnical, setShowTechnical] = useState(false);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
    const { name, value } = e.target;
    setForm((prev) => ({ ...prev, [name]: value }));
    // Clear a resolved error as the reader types; do not introduce a new one
    // mid-keystroke, which would flag every address as invalid while typing.
    setErrors((prev) => (prev[name] ? { ...prev, [name]: fieldError(name, value) } : prev));
  };

  const handleBlur = (
    e: React.FocusEvent<HTMLInputElement | HTMLTextAreaElement>,
  ) => {
    const { name, value } = e.target;
    setErrors((prev) => ({ ...prev, [name]: fieldError(name, value) }));
  };

  const handleDropdown = (name: string, value: string) => {
    setForm((prev) => ({ ...prev, [name]: value }));
  };

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();

    const nextErrors: Record<string, string | null> = {};
    for (const field of REQUIRED_FIELDS) {
      nextErrors[field] = fieldError(field, form[field]);
    }
    if (Object.values(nextErrors).some(Boolean)) {
      setErrors(nextErrors);
      return;
    }

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
        setErrors({});
        setShowTechnical(false);
      } else {
        setStatus("error");
      }
    } catch {
      setStatus("error");
    }
  };

  return (
    <section id="contact" className="border-b border-border bg-background px-6 py-24">
      <div className="mx-auto max-w-5xl">
        <p className="mb-3 border-l-[3px] border-primary pl-3 font-mono text-xs uppercase tracking-widest text-brandInk">
          Get in touch
        </p>

        <h2 className="mb-4 font-sans text-3xl font-semibold text-foreground">
          Talk to us about an agent payment workflow.
        </h2>

        <p className="mb-12 max-w-2xl font-sans text-base leading-7 text-muted-foreground">
          Tell us what the agent can pay for, which system executes the payment and which limits
          or approvals must be enforced.
        </p>

        <div className="grid grid-cols-1 gap-12 md:grid-cols-[1.2fr_0.8fr]">
          <div>
            {status === "success" ? (
              <div
                className="flex flex-col gap-4 rounded-lg border border-success/30 bg-success/5 p-8"
                aria-live="polite"
              >
                <div className="flex items-center gap-3">
                  <div className="flex h-10 w-10 items-center justify-center rounded-full border border-success/30 bg-success/10 text-success">
                    ✓
                  </div>
                  <div>
                    <p className="font-sans text-base font-semibold text-foreground">
                      Message received
                    </p>
                    <p className="font-sans text-sm text-muted-foreground">
                      Thanks for reaching out. Design-partner and technical enquiries are
                      answered within one business day, using the email you provided.
                    </p>
                  </div>
                </div>

                <div className="rounded-md border border-tileLine bg-card px-4 py-3">
                  <p className="font-sans text-sm leading-relaxed text-muted-foreground">
                    This inbox is used for design-partner enquiries, technical questions, and
                    integration conversations. If your payment workflow is a fit, we will guide
                    the next step directly.
                  </p>
                </div>

                <button
                  type="button"
                  onClick={() => setStatus("idle")}
                  className={cn(
                    "mt-1 w-fit rounded-sm font-sans text-sm text-brandInk underline underline-offset-4 transition-colors hover:text-brandDeep",
                    focusRing,
                  )}
                >
                  Send another message
                </button>
              </div>
            ) : (
              <form onSubmit={handleSubmit} noValidate className="flex flex-col gap-5">
                <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                  <div className="flex flex-col gap-1.5">
                    <label htmlFor="contact-name" className={labelClasses}>
                      Name
                    </label>
                    <input
                      id="contact-name"
                      type="text"
                      name="name"
                      value={form.name}
                      onChange={handleChange}
                      onBlur={handleBlur}
                      required
                      aria-invalid={Boolean(errors.name)}
                      aria-describedby={errors.name ? "contact-name-error" : undefined}
                      placeholder="Your name"
                      className={cn(fieldClasses, errors.name && errorFieldClasses)}
                    />
                    <FieldError id="contact-name-error" message={errors.name ?? null} />
                  </div>

                  <div className="flex flex-col gap-1.5">
                    <label htmlFor="contact-email" className={labelClasses}>
                      Work email
                    </label>
                    <input
                      id="contact-email"
                      type="email"
                      name="email"
                      value={form.email}
                      onChange={handleChange}
                      onBlur={handleBlur}
                      required
                      aria-invalid={Boolean(errors.email)}
                      aria-describedby={errors.email ? "contact-email-error" : undefined}
                      placeholder="you@company.com"
                      className={cn(fieldClasses, errors.email && errorFieldClasses)}
                    />
                    <FieldError id="contact-email-error" message={errors.email ?? null} />
                  </div>
                </div>

                <div className="flex flex-col gap-1.5">
                  <label htmlFor="contact-company" className={labelClasses}>
                    Company
                  </label>
                  <input
                    id="contact-company"
                    type="text"
                    name="company"
                    value={form.company}
                    onChange={handleChange}
                    onBlur={handleBlur}
                    required
                    aria-invalid={Boolean(errors.company)}
                    aria-describedby={errors.company ? "contact-company-error" : undefined}
                    placeholder="Your company"
                    className={cn(fieldClasses, errors.company && errorFieldClasses)}
                  />
                  <FieldError id="contact-company-error" message={errors.company ?? null} />
                </div>

                <div className="flex flex-col gap-1.5">
                  <label htmlFor="contact-message" className={labelClasses}>
                    Message
                  </label>
                  <textarea
                    id="contact-message"
                    name="message"
                    value={form.message}
                    onChange={handleChange}
                    onBlur={handleBlur}
                    required
                    rows={5}
                    aria-invalid={Boolean(errors.message)}
                    aria-describedby={errors.message ? "contact-message-error" : undefined}
                    placeholder="Tell us about your agent stack, your use case, or any questions..."
                    className={cn(fieldClasses, "resize-none", errors.message && errorFieldClasses)}
                  />
                  <FieldError id="contact-message-error" message={errors.message ?? null} />
                </div>

                {/* ── Technical detail, one level deeper ──────────────── */}
                {/* These four answers qualify a pilot, but asking all of them
                    up front turns an enquiry into a questionnaire. They are
                    optional, they are collapsed by default, and whatever is
                    filled in is submitted with the rest of the form. */}
                <div className="rounded-md border border-tileLine bg-tile">
                  <button
                    type="button"
                    onClick={() => setShowTechnical((v) => !v)}
                    aria-expanded={showTechnical}
                    aria-controls="contact-technical"
                    className={cn(
                      "flex w-full items-center justify-between px-4 py-3 text-left font-sans text-sm text-foreground transition-colors hover:text-brandInk",
                      focusRing,
                    )}
                  >
                    <span>
                      Add technical detail
                      <span className="ml-2 font-mono text-xs text-muted-foreground">
                        optional
                      </span>
                    </span>
                    <svg
                      width="16"
                      height="16"
                      viewBox="0 0 16 16"
                      fill="none"
                      aria-hidden="true"
                      className="shrink-0 text-muted-foreground transition-transform duration-200"
                      style={{ transform: showTechnical ? "rotate(180deg)" : "rotate(0deg)" }}
                    >
                      <path
                        d="M4 6L8 10L12 6"
                        stroke="currentColor"
                        strokeWidth="1.5"
                        strokeLinecap="round"
                        strokeLinejoin="round"
                      />
                    </svg>
                  </button>

                  {showTechnical && (
                    <div id="contact-technical" className="flex flex-col gap-5 border-t border-tileLine p-4">
                      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                        <div className="flex flex-col gap-1.5">
                          <label htmlFor="contact-rail" className={labelClasses}>
                            Payment rail or provider
                          </label>
                          <Dropdown
                            id="contact-rail"
                            name="rail"
                            value={form.rail}
                            placeholder="Select one"
                            options={railOptions}
                            onChange={handleDropdown}
                          />
                        </div>

                        <div className="flex flex-col gap-1.5">
                          <label htmlFor="contact-framework" className={labelClasses}>
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
                      </div>

                      <div className="flex flex-col gap-1.5">
                        <label htmlFor="contact-purchases" className={labelClasses}>
                          What can the agent purchase or pay?
                        </label>
                        <input
                          id="contact-purchases"
                          type="text"
                          name="purchases"
                          value={form.purchases}
                          onChange={handleChange}
                          placeholder="e.g. supplier invoices under $5,000, API credits, customer refunds"
                          className={fieldClasses}
                        />
                      </div>

                      <div className="flex flex-col gap-1.5">
                        <label htmlFor="contact-policy" className={labelClasses}>
                          Which policy must be enforced?
                        </label>
                        <input
                          id="contact-policy"
                          type="text"
                          name="policy"
                          value={form.policy}
                          onChange={handleChange}
                          placeholder="e.g. per-action limit, approved recipients, human approval above $1,000"
                          className={fieldClasses}
                        />
                      </div>
                    </div>
                  )}
                </div>

                {status === "error" && (
                  <p className="font-sans text-sm text-destructive">
                    Something went wrong. Email us directly at sales@inntris.com
                  </p>
                )}

                <button
                  type="submit"
                  disabled={status === "submitting"}
                  className={cn(
                    "w-fit rounded-md bg-primary px-6 py-3 font-sans text-sm font-medium text-primary-foreground transition-colors hover:bg-brandDeep disabled:cursor-not-allowed disabled:opacity-50",
                    focusRing,
                  )}
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
            <div className="h-fit rounded-lg border border-tileLine bg-tile px-5 py-4">
              <p className="font-sans text-sm leading-relaxed text-muted-foreground">
                Whether you&apos;re exploring a design-partner pilot, verifying a receipt, or
                working out how Inntris fits in front of your payment rail, this is the address.
              </p>

              <div className="mt-3 flex flex-col gap-4">
                {/* One address, deliberately. The evidence-pack verifier's
                    README tells auditors to write in on any key discrepancy, so
                    whatever this says has to resolve — a dedicated-looking
                    security@ that bounces is worse than a shared box that
                    answers. */}
                <div className="flex flex-col gap-1">
                  <p className="font-mono text-xs uppercase tracking-wide text-muted-foreground">
                    Commercial, technical and security
                  </p>
                  <a
                    href="mailto:sales@inntris.com"
                    className={cn(
                      "w-fit rounded-sm font-mono text-sm text-brandInk underline-offset-4 transition-colors hover:underline",
                      focusRing,
                    )}
                  >
                    sales@inntris.com
                  </a>
                </div>

                <div className="flex flex-col gap-1">
                  <p className="font-mono text-xs uppercase tracking-wide text-muted-foreground">
                    Response time
                  </p>
                  <p className="font-sans text-sm text-foreground">
                    Within one business day
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="mt-10 border-t border-border pt-6">
          <p className="text-center font-sans text-sm leading-relaxed text-muted-foreground">
            Design-partner and technical enquiries are answered within one business day.
          </p>
          <p className="mt-3 text-center font-sans text-sm leading-relaxed text-muted-foreground">
            Design partners, technical questions, security reports and key verification:{" "}
            <a
              href="mailto:sales@inntris.com"
              className={cn(
                "rounded-sm font-mono text-brandInk underline-offset-4 hover:underline",
                focusRing,
              )}
            >
              sales@inntris.com
            </a>
          </p>
        </div>
      </div>
    </section>
  );
}
