"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { Menu, X } from "lucide-react";
import { cn } from "@/lib/utils";

export interface MobileMenuLink {
  href: string;
  label: string;
}

interface MobileMenuProps {
  links: MobileMenuLink[];
  /** Optional highlighted call-to-action rendered below the links. */
  cta?: MobileMenuLink;
  /** Matches the light header on /ai-pr-protection; defaults to the dark shell. */
  variant?: "dark" | "light";
}

/**
 * Hamburger menu for the public page headers. The desktop nav links are
 * `hidden md:flex`, so without this, phones have no navigation at all.
 * Renders only below `md`; the dropdown panel sits under the sticky header.
 */
export function MobileMenu({ links, cta, variant = "dark" }: MobileMenuProps) {
  const [open, setOpen] = useState(false);
  const pathname = usePathname();

  // Close when the route changes (hash links don't change the pathname,
  // so those close via the link onClick below).
  useEffect(() => {
    setOpen(false);
  }, [pathname]);

  const dark = variant === "dark";

  return (
    <div className="md:hidden">
      <button
        type="button"
        aria-label={open ? "Close menu" : "Open menu"}
        aria-expanded={open}
        onClick={() => setOpen((v) => !v)}
        className={cn(
          "flex h-10 w-10 items-center justify-center rounded-lg border transition-colors",
          dark
            ? "border-[#22314D] bg-[#0D1728] text-[#C4CFDE] hover:text-white"
            : "border-[#171A1F]/15 bg-white text-[#424B57] hover:text-[#171A1F]"
        )}
      >
        {open ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
      </button>

      {open && (
        <div
          className={cn(
            "absolute inset-x-0 top-full border-b shadow-xl",
            dark
              ? "border-[#22314D] bg-[#07111F]"
              : "border-[#171A1F]/10 bg-[#F6F8FA]"
          )}
        >
          <nav className="mx-auto flex max-w-7xl flex-col px-6 py-3">
            {links.map(({ href, label }) => (
              <Link
                key={href}
                href={href}
                onClick={() => setOpen(false)}
                className={cn(
                  "rounded-lg px-3 py-3 text-[15px] transition-colors",
                  dark
                    ? "text-[#C4CFDE] hover:bg-[#0D1728] hover:text-white"
                    : "text-[#424B57] hover:bg-white hover:text-[#171A1F]"
                )}
              >
                {label}
              </Link>
            ))}
            {cta && (
              <Link
                href={cta.href}
                onClick={() => setOpen(false)}
                className={cn(
                  "mb-2 mt-2 rounded-md px-4 py-3 text-center text-sm font-medium text-white transition-opacity hover:opacity-90",
                  dark ? "bg-[#28C281]" : "bg-[#0F766E]"
                )}
              >
                {cta.label}
              </Link>
            )}
          </nav>
        </div>
      )}
    </div>
  );
}
