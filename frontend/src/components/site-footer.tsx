import Link from "next/link";
import { InntrisLogo } from "@/components/inntris-logo";
import { focusRing } from "@/components/landing/primitives";
import {
  BRAND_COPYRIGHT,
  BRAND_NAME,
  BRAND_TAGLINE,
  FOOTER_NAV,
} from "@/lib/brand";
import { cn } from "@/lib/utils";

/**
 * The one footer. Every public page renders this component, so the brand name,
 * the tagline and the footer navigation cannot drift apart between the
 * marketing site and the product surfaces.
 *
 * `className` exists only for the border/ground token a page needs to sit on
 * (`border-border` on the marketing pages, `border-tileLine` on the receipt
 * surfaces). Nothing about the content is per-page.
 */
export function SiteFooter({ className }: { className?: string }) {
  return (
    <footer className={cn("border-t border-border bg-background", className)}>
      <div className="mx-auto max-w-7xl px-6 py-10 lg:px-8">
        <div className="flex flex-col items-center gap-5">
          <div className="flex items-center gap-2.5">
            <InntrisLogo className="h-5 w-5" />
            <span className="text-sm font-semibold tracking-tight text-foreground">
              {BRAND_NAME}
            </span>
          </div>
          <p className="text-center text-sm text-muted-foreground">{BRAND_TAGLINE}</p>
          <nav
            aria-label="Footer"
            className="flex flex-wrap items-center justify-center gap-x-6 gap-y-3"
          >
            {FOOTER_NAV.map((link) => (
              <Link
                key={link.href}
                href={link.href}
                className={cn(
                  "rounded-sm text-sm text-muted-foreground transition-colors hover:text-foreground",
                  focusRing,
                )}
              >
                {link.label}
              </Link>
            ))}
          </nav>
          <p className="text-xs text-muted-foreground">{BRAND_COPYRIGHT}</p>
        </div>
      </div>
    </footer>
  );
}
