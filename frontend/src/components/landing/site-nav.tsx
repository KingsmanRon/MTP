import Link from "next/link";
import { InntrisLogo } from "@/components/inntris-logo";
import { MobileMenu } from "@/components/mobile-menu";
import { focusRing } from "./primitives";
import { cn } from "@/lib/utils";

const NAV_LINKS = [
  { href: "/#overview", label: "Overview" },
  { href: "/#modules", label: "Modules" },
  { href: "/pilot", label: "14-day Pilot" },
  { href: "/docs", label: "Docs" },
  { href: "/verify", label: "Verify" },
];

const CTA = { href: "/pilot", label: "Apply for Early Access" };

export function SiteNav() {
  return (
    <header className="sticky top-0 z-30 border-b border-border bg-background/90 backdrop-blur">
      <div className="mx-auto flex max-w-7xl items-center justify-between gap-4 px-6 py-4 lg:px-8">
        <Link
          href="/"
          aria-label="Inntris home"
          className={cn("flex items-center gap-3 rounded-md", focusRing)}
        >
          <span className="flex h-10 w-10 items-center justify-center rounded-lg border border-tileLine bg-tile">
            <InntrisLogo className="h-6 w-6" />
          </span>
          <span className="text-lg font-semibold tracking-tight text-foreground">
            Inntris
          </span>
        </Link>

        <nav aria-label="Primary" className="hidden items-center gap-7 md:flex">
          {NAV_LINKS.map((link) => (
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

        <div className="flex items-center gap-3">
          <Link
            href={CTA.href}
            className={cn(
              "hidden min-h-11 items-center rounded-md bg-primary px-4 text-sm font-medium text-primary-foreground transition-colors hover:bg-brandDeep md:inline-flex",
              focusRing,
            )}
          >
            {CTA.label}
          </Link>
          <MobileMenu variant="light" links={NAV_LINKS} cta={CTA} />
        </div>
      </div>
    </header>
  );
}
