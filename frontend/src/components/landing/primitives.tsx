import React from "react";
import { cn } from "@/lib/utils";

/**
 * Shared building blocks for the landing page.
 *
 * Two rules from the design spec are encoded here so every section inherits
 * them instead of restating the classes:
 *
 *  - Tile ground flips against its section. On a white section a tile sits on
 *    `bg-tile` with a `tile-line` border; on a tinted (`bg-muted`) section the
 *    tile is white. Hover inverts that ground and lifts the tile.
 *  - Section eyebrows carry a 3px blue bar on their left edge.
 */

/** Which ground the tile is sitting on — drives the flip and its hover inverse. */
export type Ground = "white" | "tinted";

export function Eyebrow({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <p
      className={cn(
        "border-l-[3px] border-primary pl-3 text-xs font-semibold uppercase tracking-[0.16em] text-brandInk",
        className,
      )}
    >
      {children}
    </p>
  );
}

export function SectionHeading({
  eyebrow,
  title,
  lede,
  className,
  align = "left",
}: {
  eyebrow: string;
  title: React.ReactNode;
  lede?: React.ReactNode;
  className?: string;
  align?: "left" | "center";
}) {
  return (
    <div
      className={cn(
        "max-w-3xl",
        align === "center" && "mx-auto text-center",
        className,
      )}
    >
      <Eyebrow className={cn(align === "center" && "inline-block text-left")}>
        {eyebrow}
      </Eyebrow>
      <h2 className="mt-4 text-3xl font-semibold leading-tight tracking-tight text-foreground md:text-4xl">
        {title}
      </h2>
      {lede ? (
        <p className="mt-4 text-base leading-7 text-muted-foreground md:text-lg md:leading-8">
          {lede}
        </p>
      ) : null}
    </div>
  );
}

/**
 * The flipping tile. `ground` is the colour of the section behind it, not the
 * colour of the tile — the tile always contrasts with its section, and hover
 * swaps the two.
 */
export function Tile({
  ground,
  className,
  interactive = true,
  children,
}: {
  ground: Ground;
  className?: string;
  /** Set false for tiles that are not links/buttons, to skip the hover lift. */
  interactive?: boolean;
  children: React.ReactNode;
}) {
  return (
    <div
      className={cn(
        "rounded-lg border border-tileLine transition duration-200",
        ground === "white" ? "bg-tile" : "bg-card",
        interactive && "hover:-translate-y-1 hover:border-primary/40 hover:shadow-lg",
        interactive && (ground === "white" ? "hover:bg-card" : "hover:bg-tile"),
        className,
      )}
    >
      {children}
    </div>
  );
}

/** Numeric/identifier text: mono with tabular figures, per the design rules. */
export function Num({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <span className={cn("font-mono tabular-nums", className)}>{children}</span>
  );
}

/** Icon tile filled with the blue gradient (cobalt into brand-deep). */
export function IconTile({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "flex h-12 w-12 shrink-0 items-center justify-center rounded-lg bg-gradient-to-br from-primary to-brandDeep text-primary-foreground",
        className,
      )}
    >
      {children}
    </div>
  );
}

/** Numbered step marker used by the hero panel and the integration steps. */
export function StepNumber({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-accent text-sm font-semibold text-brandInk">
      <Num>{children}</Num>
    </div>
  );
}

/**
 * Shared focus treatment. Every interactive element on the page gets this so
 * keyboard focus stays visible against both the white and tinted grounds.
 */
export const focusRing =
  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background";

export function PrimaryButton({
  href,
  children,
  className,
  external,
}: {
  href: string;
  children: React.ReactNode;
  className?: string;
  external?: boolean;
}) {
  const classes = cn(
    "inline-flex min-h-11 items-center justify-center gap-2 rounded-md bg-primary px-5 text-sm font-medium text-primary-foreground transition-colors hover:bg-brandDeep",
    focusRing,
    className,
  );
  return external ? (
    <a href={href} className={classes} target="_blank" rel="noopener noreferrer">
      {children}
    </a>
  ) : (
    <a href={href} className={classes}>
      {children}
    </a>
  );
}

export function SecondaryButton({
  href,
  children,
  className,
  external,
}: {
  href: string;
  children: React.ReactNode;
  className?: string;
  external?: boolean;
}) {
  const classes = cn(
    "inline-flex min-h-11 items-center justify-center gap-2 rounded-md border border-input bg-background px-5 text-sm font-medium text-foreground transition-colors hover:bg-tile",
    focusRing,
    className,
  );
  return external ? (
    <a href={href} className={classes} target="_blank" rel="noopener noreferrer">
      {children}
    </a>
  ) : (
    <a href={href} className={classes}>
      {children}
    </a>
  );
}

/** Dark code surface, used by the integration config and the JSON payloads. */
export function CodePanel({
  filename,
  children,
  className,
  badge,
}: {
  filename: string;
  children: React.ReactNode;
  className?: string;
  badge?: React.ReactNode;
}) {
  return (
    <div
      className={cn(
        // min-w-0 keeps the panel from widening its grid/flex track: without it
        // the track sizes to the longest code line and the page scrolls sideways
        // on narrow viewports instead of the <pre> scrolling on its own.
        "min-w-0 overflow-hidden rounded-lg border border-tileLine bg-vault",
        className,
      )}
    >
      <div className="flex items-center justify-between gap-3 border-b border-white/10 px-4 py-3">
        <span className="font-mono text-xs text-primary-foreground/70">
          {filename}
        </span>
        {badge}
      </div>
      <pre className="overflow-x-auto bg-transparent p-4 text-[13px] leading-6 text-primary-foreground/90">
        <code className="bg-transparent p-0 text-inherit">{children}</code>
      </pre>
    </div>
  );
}
