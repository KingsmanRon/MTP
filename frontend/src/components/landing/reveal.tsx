"use client";

import React, { useEffect, useRef, useState } from "react";
import { cn } from "@/lib/utils";

/**
 * Scroll-reveal primitives.
 *
 * The motion itself lives in globals.css (`.reveal` / `.reveal-stagger`), so
 * these components only decide *when* an element has entered the viewport and
 * flip `is-visible` on. Two shapes:
 *
 *  - <Reveal>      wraps a single block and adds one wrapper node.
 *  - <RevealGroup> *becomes* an existing container (grid, list, tbody) and
 *                  staggers its direct children, adding no node at all — so it
 *                  can replace a layout wrapper without disturbing the layout.
 *
 * Both degrade safely: without IntersectionObserver everything reveals on
 * mount, `prefers-reduced-motion` drops the transform and the fade, and a
 * <noscript> rule in the root layout keeps the content visible with JS off.
 */

const OBSERVER_OPTIONS: IntersectionObserverInit = {
  // Fire a little before the element is fully in view, so the transition is
  // already running by the time it reaches comfortable reading height. Kept a
  // small fixed band rather than a percentage: at the very bottom of the page
  // there is no more scrolling left, so a deep inset would strand anything
  // sitting inside it.
  rootMargin: "0px 0px -40px 0px",
  threshold: 0.05,
};

function useRevealed<T extends HTMLElement>() {
  const ref = useRef<T | null>(null);
  const [revealed, setRevealed] = useState(false);

  useEffect(() => {
    const node = ref.current;
    if (!node) return;
    if (typeof IntersectionObserver === "undefined") {
      setRevealed(true);
      return;
    }
    const observer = new IntersectionObserver((entries) => {
      for (const entry of entries) {
        if (entry.isIntersecting) {
          setRevealed(true);
          observer.disconnect();
        }
      }
    }, OBSERVER_OPTIONS);
    observer.observe(node);
    return () => observer.disconnect();
  }, []);

  return { ref, revealed };
}

type RevealProps = {
  children: React.ReactNode;
  className?: string;
  /** Extra delay in ms, for hand-tuned sequences outside a RevealGroup. */
  delay?: number;
  as?: React.ElementType;
};

export function Reveal({ children, className, delay = 0, as }: RevealProps) {
  const { ref, revealed } = useRevealed<HTMLElement>();
  const Component: React.ElementType = as ?? "div";

  return (
    <Component
      ref={ref}
      className={cn("reveal", revealed && "is-visible", className)}
      style={delay ? { transitionDelay: `${delay}ms` } : undefined}
    >
      {children}
    </Component>
  );
}

type RevealGroupProps = {
  children: React.ReactNode;
  className?: string;
  as?: React.ElementType;
} & Record<string, unknown>;

export function RevealGroup({
  children,
  className,
  as,
  ...rest
}: RevealGroupProps) {
  const { ref, revealed } = useRevealed<HTMLElement>();
  const Component: React.ElementType = as ?? "div";

  return (
    <Component
      ref={ref}
      className={cn("reveal-stagger", revealed && "is-visible", className)}
      {...rest}
    >
      {children}
    </Component>
  );
}
