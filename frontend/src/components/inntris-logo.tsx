import { cn } from "@/lib/utils";

interface InntrisLogoProps {
  className?: string;
}

export function InntrisLogo({ className = "h-6 w-6" }: InntrisLogoProps) {
  return (
    // The artwork carries its own dark plate to the edge of its canvas, so
    // inside a rounded container the mark reads as a hard-cornered square.
    // Round it here rather than at each call site, and use a percentage so the
    // curve stays proportional across the h-5/h-6/h-8 sizes in use.
    // eslint-disable-next-line @next/next/no-img-element
    <img
      src="/logo.svg"
      alt="Inntris"
      className={cn("rounded-[22%]", className)}
    />
  );
}
