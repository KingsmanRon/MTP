interface InntrisLogoProps {
  className?: string;
}

export function InntrisLogo({ className = "h-6 w-6" }: InntrisLogoProps) {
  return (
    // eslint-disable-next-line @next/next/no-img-element
    <img
      src="/logo.svg"
      alt="Inntris"
      className={className}
    />
  );
}
