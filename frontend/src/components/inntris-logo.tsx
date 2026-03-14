interface InntrisLogoProps {
  className?: string;
  glowColor?: string;
  strokeColor?: string;
}

export function InntrisLogo({
  className = "h-6 w-6",
  glowColor = "#28C281",
  strokeColor = "white",
}: InntrisLogoProps) {
  return (
    <svg
      viewBox="0 0 120 120"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
    >
      <defs>
        <radialGradient id="nn-glow" cx="50%" cy="50%" r="35%">
          <stop offset="0%" stopColor={glowColor} stopOpacity="0.6" />
          <stop offset="60%" stopColor={glowColor} stopOpacity="0.15" />
          <stop offset="100%" stopColor={glowColor} stopOpacity="0" />
        </radialGradient>
      </defs>
      <circle cx="60" cy="60" r="42" fill="url(#nn-glow)" />
      {/* Left N */}
      <path
        d="M24 96V24h10l26 48V24"
        stroke={strokeColor}
        strokeWidth="7"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      {/* Right N */}
      <path
        d="M60 96V24h10l26 48V24V96"
        stroke={strokeColor}
        strokeWidth="7"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}
