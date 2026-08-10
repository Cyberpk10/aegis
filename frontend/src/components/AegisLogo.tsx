interface AegisLogoProps {
  className?: string;
}

// Same chevron/"A" mark and gradient as the aegis-site marketing project's
// public/brand/aegis-icon.svg, reused here for product/marketing brand consistency.
export default function AegisLogo({ className }: AegisLogoProps) {
  return (
    <svg
      viewBox="0 0 64 64"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
      role="img"
      aria-label="Aegis"
    >
      <defs>
        <linearGradient id="aegisGrad" x1="8" y1="56" x2="56" y2="8" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#2F6BFF" />
          <stop offset="1" stopColor="#8B5CF6" />
        </linearGradient>
      </defs>
      <path
        fillRule="evenodd"
        clipRule="evenodd"
        d="M32 8L56 56H44L32 30L20 56H8L32 8ZM32 30L38 43H26L32 30Z"
        fill="url(#aegisGrad)"
      />
    </svg>
  );
}
