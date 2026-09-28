import { cn } from '../../lib/utils';

/** Sixty ticks round the ring, every fifth longer, like a combination dial. */
const TICKS = Array.from({ length: 60 }, (_, index) => {
  const major = index % 5 === 0;
  const angle = (index * 6 * Math.PI) / 180;
  const inner = major ? 45 : 49;
  const outer = 53;
  const at = (radius: number, axis: 'x' | 'y') =>
    Math.round((60 + radius * (axis === 'x' ? Math.sin(angle) : -Math.cos(angle))) * 100) / 100;
  return {
    index,
    major,
    x1: at(inner, 'x'),
    y1: at(inner, 'y'),
    x2: at(outer, 'x'),
    y2: at(outer, 'y'),
  };
});

interface VaultDialProps {
  version: string;
}

/**
 * The version a release-notes view is about, set in the centre of a vault dial.
 *
 * Decorative: the version is also in the dialog title, so the whole figure is
 * hidden from assistive technology. The ring turns once into place when it
 * mounts and the numerals fade in (`.release-dial-ring`, `.release-dial-numerals`
 * in `styles/globals.css`, both static under reduced motion). The index notch at
 * the top does not turn, so the ring visibly settles against it.
 */
export function VaultDial({ version }: VaultDialProps) {
  return (
    <div
      aria-hidden="true"
      data-testid="vault-dial"
      className="relative flex h-24 w-24 shrink-0 items-center justify-center sm:h-28 sm:w-28"
    >
      <div className="release-hero-glow pointer-events-none absolute -inset-6" />
      <svg
        viewBox="0 0 120 120"
        className="release-dial-ring absolute inset-0 h-full w-full text-[hsl(var(--primary))]"
      >
        <circle cx="60" cy="60" r="56" fill="none" stroke="currentColor" strokeOpacity="0.25" />
        {TICKS.map((tick) => (
          <line
            key={tick.index}
            x1={tick.x1}
            y1={tick.y1}
            x2={tick.x2}
            y2={tick.y2}
            stroke="currentColor"
            strokeLinecap="round"
            strokeOpacity={tick.major ? 0.9 : 0.35}
            strokeWidth={tick.major ? 2 : 1}
          />
        ))}
        <circle
          cx="60"
          cy="60"
          r="40"
          fill="hsl(var(--background))"
          stroke="currentColor"
          strokeOpacity="0.4"
        />
      </svg>
      <svg
        viewBox="0 0 120 120"
        className="absolute inset-0 h-full w-full text-[hsl(var(--primary))]"
      >
        <path d="M60 1 L64.5 8.5 L55.5 8.5 Z" fill="currentColor" />
      </svg>
      <span
        className={cn(
          'release-dial-numerals relative font-semibold tabular-nums tracking-tight text-[hsl(var(--foreground))]',
          version.length > 7 ? 'text-sm' : 'text-lg',
        )}
      >
        {version}
      </span>
    </div>
  );
}
