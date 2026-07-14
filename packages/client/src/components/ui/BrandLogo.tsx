import type { SVGProps } from 'react';

/**
 * H-Vault brand mark.
 *
 * The shield crest matches the lucide `Shield` outline the product already uses
 * (same path, stroke weight, and line caps), with a solid "H" monogram
 * optically centred in the shield body. Colour is inherited from
 * `currentColor`, so it honours Tailwind `text-*` utilities exactly like a
 * lucide icon and is a drop-in replacement for `<Shield className=... />`
 * wherever the *brand logo* (not a functional shield icon) is rendered.
 */

// lucide `Shield` outline (v1.x) — kept identical so the crest looks unchanged.
const SHIELD_PATH =
  'M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z';

// Solid "H" monogram, optically centred at (12, 11) within the shield body.
const MONOGRAM_PATH = 'M9.3 7.2H11.2V10.05H12.8V7.2H14.7V14.8H12.8V11.95H11.2V14.8H9.3Z';

export interface BrandLogoProps extends SVGProps<SVGSVGElement> {
  /** Icon size in px applied to width & height. Overridable via `className`. */
  size?: number | string;
}

export function BrandLogo({ size = 24, className, ...props }: BrandLogoProps) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={2}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      className={className}
      {...props}
    >
      <path d={SHIELD_PATH} />
      <path d={MONOGRAM_PATH} fill="currentColor" stroke="none" />
    </svg>
  );
}

export default BrandLogo;
