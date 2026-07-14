import { describe, it, expect } from 'vitest';
import { render } from '@testing-library/react';
import { BrandLogo } from '../src/components/ui/BrandLogo';

describe('BrandLogo', () => {
  it('renders an svg shield crest with the H monogram', () => {
    const { container } = render(<BrandLogo />);
    const svg = container.querySelector('svg');
    expect(svg).toBeInTheDocument();
    expect(svg).toHaveAttribute('viewBox', '0 0 24 24');

    const paths = container.querySelectorAll('path');
    expect(paths.length).toBe(2); // shield outline + H monogram

    const monogram = Array.from(paths).find((p) => p.getAttribute('d')?.startsWith('M9.3 7.2'));
    expect(monogram).toBeTruthy();
    expect(monogram).toHaveAttribute('fill', 'currentColor'); // filled, inherits text color
  });

  it('is decorative (aria-hidden) and inherits colour via currentColor', () => {
    const { container } = render(<BrandLogo />);
    const svg = container.querySelector('svg')!;
    expect(svg).toHaveAttribute('aria-hidden', 'true');
    expect(svg).toHaveAttribute('stroke', 'currentColor');
  });

  it('applies a custom className and defaults to size 24', () => {
    const { container } = render(<BrandLogo className="h-6 w-6 text-red-500" />);
    const svg = container.querySelector('svg')!;
    expect(svg).toHaveClass('h-6', 'w-6', 'text-red-500');
    expect(svg).toHaveAttribute('width', '24');
    expect(svg).toHaveAttribute('height', '24');
  });

  it('honours a custom size prop', () => {
    const { container } = render(<BrandLogo size={40} />);
    const svg = container.querySelector('svg')!;
    expect(svg).toHaveAttribute('width', '40');
    expect(svg).toHaveAttribute('height', '40');
  });
});
