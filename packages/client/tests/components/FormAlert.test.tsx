/**
 * The error line every account form shows above its fields — sign-in, the
 * second factor, registration, the forgotten-password request, the reset and
 * the unlock screen — as one component.
 *
 * It is an ALERT, not decoration: a sign-in that failed has to be announced to a
 * screen reader the moment it appears, so the role is part of the contract, and
 * what is announced must be the message and nothing else. Whether it is shown at
 * all is each form's condition, pinned by that form's own suite.
 */
import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { FormAlert } from '../../src/components/ui/FormAlert';

describe('FormAlert', () => {
  it('announces exactly the message, as an alert', () => {
    render(<FormAlert message="Invalid email or password" />);
    const alert = screen.getByRole('alert');
    expect(alert.textContent).toBe('Invalid email or password');
  });

  it('keeps its icon out of what a screen reader announces', () => {
    render(<FormAlert message="Invalid email or password" />);
    const icon = screen.getByRole('alert').querySelector('svg');
    expect(icon).not.toBeNull();
    expect(icon?.getAttribute('aria-hidden')).toBe('true');
    // One alert per message: nothing else on the page claims the role.
    expect(screen.getAllByRole('alert')).toHaveLength(1);
  });
});
