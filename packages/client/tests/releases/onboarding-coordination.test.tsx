/**
 * The first-run guide tells the shell while it is on screen, which is what makes
 * "What's new" wait for it instead of opening on top of it.
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { OnboardingGuide } from '../../src/components/layout/OnboardingGuide';
import { useUIStore } from '../../src/stores/uiStore';

beforeEach(() => {
  localStorage.clear();
  useUIStore.setState({ onboardingActive: false });
});

afterEach(cleanup);

describe('OnboardingGuide and the release notes', () => {
  it('is reported active while it is showing, and inactive once closed', () => {
    render(<OnboardingGuide />);
    expect(screen.getByRole('dialog', { name: 'Welcome to H-Vault' })).toBeInTheDocument();
    expect(useUIStore.getState().onboardingActive).toBe(true);
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(useUIStore.getState().onboardingActive).toBe(false);
  });

  it('is never reported active once the guide was completed', () => {
    localStorage.setItem('hvault_onboarding_completed', 'true');
    render(<OnboardingGuide />);
    expect(useUIStore.getState().onboardingActive).toBe(false);
  });

  it('is reported inactive when the shell unmounts it mid-way', () => {
    const view = render(<OnboardingGuide />);
    expect(useUIStore.getState().onboardingActive).toBe(true);
    view.unmount();
    expect(useUIStore.getState().onboardingActive).toBe(false);
  });
});
