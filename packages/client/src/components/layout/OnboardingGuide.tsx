import { useState, useEffect, useRef, useCallback } from 'react';
import { Shield, Lock, Clock, ArrowRight, X, KeyRound } from 'lucide-react';
import { useInlineDialog } from '../ui/Dialog';

const ONBOARDING_KEY = 'hvault_onboarding_completed';

interface Step {
  title: string;
  description: string;
  icon: React.ComponentType<{ className?: string }>;
}

const steps: Step[] = [
  {
    title: 'Welcome to H-Vault',
    description:
      'H-Vault is a secure password manager designed to keep your credentials, notes, and sensitive data safe. Let us walk you through the key concepts.',
    icon: Shield,
  },
  {
    title: 'Zero-Knowledge Architecture',
    description:
      'Your data is encrypted and decrypted entirely on your device. The server never sees your master password or unencrypted data. Even if the server were compromised, your vault remains secure.',
    icon: Lock,
  },
  {
    title: 'Your Master Password',
    description:
      'Your master password is the single key to your vault. It is never stored or transmitted in plain text. If you lose it, your data cannot be recovered — so choose a strong, memorable password and keep it safe.',
    icon: KeyRound,
  },
  {
    title: 'Auto-Lock Protection',
    description:
      'H-Vault automatically locks after a period of inactivity to protect your data. You can configure the timeout in Settings. You can also lock manually with Ctrl+L at any time.',
    icon: Clock,
  },
  {
    title: "You're All Set!",
    description:
      'Start by creating your first vault item. Use the "+" button or press Ctrl+N to add passwords, secure notes, cards, identities, or secrets. Use Ctrl+K to quickly search your vault.',
    icon: ArrowRight,
  },
];

export function OnboardingGuide() {
  const [visible, setVisible] = useState(false);
  const [currentStep, setCurrentStep] = useState(0);
  const dialogRef = useRef<HTMLDivElement>(null);

  const handleClose = useCallback(() => {
    localStorage.setItem(ONBOARDING_KEY, 'true');
    setVisible(false);
  }, []);

  useInlineDialog(dialogRef, visible, handleClose);

  useEffect(() => {
    const completed = localStorage.getItem(ONBOARDING_KEY);
    if (!completed) {
      setVisible(true);
    }
  }, []);

  const handleNext = () => {
    if (currentStep < steps.length - 1) {
      setCurrentStep((s) => s + 1);
    } else {
      handleClose();
    }
  };

  const handleBack = () => {
    if (currentStep > 0) {
      setCurrentStep((s) => s - 1);
    }
  };

  if (!visible) return null;

  const step = steps[currentStep] ?? steps[0];
  if (!step) return null;
  const Icon = step.icon;
  const isLast = currentStep === steps.length - 1;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50"
      onClick={(e) => {
        if (e.target === e.currentTarget) handleClose();
      }}
    >
      <div
        ref={dialogRef}
        className="w-full max-w-md rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--card))] p-6 shadow-lg"
        role="dialog"
        aria-modal="true"
        aria-label="Welcome to H-Vault"
      >
        {/* Close button */}
        <div className="flex justify-end">
          <button
            type="button"
            onClick={handleClose}
            className="rounded-md p-1 text-[hsl(var(--muted-foreground))] hover:text-[hsl(var(--foreground))] transition-colors"
            aria-label="Close onboarding"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Icon + content */}
        <div className="flex flex-col items-center text-center">
          <div className="flex h-14 w-14 items-center justify-center rounded-full bg-[hsl(var(--primary)/0.1)]">
            <Icon className="h-7 w-7 text-[hsl(var(--primary))]" />
          </div>
          <h2 className="mt-4 text-lg font-semibold text-[hsl(var(--card-foreground))]">
            {step.title}
          </h2>
          <p className="mt-2 text-sm leading-relaxed text-[hsl(var(--muted-foreground))]">
            {step.description}
          </p>
        </div>

        {/* Step indicator */}
        <div className="mt-6 flex items-center justify-center gap-1.5">
          {steps.map((_, i) => (
            <div
              key={i}
              className={`h-1.5 rounded-full transition-all ${
                i === currentStep ? 'w-6 bg-[hsl(var(--primary))]' : 'w-1.5 bg-[hsl(var(--muted))]'
              }`}
            />
          ))}
        </div>

        {/* Navigation */}
        <div className="mt-6 flex items-center justify-between">
          <button
            type="button"
            onClick={handleBack}
            disabled={currentStep === 0}
            className="rounded-md px-4 py-2 text-sm font-medium text-[hsl(var(--muted-foreground))] hover:text-[hsl(var(--foreground))] transition-colors disabled:opacity-0"
          >
            Back
          </button>
          <button
            type="button"
            onClick={handleNext}
            className="inline-flex items-center gap-2 rounded-md bg-[hsl(var(--primary))] px-4 py-2 text-sm font-medium text-[hsl(var(--primary-foreground))] hover:opacity-90 transition-opacity"
          >
            {isLast ? 'Get Started' : 'Next'}
            {!isLast && <ArrowRight className="h-4 w-4" />}
          </button>
        </div>
      </div>
    </div>
  );
}
