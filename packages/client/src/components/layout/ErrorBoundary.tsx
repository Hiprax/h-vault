import { Component } from 'react';
import type { ErrorInfo, ReactNode } from 'react';
import { Shield } from 'lucide-react';
import { logger } from '../../lib/logger';

interface ErrorBoundaryProps {
  children: ReactNode;
  /**
   * Optional compact fallback rendered in place of the default full-screen
   * error card. Use it for boundaries that wrap a sub-section of a page so a
   * localized render failure degrades that section only, instead of taking
   * over the whole viewport and hiding the surrounding controls.
   */
  fallback?: ReactNode;
}

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo): void {
    logger.error('[ErrorBoundary] Uncaught error:', error, errorInfo);
  }

  handleReload = () => {
    window.location.reload();
  };

  render() {
    if (this.state.hasError) {
      if (this.props.fallback !== undefined) {
        return this.props.fallback;
      }
      return (
        <div className="flex min-h-screen items-center justify-center bg-[hsl(var(--background))]">
          <div className="w-full max-w-md space-y-6 rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--card))] p-8 shadow-lg">
            <div className="flex flex-col items-center space-y-3">
              <div className="flex h-14 w-14 items-center justify-center rounded-full bg-[hsl(var(--destructive)/0.1)]">
                <Shield className="h-7 w-7 text-[hsl(var(--destructive))]" />
              </div>
              <h2 className="text-xl font-semibold text-[hsl(var(--card-foreground))]">
                Something went wrong
              </h2>
              <p className="text-center text-sm text-[hsl(var(--muted-foreground))]">
                An unexpected error occurred. Your data is safe. Please reload the page to continue.
              </p>
            </div>

            {this.state.error && (
              <div className="rounded-md bg-[hsl(var(--muted))] p-3">
                <p className="break-all font-mono text-xs text-[hsl(var(--muted-foreground))]">
                  {import.meta.env.DEV ? this.state.error.message : 'An unexpected error occurred'}
                </p>
              </div>
            )}

            <button
              type="button"
              onClick={this.handleReload}
              className="flex w-full items-center justify-center gap-2 rounded-md bg-[hsl(var(--primary))] px-4 py-2 text-sm font-medium text-[hsl(var(--primary-foreground))] hover:opacity-90 transition-opacity focus:outline-none focus:ring-2 focus:ring-[hsl(var(--ring))] focus:ring-offset-2"
            >
              Reload
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
