import { Link } from 'react-router-dom';
import { ShieldOff } from 'lucide-react';
import { useAuthStore } from '../stores/authStore';

export default function NotFoundPage() {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);

  return (
    <div className="flex min-h-screen flex-col items-center justify-center space-y-4 bg-[hsl(var(--background))] px-4 text-center">
      <div className="flex h-20 w-20 items-center justify-center rounded-full bg-[hsl(var(--muted))]">
        <ShieldOff className="h-10 w-10 text-[hsl(var(--muted-foreground))]" />
      </div>
      <h1 className="text-6xl font-bold text-[hsl(var(--primary))]">404</h1>
      <h2 className="text-2xl font-semibold text-[hsl(var(--foreground))]">Page Not Found</h2>
      <p className="max-w-sm text-[hsl(var(--muted-foreground))]">
        The page you are looking for does not exist or has been moved.
      </p>
      <Link
        to={isAuthenticated ? '/vault' : '/login'}
        className="rounded-md bg-[hsl(var(--primary))] px-4 py-2 text-sm font-medium text-[hsl(var(--primary-foreground))] hover:opacity-90 transition-opacity focus:outline-none focus:ring-2 focus:ring-[hsl(var(--ring))] focus:ring-offset-2"
      >
        {isAuthenticated ? 'Back to Vault' : 'Back to Login'}
      </Link>
    </div>
  );
}
