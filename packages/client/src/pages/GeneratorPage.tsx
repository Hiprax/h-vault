import { Key } from 'lucide-react';
import { PasswordGenerator } from '../components/vault/PasswordGenerator';

export default function GeneratorPage() {
  return (
    <div className="mx-auto max-w-xl space-y-6">
      <h1 className="flex items-center gap-2 text-2xl font-bold text-[hsl(var(--foreground))]">
        <Key className="h-6 w-6" />
        Password Generator
      </h1>
      <PasswordGenerator />
    </div>
  );
}
