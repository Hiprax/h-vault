import { Suspense, lazy } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { ProtectedRoute } from './components/layout/ProtectedRoute';
import { PublicOnlyRoute } from './components/layout/PublicOnlyRoute';
import { AppLayout } from './components/layout/AppLayout';
import { ErrorBoundary } from './components/layout/ErrorBoundary';
import { ToastProvider } from './components/ui/Toast';
import { ReloadPrompt } from './components/layout/ReloadPrompt';
import { useFavicon } from './hooks/useFavicon';

// Lazy-loaded page components
const LoginPage = lazy(() => import('./pages/LoginPage'));
const RegisterPage = lazy(() => import('./pages/RegisterPage'));
const VaultPage = lazy(() => import('./pages/VaultPage'));
const VaultItemPage = lazy(() => import('./pages/VaultItemPage'));
const SettingsPage = lazy(() => import('./pages/SettingsPage'));
const BackupSettingsPage = lazy(() => import('./pages/BackupSettingsPage'));
const SessionsPage = lazy(() => import('./pages/SessionsPage'));
const AuditLogPage = lazy(() => import('./pages/AuditLogPage'));
const ForgotPasswordPage = lazy(() => import('./pages/ForgotPasswordPage'));
const GeneratorPage = lazy(() => import('./pages/GeneratorPage'));
const FileEncryptionPage = lazy(() => import('./pages/FileEncryptionPage'));
const VaultHealthPage = lazy(() => import('./pages/VaultHealthPage'));
const VerifyEmailPage = lazy(() => import('./pages/VerifyEmailPage'));
const ResetPasswordPage = lazy(() => import('./pages/ResetPasswordPage'));
const UnlockAccountPage = lazy(() => import('./pages/UnlockAccountPage'));
const NotFoundPage = lazy(() => import('./pages/NotFoundPage'));

function LoadingSpinner() {
  return (
    <div className="flex h-screen w-full items-center justify-center bg-[hsl(var(--background))]">
      <div className="flex flex-col items-center gap-3">
        <div className="h-8 w-8 animate-spin rounded-full border-4 border-[hsl(var(--muted))] border-t-[hsl(var(--primary))]" />
        <p className="text-sm text-[hsl(var(--muted-foreground))]">Loading...</p>
      </div>
    </div>
  );
}

export function App() {
  // Keep the browser-tab favicon in sync with the vault state (green/open when
  // unlocked, red/closed when locked or logged out).
  useFavicon();

  return (
    <ErrorBoundary>
      <BrowserRouter>
        <ToastProvider>
          <Suspense fallback={<LoadingSpinner />}>
            <Routes>
              {/* Public routes - redirect to vault if already authenticated */}
              <Route element={<PublicOnlyRoute />}>
                <Route path="/login" element={<LoginPage />} />
                <Route path="/register" element={<RegisterPage />} />
                <Route path="/forgot-password" element={<ForgotPasswordPage />} />
              </Route>

              {/* Protected routes with layout */}
              <Route element={<ProtectedRoute />}>
                <Route element={<AppLayout />}>
                  <Route path="/" element={<Navigate to="/vault" replace />} />
                  <Route path="/vault" element={<VaultPage />} />
                  <Route path="/generator" element={<GeneratorPage />} />
                  <Route path="/tools/file-encryption" element={<FileEncryptionPage />} />
                  <Route path="/vault/health" element={<VaultHealthPage />} />
                  <Route path="/vault/:id" element={<VaultItemPage />} />
                  <Route path="/settings" element={<SettingsPage />} />
                  <Route path="/settings/backup" element={<BackupSettingsPage />} />
                  <Route path="/settings/sessions" element={<SessionsPage />} />
                  <Route path="/settings/audit" element={<AuditLogPage />} />
                </Route>
              </Route>

              {/* Token-based routes from email links (no auth required) */}
              <Route path="/verify-email" element={<VerifyEmailPage />} />
              <Route path="/reset-password" element={<ResetPasswordPage />} />
              <Route path="/unlock-account" element={<UnlockAccountPage />} />

              {/* Catch-all */}
              <Route path="*" element={<NotFoundPage />} />
            </Routes>
          </Suspense>
        </ToastProvider>
      </BrowserRouter>
      <ReloadPrompt />
    </ErrorBoundary>
  );
}
