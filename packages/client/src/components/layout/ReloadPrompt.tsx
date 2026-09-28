import { useEffect, useRef } from 'react';
import { useRegisterSW } from 'virtual:pwa-register/react';
import { RefreshCw } from 'lucide-react';
import { rememberServiceWorkerRegistration } from '../../lib/serviceWorkerUpdate';
import { useAuthStore } from '../../stores/authStore';
import { useReleaseStore } from '../../stores/releaseStore';

export function ReloadPrompt() {
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  // Set when the server's version changed while this page was open; it names the
  // version the waiting build belongs to.
  const serverUpdatedTo = useReleaseStore((state) => state.serverUpdatedTo);

  const {
    needRefresh: [needRefresh, setNeedRefresh],
    updateServiceWorker,
  } = useRegisterSW({
    onRegisteredSW(_swUrl, registration) {
      if (registration) {
        // Lets the release store ask for the new build as soon as it sees the
        // server's version change, instead of waiting for the hourly check.
        rememberServiceWorkerRegistration(registration);
        // Check for updates every hour
        intervalRef.current = setInterval(
          () => {
            void registration.update();
          },
          60 * 60 * 1000,
        );
      }
    },
  });

  useEffect(() => {
    return () => {
      if (intervalRef.current !== null) {
        clearInterval(intervalRef.current);
      }
    };
  }, []);

  // A waiting build was found: re-read the server's version so the prompt can
  // name it. Only for an unlocked session; otherwise the generic text stands.
  useEffect(() => {
    if (!needRefresh) return;
    const { user, isLocked } = useAuthStore.getState();
    if (user && !isLocked) void useReleaseStore.getState().loadStatus(user.userId);
  }, [needRefresh]);

  if (!needRefresh) return null;

  return (
    <div
      role="alert"
      className="fixed bottom-4 left-4 z-[100] flex items-center gap-3 rounded-lg border border-blue-500/30 bg-blue-50 p-4 shadow-lg dark:bg-blue-950"
    >
      <RefreshCw className="h-5 w-5 shrink-0 text-blue-600 dark:text-blue-400" />
      <div className="flex-1">
        <p className="text-sm font-semibold text-blue-900 dark:text-blue-100">Update available</p>
        <p className="text-sm text-blue-800 dark:text-blue-200">
          {serverUpdatedTo === null
            ? 'A new version of H-Vault is ready.'
            : `H-Vault ${serverUpdatedTo} is ready. Update to start using it.`}
        </p>
      </div>
      <div className="flex gap-2">
        <button
          type="button"
          onClick={() => setNeedRefresh(false)}
          className="rounded-md px-3 py-1.5 text-sm text-blue-700 hover:bg-blue-100 dark:text-blue-300 dark:hover:bg-blue-900"
        >
          Dismiss
        </button>
        <button
          type="button"
          onClick={() => void updateServiceWorker(true)}
          className="rounded-md bg-blue-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-blue-700"
        >
          Update
        </button>
      </div>
    </div>
  );
}
