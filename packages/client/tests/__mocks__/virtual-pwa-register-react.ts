import { useState } from 'react';

export function useRegisterSW(_options?: Record<string, unknown>) {
  const [needRefresh, setNeedRefresh] = useState(false);
  const [offlineReady, setOfflineReady] = useState(false);

  return {
    needRefresh: [needRefresh, setNeedRefresh] as [
      boolean,
      React.Dispatch<React.SetStateAction<boolean>>,
    ],
    offlineReady: [offlineReady, setOfflineReady] as [
      boolean,
      React.Dispatch<React.SetStateAction<boolean>>,
    ],
    updateServiceWorker: async (_reloadPage?: boolean) => {},
  };
}
