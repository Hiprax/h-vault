import { useEffect, useState } from 'react';

/** How often the countdown is redrawn. */
const TICK_MS = 1_000;

/**
 * A pause the server asked for, counted down: "Waiting 42 s, as the server
 * asked." Hidden once the time has passed, so a line from a wait that already
 * ended never sits under a job that has moved on.
 *
 * Render it keyed by `until`, so each wait starts from a fresh clock reading.
 *
 * Only a server-requested wait is shown. A job also waits on a server it cannot
 * reach, and says so when it gives up; counting that down would promise a
 * resumption nobody can promise.
 */
export function WaitNotice({ until }: { until: number }) {
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), TICK_MS);
    return () => clearInterval(timer);
  }, []);

  if (until <= now) return null;
  const seconds = Math.ceil((until - now) / 1000);
  return (
    <p className="text-xs text-[hsl(var(--muted-foreground))]">
      {`Waiting ${String(seconds)} s, as the server asked. It carries on by itself.`}
    </p>
  );
}
