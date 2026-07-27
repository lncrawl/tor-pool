import {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react';

import type { Instance, Pool, PoolEvent, Sample } from './api';

// historyPoints is how many samples the charts keep client-side.
//
// The server retains its own window; this only bounds what one open tab holds
// so a dashboard left running overnight does not grow without limit.
const historyPoints = 300;

// eventBufferSize bounds the in-tab event list for the same reason.
const eventBufferSize = 500;

interface StreamFrame {
  pool: Pool;
  instances: Instance[];
  sample: Sample;
}

interface LiveState {
  pool?: Pool;
  instances: Instance[];
  history: Sample[];
  events: PoolEvent[];
  connected: boolean;
}

const LiveContext = createContext<LiveState>({
  instances: [],
  history: [],
  events: [],
  connected: false,
});

/** useLive returns the current pool state, updated by the SSE stream. */
export const useLive = () => useContext(LiveContext);

/**
 * LiveProvider holds the single EventSource for the whole app.
 *
 * One subscription, not one per view: each connection costs the server a
 * goroutine and a ticker, and every view wants the same snapshot anyway.
 */
export function LiveProvider({ children }: { children: ReactNode }) {
  const [pool, setPool] = useState<Pool>();
  const [instances, setInstances] = useState<Instance[]>([]);
  const [history, setHistory] = useState<Sample[]>([]);
  const [events, setEvents] = useState<PoolEvent[]>([]);
  const [connected, setConnected] = useState(false);

  // The newest sample's timestamp, used to drop duplicate ticks without making
  // the effect depend on history (which would resubscribe on every frame).
  const lastSampleAt = useRef<string>('');

  useEffect(() => {
    // Backfill the charts so they are not empty for the first minute.
    let cancelled = false;
    fetch('/api/stats/history')
      .then((r) => (r.ok ? r.json() : []))
      .then((samples: Sample[]) => {
        if (!cancelled && samples.length) {
          setHistory(samples.slice(-historyPoints));
          lastSampleAt.current = samples[samples.length - 1]?.at ?? '';
        }
      })
      .catch(() => undefined);

    fetch('/api/events?limit=200')
      .then((r) => (r.ok ? r.json() : []))
      .then((initial: PoolEvent[]) => {
        if (!cancelled) setEvents(initial);
      })
      .catch(() => undefined);

    const source = new EventSource('/api/stream');

    source.addEventListener('open', () => setConnected(true));

    source.addEventListener('state', (e) => {
      const frame: StreamFrame = JSON.parse((e as MessageEvent).data);
      setConnected(true);
      setPool(frame.pool);
      setInstances(frame.instances);

      // Buckets arrive repeatedly while one is still filling; replace the
      // trailing point rather than appending a duplicate timestamp.
      setHistory((prev) => {
        const next =
          prev.length && prev[prev.length - 1].at === frame.sample.at
            ? [...prev.slice(0, -1), frame.sample]
            : [...prev, frame.sample];
        return next.slice(-historyPoints);
      });
      lastSampleAt.current = frame.sample.at;
    });

    source.addEventListener('event', (e) => {
      const event: PoolEvent = JSON.parse((e as MessageEvent).data);
      setEvents((prev) => [event, ...prev].slice(0, eventBufferSize));
    });

    // EventSource reconnects on its own; this only reflects the gap in the UI.
    source.addEventListener('error', () => setConnected(false));

    return () => {
      cancelled = true;
      source.close();
    };
  }, []);

  const value = useMemo<LiveState>(
    () => ({ pool, instances, history, events, connected }),
    [pool, instances, history, events, connected],
  );

  return <LiveContext.Provider value={value}>{children}</LiveContext.Provider>;
}
