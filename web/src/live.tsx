import {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react';

import { api } from './api';
import type { Instance, Pool, PoolEvent, Sample } from './api';
import { useAuth } from './auth';

// historyPoints is how many samples the charts keep client-side.
//
// The server retains its own window; this only bounds what one open tab holds
// so a dashboard left running overnight does not grow without limit.
const historyPoints = 300;

// eventBufferSize bounds the in-tab event list for the same reason.
const eventBufferSize = 500;

// Reconnect backoff bounds, in milliseconds.
const retryFloor = 500;
const retryCeiling = 30_000;

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
  const { token, required } = useAuth();
  const [pool, setPool] = useState<Pool>();
  const [instances, setInstances] = useState<Instance[]>([]);
  const [history, setHistory] = useState<Sample[]>([]);
  const [events, setEvents] = useState<PoolEvent[]>([]);
  const [connected, setConnected] = useState(false);

  // The newest sample's timestamp, used to drop duplicate ticks without making
  // the effect depend on history (which would resubscribe on every frame).
  const lastSampleAt = useRef<string>('');

  useEffect(() => {
    // "Nothing to connect with", not "no token". Under AUTH_DISABLED there is no
    // token and none is needed, and gating on the token alone left the stream
    // unopened: no pool, no history, no events, and a permanent "reconnecting"
    // badge over a dashboard that was in fact reachable the whole time.
    if (required && !token) return;

    let closed = false;
    let source: EventSource | undefined;
    let timer: number | undefined;
    let attempt = 0;

    // Backfill the charts so they are not empty for the first minute. Through
    // api so they carry the credential and share the sign-out handling.
    api
      .history()
      .then((samples) => {
        if (!closed && samples.length) {
          setHistory(samples.slice(-historyPoints));
          lastSampleAt.current = samples[samples.length - 1]?.at ?? '';
        }
      })
      .catch(() => undefined);

    api
      .events(200)
      .then((initial) => {
        if (!closed) setEvents(initial);
      })
      .catch(() => undefined);

    const onState = (e: Event) => {
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
    };

    const onEvent = (e: Event) => {
      const event: PoolEvent = JSON.parse((e as MessageEvent).data);
      setEvents((prev) => [event, ...prev].slice(0, eventBufferSize));
    };

    const retryLater = () => {
      if (closed) return;
      const delay = Math.min(retryCeiling, retryFloor * 2 ** attempt);
      attempt += 1;
      timer = window.setTimeout(() => void open(), delay);
    };

    /**
     * open mints a fresh ticket and subscribes.
     *
     * EventSource cannot send an Authorization header, so the credential travels
     * in the URL as a ticket that expires in about a minute. That is exactly why
     * the browser's own reconnection cannot be relied on: it retries the *same
     * URL*, so after the first blip it would spin forever against a dead ticket
     * and the dashboard would sit on "reconnecting" until someone reloaded the
     * page. Owning the loop means each attempt gets a new ticket.
     */
    const open = async () => {
      if (closed) return;

      let ticket: string;
      try {
        ticket = (await api.ticket()).ticket;
      } catch {
        // A 401 here has already signed the session out through api.ts, which
        // unmounts this provider. Anything else is transient, so back off.
        retryLater();
        return;
      }
      if (closed) return;

      const next = new EventSource(`/api/stream?ticket=${encodeURIComponent(ticket)}`);
      source = next;
      next.addEventListener('open', () => {
        attempt = 0;
        setConnected(true);
      });
      next.addEventListener('state', onState);
      next.addEventListener('event', onEvent);
      next.addEventListener('error', () => {
        setConnected(false);
        next.close();
        if (source === next) source = undefined;
        retryLater();
      });
    };

    void open();

    return () => {
      closed = true;
      if (timer !== undefined) window.clearTimeout(timer);
      source?.close();
    };
  }, [token, required]);

  const value = useMemo<LiveState>(
    () => ({ pool, instances, history, events, connected }),
    [pool, instances, history, events, connected],
  );

  return <LiveContext.Provider value={value}>{children}</LiveContext.Provider>;
}
