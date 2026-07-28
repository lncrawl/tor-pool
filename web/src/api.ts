// Types mirroring internal/server's JSON, plus the live-state hook.

export type InstanceState =
  | 'starting'
  | 'healthy'
  | 'degraded'
  | 'probation'
  | 'quarantined'
  | 'remediating';

export interface Health {
  state: InstanceState;
  failures_in_window: number;
  consecutive_failures: number;
  transport_failures: number;
  client_failures: number;
  remediations: number;
  remediation_rung: string;
}

export interface InstanceTotals {
  requests: number;
  failures: number;
  bytes_up: number;
  bytes_down: number;
  latency_ms: number;
}

export interface Instance {
  id: number;
  ready: boolean;
  running: boolean;
  bootstrap: number;
  pid: number;
  uptime_secs: number;
  sessions: number;
  socks_addr: string;
  exit_ip: string;
  exit_country: string;
  exit_nickname: string;
  // Set only while exit_ip is empty: the exit a rotation discarded, with no
  // replacement committed to yet.
  retired_exit_ip: string;
  // Whether traffic has actually left through exit_ip. When false it is inferred
  // from the circuits tor is holding, several of which it built preemptively and
  // no request may ever use.
  exit_confirmed: boolean;
  // The relay this instance is locked to, when PIN_EXIT_RELAY is on.
  pinned_exit: string;
  health: Health;
  totals: InstanceTotals;
}

export interface Session {
  key: string;
  instance: number;
  created_at: string;
  last_seen: string;
  requests: number;
  failures: number;
  bytes_up: number;
  bytes_down: number;
  active: number;
}

export interface PoolTotals {
  requests: number;
  failures: number;
  bytes_up: number;
  bytes_down: number;
}

export interface Pool {
  version: string;
  size: number;
  ready: number;
  routable: number;
  sessions: number;
  totals: PoolTotals;
  socks_port: number;
  http_port: number;
  config: {
    pool_size: number;
    session_ttl: string;
    default_session: string;
    failure_window: string;
    quarantine_failures: number;
    quarantine_consecutive: number;
    max_circuit_dirtiness: string;
  };
}

export interface Sample {
  at: string;
  requests: number;
  failures: number;
  bytes_up: number;
  bytes_down: number;
  routable: number;
  latency_p50_ms: number;
  latency_p95_ms: number;
}

export interface PoolEvent {
  seq: number;
  at: string;
  type: string;
  instance?: number;
  session?: string;
  message: string;
  detail?: string;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, init);
  if (!res.ok) {
    throw new Error((await res.text()).trim() || `${res.status} ${res.statusText}`);
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

const post = <T,>(path: string) => request<T>(path, { method: 'POST' });

export const api = {
  history: (long = false) => request<Sample[]>(`/api/stats/history${long ? '?range=long' : ''}`),
  events: (limit = 200) => request<PoolEvent[]>(`/api/events?limit=${limit}`),

  rotateInstance: (id: number) => post(`/api/instances/${id}/rotate`),
  restartInstance: (id: number, wipe = true) =>
    post(`/api/instances/${id}/restart?wipe=${wipe}`),
  quarantineInstance: (id: number) => post(`/api/instances/${id}/quarantine`),
  releaseInstance: (id: number) => post(`/api/instances/${id}/release`),
  drainInstance: (id: number) => post(`/api/instances/${id}/drain`),

  rotateAll: () => post('/api/pool/rotate'),
  resize: (size: number) =>
    request('/api/pool/resize', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ size }),
    }),

  rotateSession: (key: string, newnym = false) =>
    post(`/api/sessions/${encodeURIComponent(key)}/rotate?newnym=${newnym}`),
  dropSession: (key: string) =>
    request(`/api/sessions/${encodeURIComponent(key)}`, { method: 'DELETE' }),
  sessions: () => request<Session[]>('/api/sessions'),
};
