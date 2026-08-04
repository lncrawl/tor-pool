// Types mirroring internal/server's JSON, plus the live-state hook.

export type InstanceState =
  | 'starting'
  | 'healthy'
  | 'degraded'
  | 'probation'
  | 'quarantined'
  | 'remediating';

// What a failure report said went wrong, which is what decides how heavily it
// counts. Orthogonal to who observed it: a client reports a broken socket as
// readily as the balancer does.
export type FailureKind =
  | 'rate_limited'
  | 'blocked'
  | 'captcha'
  | 'transport'
  | 'other';

export interface Health {
  state: InstanceState;
  // failures_in_window counts reports; failure_score weighs them by kind and is
  // what quarantine_score is compared against — a captcha counts for several
  // reports, a rate limit for less than one.
  failures_in_window: number;
  failure_score: number;
  quarantine_score: number;
  consecutive_failures: number;
  transport_failures: number;
  client_failures: number;
  // Only the kinds actually seen are present, so treat a missing key as zero.
  failures_by_kind: Partial<Record<FailureKind, number>>;
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
  // The exit identity has outlived EXIT_TTL and the instance is queued: it
  // rotates as soon as no session is pinned to it, so `sessions` is why it has
  // not yet.
  rotate_pending: boolean;
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

export type TokenScope = 'proxy' | 'admin';

export interface TokenInfo {
  id: string;
  name: string;
  scope: TokenScope;
  /** 'store' for an issued token, 'environment' for one set via PROXY_TOKEN. */
  source: string;
  created_at: number;
  last_used?: number;
}

/** MintedToken is the one and only response that carries a secret. */
export interface MintedToken extends TokenInfo {
  secret: string;
}

export interface LoginResult {
  token: string;
  expires: number;
  user: string;
}

/** AuthStatus is what a client can learn before it has a credential. */
export interface AuthStatus {
  /** False when the pool runs with AUTH_DISABLED and checks nothing. */
  required: boolean;
  /** The operator name the login endpoint expects, for prefilling the form. */
  user: string;
}

export interface Ticket {
  ticket: string;
  expires_in: number;
}

// The credential every request carries, and who to tell when it stops working.
//
// Module-level rather than React context because this file is not a component:
// the auth provider writes it on sign-in and clears it on sign-out, and request()
// reads it. One place attaches the header, one place notices a 401.
let credential = '';
let onUnauthorized: (() => void) | undefined;

export function setCredential(token: string, unauthorized?: () => void) {
  credential = token;
  onUnauthorized = unauthorized;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers);
  if (credential) headers.set('authorization', `Bearer ${credential}`);

  const res = await fetch(path, { ...init, headers });
  if (res.status === 401) {
    // Only a 401 signs out. A 403 means the credential is valid and merely
    // lacks the scope, and signing out on one would loop: sign in, 403, sign
    // out, sign in.
    onUnauthorized?.();
  }
  if (!res.ok) {
    throw new Error((await res.text()).trim() || `${res.status} ${res.statusText}`);
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

const post = <T,>(path: string) => request<T>(path, { method: 'POST' });

const postJSON = <T,>(path: string, body: unknown) =>
  request<T>(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });

export const api = {
  /**
   * login exchanges the operator's credentials for a JWT.
   *
   * Its own fetch rather than request(): a 401 here is the answer to the
   * question, not a signal that an existing session died, and it must not carry
   * a stale credential.
   */
  login: async (user: string, password: string): Promise<LoginResult> => {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ user, password }),
    });
    if (!res.ok) {
      throw new Error((await res.text()).trim() || `${res.status} ${res.statusText}`);
    }
    return (await res.json()) as LoginResult;
  },

  /**
   * authStatus asks whether a credential is needed at all.
   *
   * Its own fetch rather than request(), for the same reason login has one: it
   * runs before there is a session, so a 401 here must not be read as an existing
   * session dying and sign the browser out of one it has not established yet.
   */
  authStatus: async (): Promise<AuthStatus> => {
    const res = await fetch('/api/auth/status');
    if (!res.ok) {
      throw new Error((await res.text()).trim() || `${res.status} ${res.statusText}`);
    }
    return (await res.json()) as AuthStatus;
  },

  /** ticket mints a short-lived credential for the SSE stream. */
  ticket: () => post<Ticket>('/api/auth/ticket'),

  tokens: () => request<TokenInfo[]>('/api/tokens'),
  mintToken: (name: string, scope: TokenScope) =>
    postJSON<MintedToken>('/api/tokens', { name, scope }),
  revokeToken: (id: string) =>
    request(`/api/tokens/${encodeURIComponent(id)}`, { method: 'DELETE' }),

  history: (long = false) => request<Sample[]>(`/api/stats/history${long ? '?range=long' : ''}`),
  events: (limit = 200) => request<PoolEvent[]>(`/api/events?limit=${limit}`),

  rotateInstance: (id: number) => post(`/api/instances/${id}/rotate`),
  restartInstance: (id: number, wipe = true) =>
    post(`/api/instances/${id}/restart?wipe=${wipe}`),
  quarantineInstance: (id: number) => post(`/api/instances/${id}/quarantine`),
  releaseInstance: (id: number) => post(`/api/instances/${id}/release`),
  drainInstance: (id: number) => post(`/api/instances/${id}/drain`),

  rotateAll: () => post('/api/pool/rotate'),
  resize: (size: number) => postJSON('/api/pool/resize', { size }),

  rotateSession: (key: string, newnym = false) =>
    post(`/api/sessions/${encodeURIComponent(key)}/rotate?newnym=${newnym}`),
  dropSession: (key: string) =>
    request(`/api/sessions/${encodeURIComponent(key)}`, { method: 'DELETE' }),
  sessions: () => request<Session[]>('/api/sessions'),
};
