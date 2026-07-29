import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import { Alert, Button, Card, Flex, Form, Input, Spin, Typography } from 'antd';

import { api, setCredential } from './api';
import type { AuthStatus } from './api';

// Where the session lives between reloads.
//
// localStorage rather than sessionStorage so a reload or a second tab does not
// mean signing in again. The trade is XSS exposure, which the short JWT lifetime
// bounds; the credential is deliberately never a cookie, because a header-only
// credential makes every mutating endpoint immune to cross-site requests.
const tokenKey = 'torpool.token';
const userKey = 'torpool.user';

interface AuthState {
  token: string;
  user: string;
  /**
   * Whether the pool checks credentials at all. False under AUTH_DISABLED, where
   * there is no session to end and so nothing for a sign-out control to do.
   */
  required: boolean;
  signOut: () => void;
}

const AuthContext = createContext<AuthState>({
  token: '',
  user: '',
  required: true,
  signOut: () => undefined,
});

/** useAuth returns the current session. */
export const useAuth = () => useContext(AuthContext);

/**
 * AuthProvider gates the app on a session and keeps api.ts supplied with it.
 *
 * It sits above LiveProvider on purpose: the stream must not be opened before
 * there is a credential to open it with — nor before we know whether one is
 * needed, which is why nothing renders until `/api/auth/status` has answered.
 */
export function AuthProvider({ children }: { children: ReactNode }) {
  const [token, setToken] = useState(() => localStorage.getItem(tokenKey) ?? '');
  const [user, setUser] = useState(() => localStorage.getItem(userKey) ?? '');
  const [expired, setExpired] = useState(false);
  const [status, setStatus] = useState<AuthStatus | undefined>();

  // Asked before anything renders, and asked even when a stored session exists:
  // the answer decides whether a sign-out control means anything, and a stale
  // token from before AUTH_DISABLED was set would otherwise hide that.
  useEffect(() => {
    let live = true;
    const settle = (s: AuthStatus) => {
      if (live) setStatus(s);
    };
    api.authStatus().then(settle, () =>
      // An unreachable or erroring endpoint is treated as "a credential is
      // required". That is the safe direction to be wrong in, and the sign-in
      // screen reports the real problem when the login attempt hits it too.
      settle({ required: true, user: 'admin' }),
    );
    return () => {
      live = false;
    };
  }, []);

  const signOut = useCallback(() => {
    // There is nothing to revoke server-side: a JWT is valid until it expires,
    // so signing out drops this browser's copy and the short lifetime does the
    // rest.
    localStorage.removeItem(tokenKey);
    localStorage.removeItem(userKey);
    setToken('');
    setUser('');
  }, []);

  const sessionLost = useCallback(() => {
    setExpired(true);
    signOut();
  }, [signOut]);

  // Attached during render rather than in an effect, and that is load-bearing.
  //
  // React runs child effects before parent ones, so LiveProvider's first requests
  // would go out before an effect here could attach the credential. They would
  // 401, and by the time those responses landed the sign-out handler *would* be
  // registered — so a stored session signed itself out on every single page load.
  // Writing to a module variable during render is idempotent and safe; waiting
  // for an effect is not.
  setCredential(token, sessionLost);

  const signIn = useCallback(async (name: string, password: string) => {
    const result = await api.login(name, password);
    localStorage.setItem(tokenKey, result.token);
    localStorage.setItem(userKey, result.user);
    setExpired(false);
    setCredential(result.token);
    setToken(result.token);
    setUser(result.user);
  }, []);

  const required = status?.required ?? true;
  const value = useMemo<AuthState>(
    () => ({ token, user, required, signOut }),
    [token, user, required, signOut],
  );

  if (!status) {
    // One round trip, against the same origin. Rendering the sign-in screen
    // meanwhile would flash a form at an operator who never has to fill it in.
    return (
      <Flex align="center" justify="center" style={{ minHeight: '100vh' }}>
        <Spin size="large" />
      </Flex>
    );
  }
  if (required && !token) {
    return <SignIn onSubmit={signIn} expired={expired} defaultUser={status.user} />;
  }
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

function SignIn({
  onSubmit,
  expired,
  defaultUser,
}: {
  onSubmit: (user: string, password: string) => Promise<void>;
  expired: boolean;
  defaultUser: string;
}) {
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = async ({ user, password }: { user: string; password: string }) => {
    setBusy(true);
    setError('');
    try {
      await onSubmit(user, password);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Flex align="center" justify="center" style={{ minHeight: '100vh', padding: 16 }}>
      <Card style={{ width: '100%', maxWidth: 380 }}>
        <Flex vertical gap={16}>
          <Flex vertical gap={4}>
            <Typography.Title level={4} style={{ margin: 0 }}>
              tor-pool
            </Typography.Title>
            <Typography.Text type="secondary">
              Sign in to manage the pool.
            </Typography.Text>
          </Flex>

          {expired && (
            <Alert type="warning" showIcon message="Your session expired. Sign in again." />
          )}
          {/* The server answers a wrong username and a wrong password
              identically, so this only ever says that something was wrong. */}
          {error && <Alert type="error" showIcon message={error} />}

          <Form layout="vertical" requiredMark={false} onFinish={submit} disabled={busy}>
            <Form.Item
              name="user"
              label="User"
              initialValue={defaultUser}
              rules={[{ required: true, message: 'Required' }]}
            >
              <Input autoComplete="username" autoFocus />
            </Form.Item>
            <Form.Item
              name="password"
              label="Password"
              initialValue="admin"
              rules={[{ required: true, message: 'Required' }]}
            >
              <Input.Password autoComplete="current-password" />
            </Form.Item>
            <Button type="primary" htmlType="submit" block loading={busy}>
              Sign in
            </Button>
          </Form>

          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            On a first run the password is generated and printed to the container
            log. Set <Typography.Text code>ADMIN_PASSWORD</Typography.Text> to choose
            your own.
          </Typography.Text>
        </Flex>
      </Card>
    </Flex>
  );
}
