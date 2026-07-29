import { useEffect, useState } from 'react';
import {
  Alert,
  Badge,
  Button,
  ConfigProvider,
  Flex,
  Layout,
  Switch,
  Tabs,
  Tag,
  Tooltip,
  Typography,
  theme,
} from 'antd';

import { AuthProvider, useAuth } from './auth';
import { LiveProvider, useLive } from './live';
import { surfaces } from './theme';
import { Events } from './views/Events';
import { Instances } from './views/Instances';
import { Overview } from './views/Overview';
import { Sessions } from './views/Sessions';
import { Tokens } from './views/Tokens';

const themeKey = 'torpool.theme';

export default function App() {
  const [dark, setDark] = useState(() => {
    const saved = localStorage.getItem(themeKey);
    if (saved) return saved === 'dark';
    return window.matchMedia?.('(prefers-color-scheme: dark)').matches ?? false;
  });

  useEffect(() => {
    localStorage.setItem(themeKey, dark ? 'dark' : 'light');
    // Stamp the root so the surface behind AntD matches the chart surface.
    document.documentElement.dataset.theme = dark ? 'dark' : 'light';
    document.body.style.background = dark ? surfaces.dark : surfaces.light;
  }, [dark]);

  return (
    <ConfigProvider
      theme={{ algorithm: dark ? theme.darkAlgorithm : theme.defaultAlgorithm }}
    >
      {/* AuthProvider sits above LiveProvider deliberately: the stream must not
          be opened before there is a credential to open it with, and it renders
          the sign-in screen in place of the app when there is none. */}
      <AuthProvider>
        <LiveProvider>
          <Shell dark={dark} onToggleTheme={setDark} />
        </LiveProvider>
      </AuthProvider>
    </ConfigProvider>
  );
}

function Shell({
  dark,
  onToggleTheme,
}: {
  dark: boolean;
  onToggleTheme: (v: boolean) => void;
}) {
  const { pool, connected } = useLive();
  const { user, signOut, required } = useAuth();
  const [tab, setTab] = useState('overview');

  return (
    <Layout style={{ minHeight: '100vh', background: 'transparent' }}>
      <Layout.Header
        style={{
          background: 'transparent',
          padding: '8px 16px',
          borderBottom: `1px solid ${dark ? '#33322e' : '#e6e5e0'}`,
          // The bar has to grow rather than clip: at phone widths its contents
          // wrap onto a second line, and a fixed 64px would push the live badge
          // and the theme switch outside it.
          height: 'auto',
          lineHeight: 1.4,
        }}
      >
        <Flex align="center" justify="space-between" gap={12} wrap>
          <Flex align="center" gap={12} wrap>
            <Typography.Title level={4} style={{ margin: 0, whiteSpace: 'nowrap' }}>
              tor-pool
            </Typography.Title>
            {pool && (
              <Typography.Text type="secondary" style={{ whiteSpace: 'nowrap' }}>
                SOCKS :{pool.socks_port}
                {pool.http_port ? ` · HTTP :${pool.http_port}` : ''}
              </Typography.Text>
            )}
          </Flex>
          <Flex align="center" gap={16} wrap>
            {/* nowrap throughout: these are short labels, and a version or a
                status word broken across two lines reads as corruption. */}
            <Badge
              status={connected ? 'processing' : 'error'}
              text={
                <span style={{ whiteSpace: 'nowrap' }}>
                  {connected ? 'live' : 'reconnecting'}
                </span>
              }
            />
            {pool && (
              <Typography.Text type="secondary" style={{ whiteSpace: 'nowrap' }}>
                {pool.version}
              </Typography.Text>
            )}
            <Switch
              checked={dark}
              onChange={onToggleTheme}
              checkedChildren="dark"
              unCheckedChildren="light"
            />
            {/* No sign-out under AUTH_DISABLED: there is no session to end, and a
                button that clears a credential nothing checks would appear to do
                nothing. The tag replaces it so the state is never invisible. */}
            {required ? (
              <Button size="small" onClick={signOut} style={{ whiteSpace: 'nowrap' }}>
                Sign out{user ? ` (${user})` : ''}
              </Button>
            ) : (
              <Tooltip title="AUTH_DISABLED is set: the proxy and the API accept any caller. Safe only while these ports are reachable from this machine alone.">
                <Tag color="warning" style={{ margin: 0, whiteSpace: 'nowrap' }}>
                  auth disabled
                </Tag>
              </Tooltip>
            )}
          </Flex>
        </Flex>
      </Layout.Header>

      <Layout.Content style={{ padding: 16 }}>
        {pool?.routable === 0 && (
          <Alert
            type="error"
            showIcon
            style={{ marginBottom: 16 }}
            message="No instance can take traffic"
            description="Every instance is starting, quarantined or being remediated. Clients are being refused until one recovers."
          />
        )}

        {/* Controlled, and destroyOnHidden stays false: hidden panes keep their
            sort, filter and pagination state, which is worth more than the
            memory. The cost is that a pane's effects keep running once it has
            been opened, so anything that polls needs to be told when it is not
            on screen — see Sessions. Views that read useLive() need nothing:
            they share one stream whatever is visible. */}
        <Tabs
          destroyOnHidden={false}
          activeKey={tab}
          onChange={setTab}
          items={[
            { key: 'overview', label: 'Overview', children: <Overview dark={dark} /> },
            { key: 'instances', label: 'Instances', children: <Instances /> },
            {
              key: 'sessions',
              label: 'Sessions',
              children: <Sessions active={tab === 'sessions'} />,
            },
            // Nothing checks a token under AUTH_DISABLED, so the tab would offer
            // to issue credentials that do not decide anything. Dropped rather
            // than disabled: the tokens are still stored and still start working
            // the moment the flag goes, so there is nothing broken to explain.
            ...(required
              ? [{ key: 'tokens', label: 'Tokens', children: <Tokens /> }]
              : []),
            { key: 'events', label: 'Events', children: <Events /> },
          ]}
        />
      </Layout.Content>
    </Layout>
  );
}
