import { useEffect, useState } from 'react';
import { Alert, Badge, ConfigProvider, Flex, Layout, Switch, Tabs, Typography, theme } from 'antd';

import { LiveProvider, useLive } from './live';
import { surfaces } from './theme';
import { Events } from './views/Events';
import { Instances } from './views/Instances';
import { Overview } from './views/Overview';
import { Sessions } from './views/Sessions';

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
      <LiveProvider>
        <Shell dark={dark} onToggleTheme={setDark} />
      </LiveProvider>
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

  return (
    <Layout style={{ minHeight: '100vh', background: 'transparent' }}>
      <Layout.Header
        style={{
          background: 'transparent',
          padding: '0 16px',
          borderBottom: `1px solid ${dark ? '#33322e' : '#e6e5e0'}`,
        }}
      >
        <Flex align="center" justify="space-between" style={{ height: '100%' }} gap={16}>
          <Flex align="center" gap={12}>
            <Typography.Title level={4} style={{ margin: 0 }}>
              tor-pool
            </Typography.Title>
            {pool && (
              <Typography.Text type="secondary">
                SOCKS :{pool.socks_port}
                {pool.http_port ? ` · HTTP :${pool.http_port}` : ''}
              </Typography.Text>
            )}
          </Flex>
          <Flex align="center" gap={16}>
            <Badge
              status={connected ? 'processing' : 'error'}
              text={connected ? 'live' : 'reconnecting'}
            />
            {pool && <Typography.Text type="secondary">{pool.version}</Typography.Text>}
            <Switch
              checked={dark}
              onChange={onToggleTheme}
              checkedChildren="dark"
              unCheckedChildren="light"
            />
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

        <Tabs
          defaultActiveKey="overview"
          destroyInactiveTabPane={false}
          items={[
            { key: 'overview', label: 'Overview', children: <Overview dark={dark} /> },
            { key: 'instances', label: 'Instances', children: <Instances /> },
            { key: 'sessions', label: 'Sessions', children: <Sessions /> },
            { key: 'events', label: 'Events', children: <Events /> },
          ]}
        />
      </Layout.Content>
    </Layout>
  );
}
