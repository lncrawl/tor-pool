import { useEffect, useState } from 'react';
import {
  Button,
  Card,
  Empty,
  Flex,
  Input,
  Space,
  Table,
  Tag,
  Typography,
  message,
} from 'antd';
import type { ColumnsType } from 'antd/es/table';

import { api, type Session } from '../api';
import { useLive } from '../live';
import { formatBytes } from '../theme';

// refreshInterval is how often the session list is re-fetched.
//
// Sessions are not part of the SSE frame: a busy pool can hold thousands, and
// pushing them all every second would dwarf the rest of the stream.
const refreshInterval = 3000;

/**
 * Sessions lists the pinned sessions, polling while it is on screen.
 *
 * `active` is required rather than optional. The tab strip keeps hidden panes
 * mounted, so an unguarded interval here kept fetching for the life of the page
 * once the tab had been opened even once — and it has to be the caller that says
 * so, because a mounted-but-hidden pane cannot tell the difference itself.
 */
export function Sessions({ active }: { active: boolean }) {
  const { instances } = useLive();
  const [sessions, setSessions] = useState<Session[]>([]);
  const [filter, setFilter] = useState('');
  const [busy, setBusy] = useState<string | null>(null);
  const [toast, toastHost] = message.useMessage();

  useEffect(() => {
    if (!active) return;

    let cancelled = false;
    const load = () =>
      api
        .sessions()
        .then((s) => {
          if (!cancelled) setSessions(s);
        })
        .catch(() => undefined);

    // Immediately as well as on the interval, so returning to the tab shows
    // current data rather than whatever was left from the last visit.
    load();
    const timer = setInterval(load, refreshInterval);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [active]);

  const run = async (key: string, label: string, fn: () => Promise<unknown>) => {
    setBusy(key);
    try {
      await fn();
      toast.success(`${label}: ${key}`);
      setSessions(await api.sessions());
    } catch (err) {
      toast.error(`${label} failed: ${(err as Error).message}`);
    } finally {
      setBusy(null);
    }
  };

  const visible = filter
    ? sessions.filter((s) => s.key.toLowerCase().includes(filter.toLowerCase()))
    : sessions;

  const columns: ColumnsType<Session> = [
    {
      title: 'Session key',
      dataIndex: 'key',
      // Fixed for the same reason as the exit column on the instances table: the
      // rest of the columns are fixed, so an unsized one is left with the
      // remainder of scroll.x and wraps a key one character per line.
      width: 200,
      render: (key: string) => <Typography.Text code>{key}</Typography.Text>,
    },
    {
      title: 'Instance',
      dataIndex: 'instance',
      width: 110,
      sorter: (a, b) => a.instance - b.instance,
      filters: instances.map((i) => ({ text: `Instance ${i.id}`, value: i.id })),
      onFilter: (value, r) => r.instance === value,
      render: (id: number) => <Tag>{id}</Tag>,
    },
    {
      title: 'Exit',
      key: 'exit',
      width: 150,
      render: (_, r) => {
        const inst = instances.find((i) => i.id === r.instance);
        return inst?.exit_ip ? (
          <Typography.Text code>{inst.exit_ip}</Typography.Text>
        ) : (
          <Typography.Text type="secondary">—</Typography.Text>
        );
      },
    },
    {
      title: 'Requests',
      dataIndex: 'requests',
      width: 100,
      sorter: (a, b) => a.requests - b.requests,
    },
    {
      title: 'Failures',
      dataIndex: 'failures',
      width: 100,
      sorter: (a, b) => a.failures - b.failures,
      render: (n: number) => (n > 0 ? <Tag color="red">{n}</Tag> : n),
    },
    {
      title: 'In flight',
      dataIndex: 'active',
      width: 90,
      render: (n: number) => (n > 0 ? <Tag color="blue">{n}</Tag> : n),
    },
    {
      title: 'Traffic',
      key: 'traffic',
      width: 100,
      render: (_, r) => formatBytes(r.bytes_down),
    },
    {
      title: 'Last seen',
      dataIndex: 'last_seen',
      width: 110,
      render: (iso: string) => {
        const age = (Date.now() - new Date(iso).getTime()) / 1000;
        return Number.isNaN(age) ? '—' : `${Math.max(0, Math.round(age))}s ago`;
      },
    },
    {
      title: '',
      key: 'actions',
      width: 150,
      render: (_, r) => (
        <Space size={4}>
          <Button
            size="small"
            loading={busy === r.key}
            onClick={() => run(r.key, 'Rotated', () => api.rotateSession(r.key))}
          >
            Rotate
          </Button>
          <Button
            size="small"
            danger
            loading={busy === r.key}
            onClick={() => run(r.key, 'Dropped', () => api.dropSession(r.key))}
          >
            Drop
          </Button>
        </Space>
      ),
    },
  ];

  return (
    <>
      {toastHost}
      <Card
        size="small"
        title={`Sessions (${sessions.length})`}
        extra={
          <Flex gap={8}>
            <Input.Search
              placeholder="Filter by key"
              allowClear
              size="small"
              style={{ width: 220 }}
              onChange={(e) => setFilter(e.target.value)}
            />
          </Flex>
        }
      >
        {sessions.length === 0 ? (
          <Empty
            description="No sessions yet — connect through the SOCKS port to create one"
            image={Empty.PRESENTED_IMAGE_SIMPLE}
          />
        ) : (
          <Table
            rowKey="key"
            size="small"
            columns={columns}
            dataSource={visible}
            pagination={{ pageSize: 20, hideOnSinglePage: true }}
            scroll={{ x: 1110 }}
          />
        )}
      </Card>
    </>
  );
}
