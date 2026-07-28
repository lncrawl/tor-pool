import { useState } from 'react';
import {
  Button,
  Card,
  Dropdown,
  Flex,
  InputNumber,
  Popconfirm,
  Progress,
  Space,
  Table,
  Tag,
  Tooltip,
  Typography,
  message,
} from 'antd';
import type { ColumnsType } from 'antd/es/table';

import { api, type Instance } from '../api';
import { useLive } from '../live';
import { formatBytes, formatDuration, stateColor } from '../theme';

export function Instances() {
  const { pool, instances } = useLive();
  const [busy, setBusy] = useState<number | null>(null);
  const [size, setSize] = useState<number | null>(null);
  const [toast, toastHost] = message.useMessage();

  // Actions are slow (a restart re-bootstraps tor), so the row is locked while
  // one is in flight rather than letting a second click stack another.
  const run = async (id: number, label: string, fn: () => Promise<unknown>) => {
    setBusy(id);
    try {
      await fn();
      toast.success(`${label} on instance ${id}`);
    } catch (err) {
      toast.error(`${label} failed: ${(err as Error).message}`);
    } finally {
      setBusy(null);
    }
  };

  const columns: ColumnsType<Instance> = [
    {
      title: 'ID',
      dataIndex: 'id',
      width: 60,
      sorter: (a, b) => a.id - b.id,
      defaultSortOrder: 'ascend',
    },
    {
      title: 'State',
      key: 'state',
      width: 190,
      render: (_, r) => (
        <Space direction="vertical" size={2}>
          {/* Never colour alone: the tag always carries the state name. */}
          <Tag color={stateColor(r.health.state)}>{r.health.state}</Tag>
          {r.bootstrap < 100 && (
            <Progress percent={r.bootstrap} size="small" style={{ width: 120 }} />
          )}
          {r.health.state === 'remediating' && (
            <Typography.Text type="secondary" style={{ fontSize: 11 }}>
              {r.health.remediation_rung}
            </Typography.Text>
          )}
        </Space>
      ),
      filters: [
        { text: 'healthy', value: 'healthy' },
        { text: 'degraded', value: 'degraded' },
        { text: 'probation', value: 'probation' },
        { text: 'quarantined', value: 'quarantined' },
        { text: 'remediating', value: 'remediating' },
        { text: 'starting', value: 'starting' },
      ],
      onFilter: (value, r) => r.health.state === value,
    },
    {
      title: 'Exit',
      key: 'exit',
      // Width is not optional: every other column here is fixed, so a column
      // left to size itself gets whatever is left of scroll.x — about 30px once
      // the viewport is narrower than the table, which stacks an IP one
      // character per line.
      width: 190,
      render: (_, r) => {
        if (r.exit_ip) {
          return (
            <Space direction="vertical" size={0}>
              <Typography.Text code>{r.exit_ip}</Typography.Text>
              <Typography.Text type="secondary" style={{ fontSize: 11 }}>
                {[r.exit_country, r.exit_nickname].filter(Boolean).join(' · ')}
              </Typography.Text>
            </Space>
          );
        }
        // A rotation discards the exit and Tor commits to the next one only when
        // traffic arrives, so the retired one is shown struck through rather
        // than leaving the column blank as if nothing were known.
        if (r.retired_exit_ip) {
          return (
            <Tooltip title="Retired by a rotation. The next request through this instance picks a new exit.">
              <Space direction="vertical" size={0}>
                <Typography.Text code delete type="secondary">
                  {r.retired_exit_ip}
                </Typography.Text>
                <Typography.Text type="secondary" style={{ fontSize: 11 }}>
                  awaiting a new circuit
                </Typography.Text>
              </Space>
            </Tooltip>
          );
        }
        return <Typography.Text type="secondary">—</Typography.Text>;
      },
    },
    {
      title: 'Sessions',
      dataIndex: 'sessions',
      width: 90,
      sorter: (a, b) => a.sessions - b.sessions,
    },
    {
      title: 'Requests',
      key: 'requests',
      width: 100,
      sorter: (a, b) => a.totals.requests - b.totals.requests,
      render: (_, r) => r.totals.requests,
    },
    {
      title: 'Failures',
      key: 'failures',
      width: 140,
      render: (_, r) => (
        <Tooltip
          title={`${r.health.transport_failures} seen by the balancer, ${r.health.client_failures} reported by clients`}
        >
          <Space size={4}>
            <Typography.Text>{r.health.transport_failures}</Typography.Text>
            <Typography.Text type="secondary">/</Typography.Text>
            <Typography.Text>{r.health.client_failures}</Typography.Text>
            {r.health.failures_in_window > 0 && (
              <Tag color="gold">{r.health.failures_in_window} recent</Tag>
            )}
          </Space>
        </Tooltip>
      ),
    },
    {
      title: 'Latency',
      key: 'latency',
      width: 100,
      sorter: (a, b) => a.totals.latency_ms - b.totals.latency_ms,
      render: (_, r) =>
        r.totals.latency_ms > 0 ? `${r.totals.latency_ms.toFixed(0)} ms` : '—',
    },
    {
      title: 'Traffic',
      key: 'traffic',
      width: 110,
      render: (_, r) => (
        <Tooltip title={`${formatBytes(r.totals.bytes_up)} up`}>
          {formatBytes(r.totals.bytes_down)}
        </Tooltip>
      ),
    },
    {
      title: 'Uptime',
      key: 'uptime',
      width: 90,
      render: (_, r) => formatDuration(r.uptime_secs),
    },
    {
      title: '',
      key: 'actions',
      width: 190,
      render: (_, r) => (
        <Space size={4}>
          <Button
            size="small"
            loading={busy === r.id}
            onClick={() => run(r.id, 'New circuit', () => api.rotateInstance(r.id))}
          >
            Rotate
          </Button>
          {r.health.state === 'quarantined' ? (
            <Button
              size="small"
              loading={busy === r.id}
              onClick={() => run(r.id, 'Released', () => api.releaseInstance(r.id))}
            >
              Release
            </Button>
          ) : (
            <Button
              size="small"
              loading={busy === r.id}
              onClick={() => run(r.id, 'Quarantined', () => api.quarantineInstance(r.id))}
            >
              Quarantine
            </Button>
          )}
          <Dropdown
            menu={{
              items: [
                {
                  key: 'drain',
                  label: 'Drain sessions',
                  onClick: () => run(r.id, 'Drained', () => api.drainInstance(r.id)),
                },
                {
                  key: 'restart',
                  label: 'Restart (wipe state)',
                  danger: true,
                  onClick: () => run(r.id, 'Restarted', () => api.restartInstance(r.id, true)),
                },
              ],
            }}
          >
            <Button size="small">···</Button>
          </Dropdown>
        </Space>
      ),
    },
  ];

  return (
    <>
      {toastHost}
      <Card
        size="small"
        title={`Instances (${pool?.routable ?? 0} routable of ${pool?.size ?? 0})`}
        styles={{ title: { whiteSpace: 'normal' } }}
        extra={
          <Flex gap={8} align="center" wrap>
            <InputNumber
              min={1}
              max={100}
              value={size ?? pool?.size}
              onChange={setSize}
              style={{ width: 72 }}
            />
            <Popconfirm
              title="Resize the pool?"
              description="Shrinking retires the highest-numbered instances and moves their sessions."
              onConfirm={async () => {
                const target = size ?? pool?.size ?? 1;
                try {
                  await api.resize(target);
                  toast.success(`Pool resizing to ${target}`);
                } catch (err) {
                  toast.error((err as Error).message);
                }
              }}
            >
              <Button size="small">Resize</Button>
            </Popconfirm>
            <Popconfirm
              title="New circuit on every instance?"
              description="Each waits out its own cooldown, so this takes a few seconds."
              onConfirm={async () => {
                await api.rotateAll();
                toast.success('Rotating every instance');
              }}
            >
              <Button size="small">Rotate all</Button>
            </Popconfirm>
          </Flex>
        }
      >
        <Table
          rowKey="id"
          size="small"
          columns={columns}
          dataSource={instances}
          pagination={false}
          scroll={{ x: 1260 }}
        />
      </Card>
    </>
  );
}
