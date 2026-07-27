import { useState } from 'react';
import { Card, Empty, Select, Space, Table, Tag, Typography } from 'antd';
import type { ColumnsType } from 'antd/es/table';

import type { PoolEvent } from '../api';
import { useLive } from '../live';

const typeColors: Record<string, string> = {
  assignment: 'blue',
  rotate: 'cyan',
  quarantine: 'red',
  remediation: 'purple',
  restart: 'orange',
  resize: 'geekblue',
  instance: 'gold',
};

export function Events() {
  const { events } = useLive();
  const [types, setTypes] = useState<string[]>([]);

  const present = Array.from(new Set(events.map((e) => e.type))).sort();
  const visible = types.length ? events.filter((e) => types.includes(e.type)) : events;

  const columns: ColumnsType<PoolEvent> = [
    {
      title: 'Time',
      dataIndex: 'at',
      width: 170,
      render: (iso: string) => (
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
          {new Date(iso).toLocaleString(undefined, { hour12: false })}
        </Typography.Text>
      ),
    },
    {
      title: 'Type',
      dataIndex: 'type',
      width: 130,
      render: (t: string) => <Tag color={typeColors[t] ?? 'default'}>{t}</Tag>,
    },
    {
      title: 'Instance',
      dataIndex: 'instance',
      width: 90,
      render: (id?: number) =>
        id === undefined ? (
          <Typography.Text type="secondary">—</Typography.Text>
        ) : (
          <Tag>{id}</Tag>
        ),
    },
    {
      title: 'Session',
      dataIndex: 'session',
      width: 160,
      render: (key?: string) =>
        key ? (
          <Typography.Text code>{key}</Typography.Text>
        ) : (
          <Typography.Text type="secondary">—</Typography.Text>
        ),
    },
    {
      title: 'What happened',
      key: 'message',
      render: (_, r) => (
        <Space direction="vertical" size={0}>
          <Typography.Text>{r.message}</Typography.Text>
          {r.detail && (
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              {r.detail}
            </Typography.Text>
          )}
        </Space>
      ),
    },
  ];

  return (
    <Card
      size="small"
      title="Events"
      extra={
        <Select
          mode="multiple"
          allowClear
          size="small"
          placeholder="All types"
          style={{ minWidth: 220 }}
          value={types}
          onChange={setTypes}
          options={present.map((t) => ({ label: t, value: t }))}
        />
      }
    >
      {events.length === 0 ? (
        <Empty
          description="Nothing has happened yet"
          image={Empty.PRESENTED_IMAGE_SIMPLE}
        />
      ) : (
        <Table
          rowKey="seq"
          size="small"
          columns={columns}
          dataSource={visible}
          pagination={{ pageSize: 25, hideOnSinglePage: true }}
          scroll={{ x: 900 }}
        />
      )}
    </Card>
  );
}
