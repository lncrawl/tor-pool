import { useCallback, useEffect, useState } from 'react';
import {
  Alert,
  Button,
  Card,
  Empty,
  Flex,
  Form,
  Input,
  Modal,
  Popconfirm,
  Select,
  Table,
  Tag,
  Typography,
  message,
} from 'antd';
import type { ColumnsType } from 'antd/es/table';

import { api, type MintedToken, type TokenInfo, type TokenScope } from '../api';
import { clockTime } from '../theme';

export function Tokens() {
  const [tokens, setTokens] = useState<TokenInfo[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [minted, setMinted] = useState<MintedToken | null>(null);
  const [toast, toastHost] = message.useMessage();
  const [form] = Form.useForm<{ name: string; scope: TokenScope }>();

  const load = useCallback(
    () =>
      api
        .tokens()
        .then(setTokens)
        .catch((err: Error) => toast.error(`Could not list tokens: ${err.message}`)),
    [toast],
  );

  useEffect(() => {
    void load();
  }, [load]);

  const mint = async ({ name, scope }: { name: string; scope: TokenScope }) => {
    setBusy('mint');
    try {
      const created = await api.mintToken(name, scope);
      // Shown in a modal because this is the only response that carries the
      // secret: it is stored as a digest, so it cannot be shown twice.
      setMinted(created);
      form.resetFields();
      await load();
    } catch (err) {
      toast.error(`Could not issue the token: ${(err as Error).message}`);
    } finally {
      setBusy(null);
    }
  };

  const revoke = async (token: TokenInfo) => {
    setBusy(token.id);
    try {
      await api.revokeToken(token.id);
      toast.success(`Revoked ${token.name}`);
      await load();
    } catch (err) {
      toast.error(`Could not revoke ${token.name}: ${(err as Error).message}`);
    } finally {
      setBusy(null);
    }
  };

  const columns: ColumnsType<TokenInfo> = [
    {
      title: 'Name',
      dataIndex: 'name',
      width: 220,
      render: (name: string, token) => (
        <Flex vertical>
          <Typography.Text>{name}</Typography.Text>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            {token.id}
          </Typography.Text>
        </Flex>
      ),
    },
    {
      title: 'Scope',
      dataIndex: 'scope',
      width: 120,
      render: (scope: TokenScope) => (
        <Tag color={scope === 'admin' ? 'volcano' : 'blue'}>{scope}</Tag>
      ),
    },
    {
      title: 'Source',
      dataIndex: 'source',
      width: 130,
      render: (source: string) =>
        source === 'environment' ? (
          <Tag>PROXY_TOKEN</Tag>
        ) : (
          <Typography.Text type="secondary">issued</Typography.Text>
        ),
    },
    {
      title: 'Last used',
      dataIndex: 'last_used',
      width: 140,
      render: (at?: number) =>
        at ? (
          clockTime(new Date(at * 1000).toISOString())
        ) : (
          <Typography.Text type="secondary">never</Typography.Text>
        ),
    },
    {
      title: '',
      key: 'actions',
      width: 110,
      render: (_, token) =>
        token.source === 'environment' ? (
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            set in env
          </Typography.Text>
        ) : (
          <Popconfirm
            title={`Revoke ${token.name}?`}
            description="Anything using it stops working immediately."
            okText="Revoke"
            okButtonProps={{ danger: true }}
            onConfirm={() => revoke(token)}
          >
            <Button size="small" danger loading={busy === token.id}>
              Revoke
            </Button>
          </Popconfirm>
        ),
    },
  ];

  return (
    <>
      {toastHost}

      <Card size="small" title="Issue a token" style={{ marginBottom: 16 }}>
        <Form form={form} layout="inline" onFinish={mint} requiredMark={false}>
          <Form.Item name="name" rules={[{ required: true, message: 'Name it' }]}>
            <Input placeholder="scraper-prod" style={{ width: 220 }} />
          </Form.Item>
          <Form.Item name="scope" initialValue="proxy">
            <Select
              style={{ width: 260 }}
              options={[
                { value: 'proxy', label: 'proxy — traffic and its own sessions' },
                { value: 'admin', label: 'admin — full control of the pool' },
              ]}
            />
          </Form.Item>
          <Button type="primary" htmlType="submit" loading={busy === 'mint'}>
            Issue
          </Button>
        </Form>
        <Typography.Paragraph
          type="secondary"
          style={{ fontSize: 12, marginTop: 12, marginBottom: 0 }}
        >
          A token is the password on a proxy URL:{' '}
          <Typography.Text code>socks5h://&lt;session&gt;:&lt;token&gt;@host:9250</Typography.Text>.
          The username stays the session key. Give a scraper the{' '}
          <Typography.Text code>proxy</Typography.Text> scope — an{' '}
          <Typography.Text code>admin</Typography.Text> token can also resize the
          pool and restart instances.
        </Typography.Paragraph>
      </Card>

      <Card size="small" title={`Tokens (${tokens.length})`}>
        {tokens.length === 0 ? (
          <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="No tokens" />
        ) : (
          <Table
            rowKey="id"
            size="small"
            columns={columns}
            dataSource={tokens}
            pagination={{ pageSize: 20, hideOnSinglePage: true }}
            scroll={{ x: 720 }}
          />
        )}
      </Card>

      <Modal
        open={minted !== null}
        title="Copy this token now"
        onCancel={() => setMinted(null)}
        onOk={() => setMinted(null)}
        okText="Done"
        cancelButtonProps={{ style: { display: 'none' } }}
      >
        <Flex vertical gap={12}>
          <Alert
            type="warning"
            showIcon
            message="Shown once"
            description="Only a digest is stored, so this cannot be displayed again. Losing it means issuing another."
          />
          <Input.TextArea value={minted?.secret} readOnly autoSize rows={1} />
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            Use it as the password, keeping the username as the session key:
          </Typography.Text>
          <Input.TextArea
            value={`socks5h://my-session:${minted?.secret ?? ''}@127.0.0.1:9250`}
            readOnly
            autoSize
          />
        </Flex>
      </Modal>
    </>
  );
}
