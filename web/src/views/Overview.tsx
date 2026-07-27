import { Card, Col, Empty, Flex, Row, Statistic, Tag, Typography } from 'antd';

import type { Sample } from '../api';
import { TimeChart } from '../components/Charts';
import { useLive } from '../live';
import { clockTime, formatBytes, palette } from '../theme';

export function Overview({ dark }: { dark: boolean }) {
  const { pool, instances, history, events } = useLive();
  const p = palette(dark);

  const latest = history.length ? history[history.length - 1] : undefined;
  const errorRate = latest && latest.requests > 0
    ? (latest.failures / latest.requests) * 100
    : 0;

  const unhealthy = instances.filter(
    (i) => i.health.state === 'quarantined' || i.health.state === 'remediating',
  ).length;

  // Error rate is a derived measure, so it is computed here rather than being
  // another field the server has to keep in every bucket.
  const withRate: Sample[] = history.map((s) => ({
    ...s,
    failures: s.requests > 0 ? Number(((s.failures / s.requests) * 100).toFixed(1)) : 0,
  }));

  return (
    <Flex vertical gap={16}>
      <Row gutter={[16, 16]}>
        <Col xs={12} md={6}>
          <Card size="small">
            <Statistic
              title="Routable instances"
              value={pool?.routable ?? 0}
              suffix={`/ ${pool?.size ?? 0}`}
              valueStyle={{
                color: (pool?.routable ?? 0) === 0 ? p.status.critical : undefined,
              }}
            />
            {unhealthy > 0 && (
              <Tag color="red" style={{ marginTop: 8 }}>
                {unhealthy} in trouble
              </Tag>
            )}
          </Card>
        </Col>
        <Col xs={12} md={6}>
          <Card size="small">
            <Statistic title="Active sessions" value={pool?.sessions ?? 0} />
          </Card>
        </Col>
        <Col xs={12} md={6}>
          <Card size="small">
            <Statistic title="Requests" value={pool?.totals.requests ?? 0} />
          </Card>
        </Col>
        <Col xs={12} md={6}>
          <Card size="small">
            <Statistic
              title="Error rate"
              value={errorRate}
              precision={1}
              suffix="%"
              valueStyle={{ color: errorRate > 10 ? p.status.critical : undefined }}
            />
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]}>
        <Col xs={24} lg={12}>
          <TimeChart
            title="Requests"
            subtitle="Connections proxied per bucket."
            samples={history}
            series={[{ key: 'requests', label: 'Requests', slot: 0 }]}
            dark={dark}
          />
        </Col>
        <Col xs={24} lg={12}>
          <TimeChart
            title="Error rate"
            subtitle="Share of connections that failed."
            samples={withRate}
            series={[{ key: 'failures', label: 'Error rate', slot: 1 }]}
            dark={dark}
            unit="%"
          />
        </Col>
        <Col xs={24} lg={12}>
          <TimeChart
            title="Connect latency"
            subtitle="Time to establish a connection through Tor."
            samples={history}
            series={[
              { key: 'latency_p50_ms', label: 'p50', slot: 0 },
              { key: 'latency_p95_ms', label: 'p95', slot: 1 },
            ]}
            dark={dark}
            unit="ms"
          />
        </Col>
        <Col xs={24} lg={12}>
          <TimeChart
            title="Routable instances"
            subtitle="Instances able to take traffic."
            samples={history}
            series={[{ key: 'routable', label: 'Routable', slot: 2 }]}
            dark={dark}
          />
        </Col>
      </Row>

      <Row gutter={[16, 16]}>
        <Col xs={24} lg={12}>
          <Card size="small" title="Traffic">
            <Row gutter={16}>
              <Col span={12}>
                <Statistic
                  title="Downloaded"
                  value={formatBytes(pool?.totals.bytes_down ?? 0)}
                />
              </Col>
              <Col span={12}>
                <Statistic
                  title="Uploaded"
                  value={formatBytes(pool?.totals.bytes_up ?? 0)}
                />
              </Col>
            </Row>
          </Card>
        </Col>
        <Col xs={24} lg={12}>
          <Card size="small" title="Recent activity">
            {events.length === 0 ? (
              <Empty description="Nothing yet" image={Empty.PRESENTED_IMAGE_SIMPLE} />
            ) : (
              <Flex vertical gap={4}>
                {events.slice(0, 6).map((e) => (
                  <Flex key={e.seq} gap={8} align="baseline">
                    <Typography.Text type="secondary" style={{ fontSize: 12, minWidth: 62 }}>
                      {clockTime(e.at)}
                    </Typography.Text>
                    <Tag>{e.type}</Tag>
                    <Typography.Text style={{ fontSize: 13 }}>{e.message}</Typography.Text>
                  </Flex>
                ))}
              </Flex>
            )}
          </Card>
        </Col>
      </Row>
    </Flex>
  );
}
