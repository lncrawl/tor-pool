import { Card, Empty, Typography } from 'antd';
import {
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';

import type { Sample } from '../api';
import { clockTime, palette } from '../theme';

export interface SeriesSpec {
  key: keyof Sample;
  label: string;
  /** Index into the validated categorical palette. */
  slot: 0 | 1 | 2;
}

interface Props {
  title: string;
  /** Short sentence naming what the reader is looking at. */
  subtitle?: string;
  samples: Sample[];
  series: SeriesSpec[];
  dark: boolean;
  /** Rendered next to the latest value, e.g. "ms" or "%". */
  unit?: string;
  height?: number;
}

/**
 * TimeChart draws one or more measures against time.
 *
 * Deliberately one y-axis only: two scales on one chart is the single most
 * misread chart form. Measures of different magnitude get their own chart.
 */
export function TimeChart({
  title,
  subtitle,
  samples,
  series,
  dark,
  unit,
  height = 200,
}: Props) {
  const p = palette(dark);
  const latest = samples.length ? samples[samples.length - 1] : undefined;

  // A single series is named by the title, so it needs no legend box.
  const showLegend = series.length > 1;

  return (
    <Card
      size="small"
      title={title}
      // The latest value as a direct label, rather than a number on every
      // point. This also carries the relief rule for the lower-contrast hues.
      extra={
        latest && (
          <Typography.Text strong>
            {series
              .map((s) => formatValue(latest[s.key]))
              .join(' / ')}
            {unit ? ` ${unit}` : ''}
          </Typography.Text>
        )
      }
    >
      {subtitle && (
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
          {subtitle}
        </Typography.Text>
      )}

      {samples.length === 0 ? (
        <Empty
          description="No traffic yet"
          image={Empty.PRESENTED_IMAGE_SIMPLE}
          style={{ height, display: 'flex', flexDirection: 'column', justifyContent: 'center' }}
        />
      ) : (
        <ResponsiveContainer width="100%" height={height}>
          <LineChart data={samples} margin={{ top: 12, right: 8, bottom: 0, left: -12 }}>
            <CartesianGrid stroke={p.ink.grid} vertical={false} />
            <XAxis
              dataKey="at"
              tickFormatter={clockTime}
              stroke={p.ink.secondary}
              tick={{ fontSize: 11, fill: p.ink.secondary }}
              minTickGap={48}
            />
            <YAxis
              stroke={p.ink.secondary}
              tick={{ fontSize: 11, fill: p.ink.secondary }}
              width={48}
              allowDecimals={false}
            />
            <Tooltip
              contentStyle={{
                background: p.surface,
                border: `1px solid ${p.ink.grid}`,
                borderRadius: 6,
                color: p.ink.primary,
              }}
              labelFormatter={(v) => clockTime(String(v))}
              formatter={(value, name) => [formatValue(value), name]}
            />
            {showLegend && <Legend wrapperStyle={{ fontSize: 12 }} />}
            {series.map((s) => (
              <Line
                key={String(s.key)}
                type="monotone"
                dataKey={s.key}
                name={s.label}
                stroke={p.series[s.slot]}
                strokeWidth={2}
                dot={false}
                // A visible marker only on hover; ≥8px so it is easy to hit.
                activeDot={{ r: 4, strokeWidth: 2, stroke: p.surface }}
                isAnimationActive={false}
              />
            ))}
          </LineChart>
        </ResponsiveContainer>
      )}
    </Card>
  );
}

function formatValue(value: unknown): string {
  if (typeof value !== 'number') return String(value ?? '');
  return Number.isInteger(value) ? String(value) : value.toFixed(1);
}
