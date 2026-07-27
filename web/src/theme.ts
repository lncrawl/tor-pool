import type { InstanceState } from './api';

/**
 * Chart colours, validated for colour-vision deficiency against both surfaces.
 *
 * Only the first three categorical slots are used, and only on line charts
 * (the adjacent pairlist), which is what the validation covers. Adding a fourth
 * series would put yellow next to orange and fail the separation floor — fold
 * extra series into "other" or use a second chart instead.
 */
export const series = {
  light: ['#2a78d6', '#eb6834', '#1baf7a'],
  dark: ['#3987e5', '#d95926', '#199e70'],
} as const;

/**
 * Status colours are reserved for state and never reused as a series hue.
 */
export const status = {
  light: { good: '#1baf7a', warning: '#eda100', critical: '#e34948' },
  dark: { good: '#199e70', warning: '#c98500', critical: '#e66767' },
} as const;

export const surfaces = { light: '#fcfcfb', dark: '#1a1a19' } as const;

export const ink = {
  light: { primary: '#1a1a19', secondary: '#5c5b52', grid: '#e6e5e0' },
  dark: { primary: '#ffffff', secondary: '#c3c2b7', grid: '#33322e' },
} as const;

/** palette resolves every token for the active mode. */
export function palette(dark: boolean) {
  return {
    series: dark ? series.dark : series.light,
    status: dark ? status.dark : status.light,
    surface: dark ? surfaces.dark : surfaces.light,
    ink: dark ? ink.dark : ink.light,
  };
}

/**
 * stateColor maps an instance state onto an AntD tag colour.
 *
 * State is never conveyed by colour alone — the tag always shows the state's
 * name too.
 */
export function stateColor(state: InstanceState): string {
  switch (state) {
    case 'healthy':
      return 'green';
    case 'degraded':
      return 'gold';
    case 'probation':
      return 'orange';
    case 'quarantined':
      return 'red';
    case 'remediating':
      return 'purple';
    case 'starting':
      return 'blue';
    default:
      return 'default';
  }
}

/** formatBytes renders a byte count compactly. */
export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let value = n / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  return `${value.toFixed(value < 10 ? 1 : 0)} ${units[unit]}`;
}

/** formatDuration renders a second count as a compact age. */
export function formatDuration(seconds: number): string {
  if (seconds < 60) return `${Math.round(seconds)}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s`;
  const hours = Math.floor(seconds / 3600);
  return `${hours}h ${Math.floor((seconds % 3600) / 60)}m`;
}

/** clockTime renders an ISO timestamp as a short local time. */
export function clockTime(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime())
    ? ''
    : d.toLocaleTimeString(undefined, { hour12: false });
}
