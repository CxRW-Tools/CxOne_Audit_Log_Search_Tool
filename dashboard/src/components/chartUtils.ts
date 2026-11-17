import {
  Chart,
  ArcElement,
  BarController,
  BarElement,
  CategoryScale,
  DoughnutController,
  Legend,
  LinearScale,
  LineController,
  LineElement,
  PointElement,
  Tooltip,
  type ChartConfiguration,
} from 'chart.js';
export { truncate } from '../format.js';

Chart.register(
  ArcElement,
  BarController,
  BarElement,
  CategoryScale,
  DoughnutController,
  Legend,
  LinearScale,
  LineController,
  LineElement,
  PointElement,
  Tooltip,
);

export const CAT_COLORS: Record<string, string> = {
  'Scanning': '#6B34FD',
  'Identity & Auth': '#006BD5',
  'Project Mgmt': '#A822BF',
  'Access Control': '#F25929',
  'Data Access': '#D91A3C',
  'Config': '#E89000',
  'Other': '#a99fc0',
};

export const COLORS = {
  violet: '#6B34FD',
  orange: '#F25929',
  magenta: '#A822BF',
  muted: '#a99fc0',
  rest: '#5b4d73',
  grid: '#3a2a52',
  text: '#FCF9FE',
  previous: 'rgba(252,249,254,0.55)',
};

export function allDaysInRange(dateMin: string, dateMax: string): string[] {
  const days: string[] = [];
  if (!dateMin || !dateMax) return days;
  const start = new Date(dateMin + 'T00:00:00Z');
  const end = new Date(dateMax + 'T00:00:00Z');
  for (let d = new Date(start); d <= end; d.setUTCDate(d.getUTCDate() + 1)) {
    days.push(d.toISOString().slice(0, 10));
  }
  return days;
}

export interface Bucket {
  /** Underlying key (used for filtering); null for the "Other" bucket. */
  key: string | null;
  label: string;
  value: number;
  /** For the rest bucket: the keys it aggregates. */
  rest?: { key: string; value: number }[];
}

/**
 * Top N entries by count, plus an "Other (+k)" bucket for the remainder so the chart's
 * total always matches the data in scope.
 */
export function topWithRest(counts: Map<string, number>, n: number, label = (k: string) => k): Bucket[] {
  const sorted = Array.from(counts.entries()).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  const top: Bucket[] = sorted.slice(0, n).map(([k, v]) => ({ key: k, label: label(k), value: v }));
  const rest = sorted.slice(n);
  if (rest.length) {
    top.push({
      key: null,
      label: `Other (+${rest.length})`,
      value: rest.reduce((s, [, v]) => s + v, 0),
      rest: rest.map(([key, value]) => ({ key, value })),
    });
  }
  return top;
}

/** Tooltip lines for a rest bucket: its largest members. */
export function restTooltip(b: Bucket, max = 8): string[] {
  if (!b.rest) return [];
  const lines = b.rest.slice(0, max).map((r) => `  ${r.key}: ${r.value.toLocaleString()}`);
  if (b.rest.length > max) lines.push(`  … and ${b.rest.length - max} more`);
  return lines;
}

/**
 * Create the chart, or update it in place when the type is unchanged (far cheaper than
 * destroy + recreate on every filter change, and avoids flicker).
 */
export function upsertChart(existing: Chart | null, canvas: HTMLCanvasElement, config: ChartConfiguration): Chart {
  if (existing && (existing.config as ChartConfiguration).type === config.type) {
    existing.data = config.data;
    existing.options = config.options ?? {};
    existing.update('none');
    return existing;
  }
  existing?.destroy();
  return new Chart(canvas.getContext('2d')!, config);
}

/** Text alternative for a chart canvas, plus an empty-state message over the panel. */
export function describeChart(canvas: HTMLCanvasElement, summary: string, empty: boolean, emptyText = 'No events in scope'): void {
  canvas.setAttribute('role', 'img');
  canvas.setAttribute('aria-label', summary);
  const container = canvas.parentElement!;
  let note = container.querySelector<HTMLElement>('.chart-empty');
  if (!note) {
    note = document.createElement('div');
    note.className = 'chart-empty';
    container.appendChild(note);
  }
  note.textContent = emptyText;
  note.hidden = !empty;
}

/** "Scanning 41%, Identity & Auth 30%, …" for aria-labels. */
export function summarize(buckets: Bucket[], max = 5): string {
  const total = buckets.reduce((s, b) => s + b.value, 0);
  if (!total) return 'No data';
  return buckets
    .slice(0, max)
    .map((b) => `${b.label} ${b.value.toLocaleString()} (${Math.round((b.value / total) * 100)}%)`)
    .join(', ');
}

export const axisStyle = {
  x: { ticks: { color: COLORS.muted }, grid: { color: COLORS.grid } },
  y: { ticks: { color: COLORS.text, font: { size: 11 } }, grid: { color: COLORS.grid } },
};
