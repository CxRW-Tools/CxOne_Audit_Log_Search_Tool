import type { Chart } from 'chart.js';
import { rows, getFilter, setFilter, getTimeZone } from '../state.js';
import { tzLabel } from '../format.js';
import { COLORS, describeChart, upsertChart } from './chartUtils.js';

let _chart: Chart | null = null;
let _cb: () => void = () => {};

export function initHourChart(cb: () => void): void {
  _cb = cb;
}

export function renderHourChart(): void {
  const canvas = document.getElementById('hour-canvas') as HTMLCanvasElement | null;
  if (!canvas) return;

  const titleEl = document.getElementById('hour-title');
  if (titleEl) titleEl.textContent = `Hourly Distribution (${getTimeZone() === 'utc' ? 'UTC' : 'local'})`;

  const f = getFilter();
  const scoped = rows();
  const counts = new Array(24).fill(0);
  for (const e of scoped) counts[e.hour]++;
  const labels = Array.from({ length: 24 }, (_, i) => String(i).padStart(2, '0'));

  _chart = upsertChart(_chart, canvas, {
    type: 'bar',
    data: {
      labels,
      datasets: [{ data: counts, backgroundColor: labels.map((_, h) => (h === f.hour ? COLORS.orange : COLORS.magenta)), borderRadius: 2 }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            title: (items) => `${labels[items[0].dataIndex]}:00–${labels[items[0].dataIndex]}:59 ${getTimeZone() === 'utc' ? 'UTC' : 'local'}`,
            label: (ctx) => ` ${(ctx.raw as number).toLocaleString()} events`,
          },
        },
      },
      scales: {
        x: { ticks: { color: COLORS.muted, font: { size: 10 } }, grid: { color: COLORS.grid } },
        y: { beginAtZero: true, ticks: { color: COLORS.muted }, grid: { color: COLORS.grid } },
      },
      onClick: (_evt, elements) => {
        if (!elements.length) return;
        const hour = elements[0].index;
        setFilter({ hour: f.hour === hour ? null : hour });
        _cb();
      },
    },
  });

  const peak = counts.indexOf(Math.max(...counts));
  describeChart(canvas, `Events by hour of day in ${tzLabel(getTimeZone())}; peak at ${labels[peak]}:00 with ${counts[peak].toLocaleString()} events.`, scoped.length === 0);
}
