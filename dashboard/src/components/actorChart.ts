import {
  Chart,
  BarController,
  BarElement,
  CategoryScale,
  LinearScale,
  Tooltip,
} from 'chart.js';
import { rows, setFilter, getFilter, countBy } from '../state.js';
import { getDataset } from '../state.js';
import { truncate } from './chartUtils.js';

Chart.register(BarController, BarElement, CategoryScale, LinearScale, Tooltip);

let _chart: Chart | null = null;
let _cb: () => void = () => {};

export function initActorChart(cb: () => void): void {
  _cb = cb;
}

export function renderActorChart(): void {
  const canvas = document.getElementById('actor-canvas') as HTMLCanvasElement | null;
  if (!canvas) return;

  const ds = getDataset();
  if (!ds) return;

  const f = getFilter();
  const scoped = rows();

  // Only named actors
  const named = new Set(
    ds.users.filter((_, i) => ds.named[i] === 1)
  );

  const counts = countBy(scoped, (e) => e.user);
  const entries = Array.from(counts.entries())
    .filter(([u]) => named.has(u))
    .sort((a, b) => b[1] - a[1])
    .slice(0, 12);

  if (_chart) {
    _chart.destroy();
    _chart = null;
  }

  const ctx = canvas.getContext('2d')!;
  const labels = entries.map(([k]) => k);
  const values = entries.map(([, v]) => v);
  const colors = labels.map((l) =>
    l === f.user ? '#F25929' : '#6B34FD'
  );

  _chart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: labels.map((l) => truncate(l, 25)),
      datasets: [{ data: values, backgroundColor: colors, borderRadius: 4 }],
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            title: (items) => labels[items[0].dataIndex] ?? '',
            label: (ctx) => ` ${(ctx.raw as number).toLocaleString()} events`,
          },
        },
      },
      scales: {
        x: { ticks: { color: '#a99fc0' }, grid: { color: '#3a2a52' } },
        y: { ticks: { color: '#FCF9FE', font: { size: 11 } } },
      },
      onClick: (_evt, elements) => {
        if (!elements.length) return;
        const idx = elements[0].index;
        const user = labels[idx];
        setFilter({ user: f.user === user ? null : user });
        _cb();
      },
    },
  });
}
