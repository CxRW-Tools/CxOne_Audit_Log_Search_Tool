import {
  Chart,
  BarController,
  BarElement,
  CategoryScale,
  LinearScale,
  Tooltip,
} from 'chart.js';
import { rows, setFilter, getFilter, getDataset } from '../state.js';
import { allDaysInRange } from './chartUtils.js';

Chart.register(BarController, BarElement, CategoryScale, LinearScale, Tooltip);

let _chart: Chart | null = null;
let _cb: () => void = () => {};

export function initTrendChart(cb: () => void): void {
  _cb = cb;
}

export function renderTrendChart(): void {
  const canvas = document.getElementById('trend-canvas') as HTMLCanvasElement | null;
  if (!canvas) return;

  const ds = getDataset();
  if (!ds) return;

  const f = getFilter();
  const scoped = rows();

  const days = allDaysInRange(ds.meta.dateMin, ds.meta.dateMax);
  const countMap = new Map<string, number>();
  for (const d of days) countMap.set(d, 0);
  for (const e of scoped) countMap.set(e.day, (countMap.get(e.day) ?? 0) + 1);

  const values = days.map((d) => countMap.get(d) ?? 0);
  const colors = days.map((d) => (d === f.day ? '#F25929' : '#6B34FD'));

  if (_chart) {
    _chart.destroy();
    _chart = null;
  }

  const ctx = canvas.getContext('2d')!;

  _chart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: days,
      datasets: [{ data: values, backgroundColor: colors, borderRadius: 2 }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label: (ctx) => ` ${(ctx.raw as number).toLocaleString()} events`,
          },
        },
      },
      scales: {
        x: {
          ticks: {
            color: '#a99fc0',
            maxTicksLimit: 15,
            maxRotation: 45,
          },
          grid: { color: '#3a2a52' },
        },
        y: { ticks: { color: '#a99fc0' }, grid: { color: '#3a2a52' } },
      },
      onClick: (_evt, elements) => {
        if (!elements.length) return;
        const idx = elements[0].index;
        const day = days[idx];
        setFilter({ day: f.day === day ? null : day });
        _cb();
      },
    },
  });
}
