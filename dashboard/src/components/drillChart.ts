import {
  Chart,
  DoughnutController,
  BarController,
  ArcElement,
  BarElement,
  CategoryScale,
  LinearScale,
  Tooltip,
  Legend,
} from 'chart.js';
import { rows, getDrillLevel, setFilter, countBy, getFilter } from '../state.js';
import { CAT_COLORS, truncate } from './chartUtils.js';

Chart.register(DoughnutController, BarController, ArcElement, BarElement, CategoryScale, LinearScale, Tooltip, Legend);

let _chart: Chart | null = null;
let _cb: () => void = () => {};

export function initDrillChart(cb: () => void): void {
  _cb = cb;
}

export function renderDrillChart(): void {
  const canvas = document.getElementById('drill-canvas') as HTMLCanvasElement | null;
  const titleEl = document.getElementById('drill-title');
  const hintEl = document.getElementById('drill-hint');
  if (!canvas) return;

  const level = getDrillLevel();
  const f = getFilter();

  let title = '';
  let hint = '';
  let labels: string[] = [];
  let values: number[] = [];
  let colors: string[] = [];
  let chartType: 'doughnut' | 'bar' = 'doughnut';

  const scopedRows = rows();

  if (level === 'category') {
    title = 'Events by Category';
    hint = 'Click a slice to drill into a category.';
    chartType = 'doughnut';
    const counts = countBy(scopedRows, (e) => e.cat);
    const entries = Array.from(counts.entries()).sort((a, b) => b[1] - a[1]).slice(0, 8);
    labels = entries.map(([k]) => k);
    values = entries.map(([, v]) => v);
    colors = labels.map((l) => CAT_COLORS[l] ?? '#a99fc0');
  } else if (level === 'eventType') {
    title = `Event Types in "${f.cat}"`;
    hint = 'Click a bar to drill into an event type.';
    chartType = 'bar';
    const counts = countBy(scopedRows, (e) => e.type);
    const entries = Array.from(counts.entries()).sort((a, b) => b[1] - a[1]).slice(0, 14);
    labels = entries.map(([k]) => k);
    values = entries.map(([, v]) => v);
    colors = labels.map(() => CAT_COLORS[f.cat ?? ''] ?? '#a99fc0');
  } else if (level === 'actor') {
    title = `Actors for "${f.type}"`;
    hint = 'Click a bar to filter by actor.';
    chartType = 'bar';
    const counts = countBy(scopedRows, (e) => e.user);
    const entries = Array.from(counts.entries()).sort((a, b) => b[1] - a[1]).slice(0, 14);
    labels = entries.map(([k]) => k);
    values = entries.map(([, v]) => v);
    colors = labels.map(() => CAT_COLORS[f.cat ?? ''] ?? '#a99fc0');
  } else {
    // leaf: actor's event-type mix
    title = `${f.user}'s Event Types`;
    hint = 'Click a bar to switch event type.';
    chartType = 'bar';
    const counts = countBy(scopedRows, (e) => e.type);
    const entries = Array.from(counts.entries()).sort((a, b) => b[1] - a[1]).slice(0, 14);
    labels = entries.map(([k]) => k);
    values = entries.map(([, v]) => v);
    colors = labels.map((l) => {
      // color by category of that event type
      for (const e of scopedRows) {
        if (e.type === l) return CAT_COLORS[e.cat] ?? '#a99fc0';
      }
      return '#a99fc0';
    });
  }

  if (titleEl) titleEl.textContent = title;
  if (hintEl) hintEl.textContent = hint;

  if (_chart) {
    _chart.destroy();
    _chart = null;
  }

  const ctx = canvas.getContext('2d')!;

  const truncatedLabels = labels.map((l) => truncate(l, 30));

  if (chartType === 'doughnut') {
    _chart = new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: truncatedLabels,
        datasets: [{ data: values, backgroundColor: colors, borderColor: '#140921', borderWidth: 2 }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { position: 'right', labels: { color: '#FCF9FE', font: { size: 12 } } },
          tooltip: { callbacks: { label: (ctx) => ` ${ctx.label}: ${(ctx.raw as number).toLocaleString()}` } },
        },
        onClick: (_evt, elements) => {
          if (!elements.length) return;
          const idx = elements[0].index;
          setFilter({ cat: labels[idx], type: null, user: null, day: null });
          _cb();
        },
      },
    });
  } else {
    _chart = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: truncatedLabels,
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
          if (level === 'eventType') {
            setFilter({ type: labels[idx], day: null });
          } else if (level === 'actor') {
            setFilter({ user: labels[idx], day: null });
          } else if (level === 'leaf') {
            setFilter({ type: labels[idx] });
          }
          _cb();
        },
      },
    });
  }
}
