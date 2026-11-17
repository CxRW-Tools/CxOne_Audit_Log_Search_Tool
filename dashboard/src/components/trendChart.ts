import type { Chart } from 'chart.js';
import { rows, setFilter, getFilter, periodEvents, previousRows, previousPeriodEvents, getCompareSplit } from '../state.js';
import { COLORS, allDaysInRange, describeChart, upsertChart } from './chartUtils.js';

let _chart: Chart | null = null;
let _cb: () => void = () => {};

export function initTrendChart(cb: () => void): void {
  _cb = cb;
}

function dayRange(events: { day: string }[]): string[] {
  let min = '';
  let max = '';
  for (const e of events) {
    if (!min || e.day < min) min = e.day;
    if (!max || e.day > max) max = e.day;
  }
  return allDaysInRange(min, max);
}

export function renderTrendChart(): void {
  const canvas = document.getElementById('trend-canvas') as HTMLCanvasElement | null;
  const hintEl = document.getElementById('trend-hint');
  if (!canvas) return;

  const f = getFilter();
  const scoped = rows();
  // X axis spans the whole current period (not just days that have matching events).
  const days = dayRange(periodEvents());
  const countMap = new Map<string, number>(days.map((d) => [d, 0]));
  for (const e of scoped) countMap.set(e.day, (countMap.get(e.day) ?? 0) + 1);
  const values = days.map((d) => countMap.get(d) ?? 0);
  const colors = days.map((d) => (d === f.day ? COLORS.orange : COLORS.violet));

  const comparing = getCompareSplit() !== null;
  const datasets: NonNullable<Parameters<typeof upsertChart>[2]['data']>['datasets'] = [
    { type: 'bar', label: 'Current period', data: values, backgroundColor: colors, borderRadius: 2, order: 2 },
  ];
  if (comparing) {
    // Previous period aligned day-by-day (day 1 vs day 1, …).
    const prevDays = dayRange(previousPeriodEvents());
    const prevMap = new Map<string, number>(prevDays.map((d) => [d, 0]));
    for (const e of previousRows()) prevMap.set(e.day, (prevMap.get(e.day) ?? 0) + 1);
    const offset = Math.max(0, prevDays.length - days.length);
    datasets.push({
      type: 'line',
      label: 'Previous period',
      data: days.map((_, i) => prevMap.get(prevDays[i + offset]) ?? null) as number[],
      borderColor: COLORS.previous,
      backgroundColor: COLORS.previous,
      borderDash: [4, 3],
      borderWidth: 1.5,
      pointRadius: 0,
      tension: 0.2,
      order: 1,
    });
  }

  if (hintEl) {
    hintEl.textContent = comparing
      ? 'Daily volume; dashed line is the previous period, aligned by day. Click a bar to filter by day.'
      : 'Daily event volume. Click a bar to filter by day.';
  }

  _chart = upsertChart(_chart, canvas, {
    type: 'bar',
    data: { labels: days, datasets },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: false,
      plugins: {
        legend: { display: comparing, labels: { color: COLORS.text, boxWidth: 12 } },
        tooltip: {
          mode: 'index',
          intersect: false,
          callbacks: { label: (ctx) => ` ${ctx.dataset.label}: ${((ctx.raw as number) ?? 0).toLocaleString()} events` },
        },
      },
      scales: {
        x: { ticks: { color: COLORS.muted, maxTicksLimit: 15, maxRotation: 45 }, grid: { color: COLORS.grid } },
        y: { beginAtZero: true, ticks: { color: COLORS.muted }, grid: { color: COLORS.grid } },
      },
      onClick: (_evt, elements) => {
        const bar = elements.find((el) => el.datasetIndex === 0) ?? elements[0];
        if (!bar) return;
        const day = days[bar.index];
        setFilter({ day: f.day === day ? null : day });
        _cb();
      },
    },
  });

  const busiest = days.reduce((best, d, i) => (values[i] > (countMap.get(best) ?? -1) ? d : best), days[0] ?? '');
  describeChart(
    canvas,
    `Activity timeline: ${scoped.length.toLocaleString()} events over ${days.length} days; busiest day ${busiest} with ${(countMap.get(busiest) ?? 0).toLocaleString()}.`,
    scoped.length === 0,
  );
}
