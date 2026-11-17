import type { Chart } from 'chart.js';
import { rows, setFilter, getFilter, countBy, getDataset } from '../state.js';
import { actorShort } from '../format.js';
import { isNamed } from '../parser.js';
import { COLORS, axisStyle, describeChart, restTooltip, summarize, topWithRest, upsertChart } from './chartUtils.js';

let _chart: Chart | null = null;
let _cb: () => void = () => {};

export function initActorChart(cb: () => void): void {
  _cb = cb;
}

export function renderActorChart(): void {
  const canvas = document.getElementById('actor-canvas') as HTMLCanvasElement | null;
  const hintEl = document.getElementById('actor-hint');
  if (!canvas || !getDataset()) return;

  const f = getFilter();
  const scoped = rows();
  const counts = countBy(scoped, (e) => e.user);
  const buckets = topWithRest(counts, 12, (k) => actorShort(k, 26));
  const anyNamed = buckets.some((b) => b.key && isNamed(b.key));

  // Unresolved IDs and system are included (muted) so the chart is never silently empty.
  const colors = buckets.map((b) => {
    if (!b.key) return COLORS.rest;
    if (b.key === f.user) return COLORS.orange;
    return isNamed(b.key) ? COLORS.violet : COLORS.muted;
  });

  if (hintEl) {
    hintEl.textContent = !scoped.length
      ? 'Actors by event count.'
      : anyNamed
        ? 'Actors by event count. Click to filter; grey bars are unresolved IDs or system.'
        : 'Names weren’t resolved, so actors are user IDs. Re-run with “Resolve names” (or --human-readable) to see names.';
  }

  _chart = upsertChart(_chart, canvas, {
    type: 'bar',
    data: {
      labels: buckets.map((b) => b.label),
      datasets: [{ data: buckets.map((b) => b.value), backgroundColor: colors, borderRadius: 4 }],
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: false,
      animation: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            title: (items) => buckets[items[0].dataIndex]?.key ?? buckets[items[0].dataIndex]?.label ?? '',
            label: (ctx) => ` ${(ctx.raw as number).toLocaleString()} events`,
            afterBody: (items) => restTooltip(buckets[items[0].dataIndex]),
          },
        },
      },
      scales: axisStyle,
      onClick: (_evt, elements) => {
        const b = elements.length ? buckets[elements[0].index] : undefined;
        if (!b?.key) return;
        setFilter({ user: f.user === b.key ? null : b.key });
        _cb();
      },
    },
  });

  describeChart(canvas, `Top actors: ${summarize(buckets)}`, scoped.length === 0);
}
