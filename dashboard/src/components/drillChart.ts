import type { Chart } from 'chart.js';
import { rows, getDrillLevel, setFilter, countBy, getFilter, getDataset } from '../state.js';
import { actorShort } from '../format.js';
import { CAT_COLORS, COLORS, axisStyle, describeChart, restTooltip, summarize, topWithRest, truncate, upsertChart, type Bucket } from './chartUtils.js';

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
  const scoped = rows();
  const ds = getDataset();
  const catOfType = new Map<string, string>();
  if (ds) ds.types.forEach((t, i) => catOfType.set(t, ds.cats[ds.typeCat[i]]));

  let title: string;
  let hint: string;
  let buckets: Bucket[];
  let colors: string[];
  const doughnut = level === 'category';

  if (level === 'category') {
    title = 'Events by Category';
    hint = 'Click a slice or legend entry to drill into a category.';
    buckets = topWithRest(countBy(scoped, (e) => e.cat), 8);
    colors = buckets.map((b) => (b.key ? CAT_COLORS[b.key] ?? COLORS.muted : COLORS.rest));
  } else if (level === 'eventType') {
    title = `Event Types in "${f.cat}"`;
    hint = 'Click a bar to drill into an event type.';
    buckets = topWithRest(countBy(scoped, (e) => e.type), 14);
    colors = buckets.map((b) => (b.key ? CAT_COLORS[f.cat ?? ''] ?? COLORS.muted : COLORS.rest));
  } else if (level === 'actor') {
    title = `Actors for "${f.type}"`;
    hint = 'Click a bar to filter by actor.';
    buckets = topWithRest(countBy(scoped, (e) => e.user), 14, (k) => actorShort(k, 30));
    colors = buckets.map((b) => (b.key ? CAT_COLORS[f.cat ?? ''] ?? COLORS.muted : COLORS.rest));
  } else {
    title = `Event Types for ${actorShort(f.user ?? '', 40)}`;
    hint = 'Click a bar to switch event type.';
    buckets = topWithRest(countBy(scoped, (e) => e.type), 14);
    colors = buckets.map((b) => (b.key ? CAT_COLORS[catOfType.get(b.key) ?? ''] ?? COLORS.muted : COLORS.rest));
  }
  if (buckets.some((b) => !b.key)) hint += ' "Other" groups the smaller entries.';

  if (titleEl) titleEl.textContent = title;
  if (hintEl) hintEl.textContent = hint;

  const select = (b: Bucket | undefined) => {
    if (!b?.key) return; // "Other" isn't a single value
    if (level === 'category') setFilter({ cat: b.key, type: null, user: null, day: null });
    else if (level === 'eventType') setFilter({ type: b.key, day: null });
    else if (level === 'actor') setFilter({ user: b.key, day: null });
    else setFilter({ type: b.key, cat: catOfType.get(b.key) ?? f.cat });
    _cb();
  };

  const tooltip = {
    callbacks: {
      title: (items: { dataIndex: number }[]) => buckets[items[0].dataIndex]?.key ?? buckets[items[0].dataIndex]?.label ?? '',
      label: (ctx: { raw: unknown }) => ` ${(ctx.raw as number).toLocaleString()} events`,
      afterBody: (items: { dataIndex: number }[]) => restTooltip(buckets[items[0].dataIndex]),
    },
  };

  _chart = upsertChart(_chart, canvas, doughnut
    ? {
        type: 'doughnut',
        data: {
          labels: buckets.map((b) => truncate(b.label, 30)),
          datasets: [{ data: buckets.map((b) => b.value), backgroundColor: colors, borderColor: '#140921', borderWidth: 2 }],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          animation: false,
          plugins: {
            legend: {
              position: 'right',
              labels: { color: COLORS.text, font: { size: 12 } },
              // Legend clicks filter like slice clicks (Chart.js would hide the slice instead).
              onClick: (_e, item) => select(buckets[item.index ?? -1]),
            },
            tooltip,
          },
          onClick: (_evt, elements) => elements.length && select(buckets[elements[0].index]),
        },
      }
    : {
        type: 'bar',
        data: {
          labels: buckets.map((b) => truncate(b.label, 30)),
          datasets: [{ data: buckets.map((b) => b.value), backgroundColor: colors, borderRadius: 4 }],
        },
        options: {
          indexAxis: 'y',
          responsive: true,
          maintainAspectRatio: false,
          animation: false,
          plugins: { legend: { display: false }, tooltip },
          scales: axisStyle,
          onClick: (_evt, elements) => elements.length && select(buckets[elements[0].index]),
        },
      });

  describeChart(canvas, `${title}: ${summarize(buckets)}`, scoped.length === 0);
}
