import type { DecodedEvent } from '../types.js';
import { getFilter, setFilter, resetFilter, periodEvents, previousPeriodEvents, getCompareSplit, getField, type Facet, type FilterState } from '../state.js';
import { categoryFor } from '../parser.js';
import { esc } from '../format.js';

type Callback = () => void;
let _cb: Callback = () => {};
let _wired = false;

/**
 * Each card is an exact predicate. The same definition drives the count and the filter the
 * card applies, so the number on the card always matches the events it shows.
 */
interface KpiDef {
  key: string;
  label: string;
  cls: string;
  type?: string;
  facet?: Facet;
  /** Rising is bad (failures, downloads): colours the delta. */
  upIsBad?: boolean;
  alertCls?: string;
  sub?: (events: DecodedEvent[]) => string;
}

const KPIS: KpiDef[] = [
  { key: 'total', label: 'Total Events', cls: 'kpi-total' },
  { key: 'scans', label: 'Scans Created', cls: 'kpi-scans', type: 'scans.create' },
  { key: 'projects', label: 'Projects Created', cls: 'kpi-projects', type: 'projects.create' },
  {
    key: 'logins',
    label: 'Logins',
    cls: 'kpi-logins',
    type: 'users.login',
    sub: (evs) => `${evs.filter((e) => e.data.status === 'OK').length.toLocaleString()} successful`,
  },
  {
    key: 'failed-logins',
    label: 'Failed Logins',
    cls: 'kpi-logins',
    type: 'users.login',
    facet: { field: 'data.status', value: 'FAIL', exclude: false },
    upIsBad: true,
    alertCls: 'kpi-warn',
  },
  { key: 'downloads', label: 'Source-Code Downloads', cls: 'kpi-downloads', type: 'source-code.download', upIsBad: true, alertCls: 'kpi-alert' },
];

function predicate(def: KpiDef): (e: DecodedEvent) => boolean {
  return (e) => (!def.type || e.type === def.type) && (!def.facet || getField(e, def.facet.field) === def.facet.value);
}

function isActive(def: KpiDef, f: FilterState): boolean {
  const facetMatch = def.facet
    ? f.facets.length === 1 && f.facets[0].field === def.facet.field && f.facets[0].value === def.facet.value && !f.facets[0].exclude
    : f.facets.length === 0;
  const noExtra = !f.user && !f.day && f.hour === null && !f.q && !f.highlight;
  if (!def.type) return !f.cat && !f.type && facetMatch && noExtra;
  return f.type === def.type && facetMatch && noExtra;
}

function delta(current: number, previous: number, upIsBad: boolean): string {
  if (!previous && !current) return `<div class="kpi-delta">no change vs previous</div>`;
  if (!previous) return `<div class="kpi-delta ${upIsBad ? 'delta-bad' : 'delta-up'}">new vs previous (0)</div>`;
  const change = ((current - previous) / previous) * 100;
  const rounded = Math.round(change);
  const dir = rounded > 0 ? 'up' : rounded < 0 ? 'down' : 'flat';
  const cls = dir === 'flat' ? '' : (dir === 'up') === upIsBad ? 'delta-bad' : 'delta-good';
  const arrow = dir === 'up' ? '▲' : dir === 'down' ? '▼' : '■';
  return `<div class="kpi-delta ${cls}" title="Previous period: ${previous.toLocaleString()}">${arrow} ${Math.abs(rounded)}% vs previous (${previous.toLocaleString()})</div>`;
}

export function initKpis(cb: Callback): void {
  _cb = cb;
  const el = document.getElementById('kpis');
  if (!el || _wired) return;
  _wired = true;
  el.addEventListener('click', (ev) => {
    const card = (ev.target as HTMLElement).closest<HTMLElement>('[data-kpi]');
    if (!card) return;
    const def = KPIS.find((k) => k.key === card.dataset.kpi)!;
    const f = getFilter();
    resetFilter();
    if (!isActive(def, f) && def.type) {
      setFilter({ cat: categoryFor(def.type), type: def.type, facets: def.facet ? [def.facet] : [] });
    }
    _cb();
  });
}

export function renderKpis(): void {
  const el = document.getElementById('kpis');
  if (!el) return;
  const f = getFilter();
  const current = periodEvents();
  const comparing = getCompareSplit() !== null;
  const previous = comparing ? previousPeriodEvents() : [];

  el.innerHTML = KPIS.map((def) => {
    const pred = predicate(def);
    const matched = current.filter(pred);
    const n = matched.length;
    const active = isActive(def, f);
    const cls = [def.cls, def.alertCls && n > 0 ? def.alertCls : '', active ? 'kpi-active' : ''].filter(Boolean).join(' ');
    const title = def.type ? `${active ? 'Clear filter' : 'Filter to'} ${def.type}${def.facet ? ` with ${def.facet.field.replace('data.', '')} = ${def.facet.value}` : ''}` : 'Show all events';
    return `
      <button type="button" class="kpi-card ${cls}" data-kpi="${def.key}" aria-pressed="${active}" title="${esc(title)}">
        <span class="kpi-label">${esc(def.label)}</span>
        <span class="kpi-value">${n.toLocaleString()}</span>
        ${def.sub ? `<span class="kpi-sub">${esc(def.sub(matched))}</span>` : ''}
        ${comparing ? delta(n, previous.filter(pred).length, !!def.upIsBad) : ''}
      </button>`;
  }).join('');
}
