import type { Dataset, DecodedEvent, TimeZoneMode } from './types.js';
import { applyTimeZone } from './loader.js';
import { fmtValue } from './format.js';

// ── Fields ──────────────────────────────────────────────────────────────────

/** Filterable fields. `data.<key>` addresses a key in the event payload. */
export type FieldKey = 'ip' | 'action' | 'resource' | 'id' | 'user' | 'type' | 'cat' | `data.${string}`;

export function getField(e: DecodedEvent, field: FieldKey): string | undefined {
  switch (field) {
    case 'ip':
      return e.ip;
    case 'action':
      return e.action;
    case 'resource':
      return e.resource;
    case 'id':
      return e.id;
    case 'user':
      return e.user;
    case 'type':
      return e.type;
    case 'cat':
      return e.cat;
    default: {
      const v = e.data[field.slice(5)];
      return v === undefined || v === null ? undefined : fmtValue(v);
    }
  }
}

const FIELD_LABELS: Record<string, string> = {
  ip: 'IP',
  action: 'Action',
  resource: 'Resource',
  id: 'Event ID',
  user: 'Actor',
  type: 'Event type',
  cat: 'Category',
  'data.status': 'Status',
  'data.projectName': 'Project',
};

export function fieldLabel(field: FieldKey): string {
  return FIELD_LABELS[field] ?? field.replace(/^data\./, '');
}

// ── Filter state ────────────────────────────────────────────────────────────

export interface Facet {
  field: FieldKey;
  value: string;
  /** true = hide events with this value; false = keep only events with it. */
  exclude: boolean;
}

/** A precomputed set of events (from the Highlights panel). */
export interface HighlightFilter {
  id: string;
  label: string;
  ids: Set<number>;
}

export interface FilterState {
  cat: string | null;
  type: string | null;
  user: string | null;
  day: string | null;
  hour: number | null;
  q: string;
  facets: Facet[];
  highlight: HighlightFilter | null;
}

export type DrillLevel = 'category' | 'eventType' | 'actor' | 'leaf';

const EMPTY: FilterState = { cat: null, type: null, user: null, day: null, hour: null, q: '', facets: [], highlight: null };

let _dataset: Dataset | null = null;
let _events: DecodedEvent[] = [];
let _filter: FilterState = { ...EMPTY };
let _tz: TimeZoneMode = 'utc';
/** Comparison: events at/after this instant are the current period, earlier ones the previous. */
let _compareSplit: number | null = null;
/** Bumped on any change (filters, data, time zone, comparison). */
let _version = 0;
/** Bumped only when the data, time zone or comparison changes — not on filter changes. */
let _dataVersion = 0;
const bump = () => {
  _version++;
};
const bumpData = () => {
  _dataVersion++;
  _version++;
};

export function setData(dataset: Dataset, events: DecodedEvent[]): void {
  _dataset = dataset;
  _events = events;
  _filter = { ...EMPTY, facets: [] };
  _compareSplit = null;
  bumpData();
}

export function getDataset(): Dataset | null {
  return _dataset;
}

export function allEvents(): DecodedEvent[] {
  return _events;
}

export function getFilter(): FilterState {
  return { ..._filter, facets: [..._filter.facets] };
}

export function setFilter(update: Partial<FilterState>): void {
  _filter = { ..._filter, ...update };
  bump();
}

export function resetFilter(): void {
  _filter = { ...EMPTY, facets: [] };
  bump();
}

export function isFilterActive(): boolean {
  const f = _filter;
  return !!(f.cat || f.type || f.user || f.day || f.hour !== null || f.q || f.facets.length || f.highlight);
}

/** Add an include/exclude field filter (replacing an existing one for the same field+value). */
export function addFacet(facet: Facet): void {
  const facets = _filter.facets.filter((x) => !(x.field === facet.field && x.value === facet.value));
  // Only one include per field makes sense (AND of two different values is always empty).
  const cleaned = facet.exclude ? facets : facets.filter((x) => !(x.field === facet.field && !x.exclude));
  setFilter({ facets: [...cleaned, facet] });
}

export function removeFacet(index: number): void {
  setFilter({ facets: _filter.facets.filter((_, i) => i !== index) });
}

// ── Time zone & comparison ──────────────────────────────────────────────────

export function getTimeZone(): TimeZoneMode {
  return _tz;
}

/** Switch display time zone. Day/hour filters are cleared because their meaning changes. */
export function setTimeZone(tz: TimeZoneMode): void {
  if (tz === _tz) return;
  _tz = tz;
  applyTimeZone(_events, tz);
  _filter = { ..._filter, day: null, hour: null };
  bumpData();
}

export function getCompareSplit(): number | null {
  return _compareSplit;
}

export function setCompareSplit(split: number | null): void {
  _compareSplit = split;
  _filter = { ..._filter, day: null }; // the selected day may not exist in the new current period
  bumpData();
}

/** Split point that divides the loaded data into two equal whole-day halves (UTC), or null if < 2 days. */
export function midpointSplit(): number | null {
  if (!_dataset?.meta.dateMin) return null;
  const start = Date.parse(_dataset.meta.dateMin + 'T00:00:00Z');
  const end = Date.parse(_dataset.meta.dateMax + 'T00:00:00Z');
  const days = Math.round((end - start) / 86400000) + 1;
  if (days < 2) return null;
  return start + Math.floor(days / 2) * 86400000;
}

/** Events in the current period (all events unless comparing). */
export function periodEvents(): DecodedEvent[] {
  return cachedData('period', () => (_compareSplit === null ? _events : _events.filter((e) => e.epoch >= _compareSplit!)));
}

/** Events in the previous period (empty unless comparing). */
export function previousPeriodEvents(): DecodedEvent[] {
  return cachedData('prev', () => (_compareSplit === null ? [] : _events.filter((e) => e.epoch < _compareSplit!)));
}

// ── Filtering ───────────────────────────────────────────────────────────────

export function matches(e: DecodedEvent, f: FilterState, q = f.q.trim().toLowerCase()): boolean {
  if (f.highlight && !f.highlight.ids.has(e.idx)) return false;
  if (f.cat && e.cat !== f.cat) return false;
  if (f.type && e.type !== f.type) return false;
  if (f.user && e.user !== f.user) return false;
  if (f.day && e.day !== f.day) return false;
  if (f.hour !== null && e.hour !== f.hour) return false;
  for (const facet of f.facets) {
    const has = getField(e, facet.field) === facet.value;
    if (facet.exclude ? has : !has) return false;
  }
  if (q && !e.search.includes(q)) return false;
  return true;
}

/** Filtered events in the current period. Cached until the filter or data changes. */
export function rows(): DecodedEvent[] {
  return memo('rows', () => {
    const f = _filter;
    const q = f.q.trim().toLowerCase();
    return periodEvents().filter((e) => matches(e, f, q));
  });
}

/** Same filters applied to the previous period (for comparison overlays). */
export function previousRows(): DecodedEvent[] {
  return memo('prevRows', () => {
    const f = { ..._filter, day: null }; // a day filter can't apply to the other period
    const q = f.q.trim().toLowerCase();
    return previousPeriodEvents().filter((e) => matches(e, f, q));
  });
}

const _memo = new Map<string, { v: number; value: unknown }>();
function memoAt<T>(key: string, version: number, compute: () => T): T {
  const hit = _memo.get(key);
  if (hit && hit.v === version) return hit.value as T;
  const value = compute();
  _memo.set(key, { v: version, value });
  return value;
}
const memo = <T>(key: string, compute: () => T) => memoAt(key, _version, compute);

/** Cache derived values (sorted rows, chart series) until the filter or data changes. */
export function cached<T>(key: string, compute: () => T): T {
  return memoAt('ext:' + key, _version, compute);
}

/** Cache values that depend only on the data, time zone and comparison (not on filters). */
export function cachedData<T>(key: string, compute: () => T): T {
  return memoAt('data:' + key, _dataVersion, compute);
}

export function countBy<K extends string>(events: DecodedEvent[], key: (e: DecodedEvent) => K): Map<K, number> {
  const map = new Map<K, number>();
  for (const e of events) {
    const k = key(e);
    map.set(k, (map.get(k) ?? 0) + 1);
  }
  return map;
}

export function getDrillLevel(): DrillLevel {
  const f = _filter;
  if (!f.cat) return 'category';
  if (!f.type) return 'eventType';
  if (!f.user) return 'actor';
  return 'leaf';
}

export function scopeSummary(): {
  count: number;
  total: number;
  eventTypes: number;
  namedActors: number;
  activeDays: number;
  dateMin: string;
  dateMax: string;
} {
  const scoped = rows();
  const typeSet = new Set<string>();
  const actorSet = new Set<string>();
  const daySet = new Set<string>();
  let dateMin = '';
  let dateMax = '';

  if (!_dataset) {
    return { count: 0, total: 0, eventTypes: 0, namedActors: 0, activeDays: 0, dateMin: '', dateMax: '' };
  }

  for (const e of scoped) {
    typeSet.add(e.type);
    if (_dataset.named[e.userIdx]) actorSet.add(e.user);
    daySet.add(e.day);
    if (!dateMin || e.day < dateMin) dateMin = e.day;
    if (!dateMax || e.day > dateMax) dateMax = e.day;
  }

  return {
    count: scoped.length,
    total: periodEvents().length,
    eventTypes: typeSet.size,
    namedActors: actorSet.size,
    activeDays: daySet.size,
    dateMin,
    dateMax,
  };
}
