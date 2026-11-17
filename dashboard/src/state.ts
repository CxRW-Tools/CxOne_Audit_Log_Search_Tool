import type { Dataset, DecodedEvent } from './types.js';

export interface FilterState {
  cat: string | null;
  type: string | null;
  user: string | null;
  day: string | null;
  q: string;
}

export type DrillLevel = 'category' | 'eventType' | 'actor' | 'leaf';

let _dataset: Dataset | null = null;
let _events: DecodedEvent[] = [];
let _filter: FilterState = { cat: null, type: null, user: null, day: null, q: '' };

export function setData(dataset: Dataset, events: DecodedEvent[]): void {
  _dataset = dataset;
  _events = events;
  _filter = { cat: null, type: null, user: null, day: null, q: '' };
}

export function getDataset(): Dataset | null {
  return _dataset;
}

export function getFilter(): FilterState {
  return { ..._filter };
}

export function setFilter(update: Partial<FilterState>): void {
  _filter = { ..._filter, ...update };
}

export function resetFilter(): void {
  _filter = { cat: null, type: null, user: null, day: null, q: '' };
}

export function isFilterActive(): boolean {
  return !!(
    _filter.cat || _filter.type || _filter.user || _filter.day || _filter.q
  );
}

export type ExceptDim = 'cat' | 'type' | 'user' | 'day' | null;

function matchesSearch(e: DecodedEvent, q: string): boolean {
  const lower = q.toLowerCase();
  return (
    e.type.toLowerCase().includes(lower) ||
    e.cat.toLowerCase().includes(lower) ||
    e.user.toLowerCase().includes(lower) ||
    JSON.stringify(e.data).toLowerCase().includes(lower)
  );
}

export function rows(except: ExceptDim = null): DecodedEvent[] {
  return _events.filter((e) => {
    if (except !== 'cat' && _filter.cat && e.cat !== _filter.cat) return false;
    if (except !== 'type' && _filter.type && e.type !== _filter.type) return false;
    if (except !== 'user' && _filter.user && e.user !== _filter.user) return false;
    if (except !== 'day' && _filter.day && e.day !== _filter.day) return false;
    if (_filter.q && !matchesSearch(e, _filter.q)) return false;
    return true;
  });
}

export function countBy<K extends string>(
  events: DecodedEvent[],
  key: (e: DecodedEvent) => K,
  topN?: number
): Map<K, number> {
  const map = new Map<K, number>();
  for (const e of events) {
    const k = key(e);
    map.set(k, (map.get(k) ?? 0) + 1);
  }
  if (topN !== undefined) {
    // Keep only top N by count
    const sorted = Array.from(map.entries()).sort((a, b) => b[1] - a[1]);
    return new Map(sorted.slice(0, topN));
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
    total: _dataset.meta.total,
    eventTypes: typeSet.size,
    namedActors: actorSet.size,
    activeDays: daySet.size,
    dateMin,
    dateMax,
  };
}
