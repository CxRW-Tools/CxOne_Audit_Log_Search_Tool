// Filters (and, in --serve mode, the query) in the URL hash, so a view can be bookmarked or
// shared. The data itself is never put in the URL.
import type { Facet, FieldKey, FilterState } from './state.js';
import type { TimeZoneMode } from './types.js';

export interface UrlState {
  filter: Partial<Omit<FilterState, 'highlight'>> & { highlightId?: string };
  tz?: TimeZoneMode;
  compare?: boolean;
  query?: { start: string; end: string; search: string; humanReadable: boolean; compare: boolean };
}

export function encodeUrlState(s: UrlState): string {
  const p = new URLSearchParams();
  const f = s.filter;
  if (f.cat) p.set('cat', f.cat);
  if (f.type) p.set('type', f.type);
  if (f.user) p.set('user', f.user);
  if (f.day) p.set('day', f.day);
  if (f.hour !== undefined && f.hour !== null) p.set('hour', String(f.hour));
  if (f.q) p.set('q', f.q);
  for (const facet of f.facets ?? []) p.append(facet.exclude ? 'not' : 'only', `${facet.field}=${facet.value}`);
  if (f.highlightId) p.set('hl', f.highlightId);
  if (s.tz && s.tz !== 'utc') p.set('tz', s.tz);
  if (s.compare) p.set('compare', '1');
  if (s.query) {
    p.set('qs', s.query.start);
    p.set('qe', s.query.end);
    if (s.query.search) p.set('qq', s.query.search);
    if (!s.query.humanReadable) p.set('qhr', '0');
    if (s.query.compare) p.set('qc', '1');
  }
  const str = p.toString();
  return str ? '#' + str : '';
}

export function decodeUrlState(hash: string): UrlState {
  const p = new URLSearchParams(hash.replace(/^#/, ''));
  const facets: Facet[] = [];
  for (const [k, v] of p) {
    if (k !== 'only' && k !== 'not') continue;
    const i = v.indexOf('=');
    if (i > 0) facets.push({ field: v.slice(0, i) as FieldKey, value: v.slice(i + 1), exclude: k === 'not' });
  }
  const hour = p.get('hour');
  const tz = p.get('tz');
  const s: UrlState = {
    filter: {
      cat: p.get('cat'),
      type: p.get('type'),
      user: p.get('user'),
      day: p.get('day'),
      hour: hour !== null && /^\d{1,2}$/.test(hour) && +hour < 24 ? +hour : null,
      q: p.get('q') ?? '',
      facets,
      highlightId: p.get('hl') ?? undefined,
    },
    tz: tz === 'local' ? 'local' : 'utc',
    compare: p.get('compare') === '1',
  };
  const qs = p.get('qs');
  const qe = p.get('qe');
  if (qs && qe && /^\d{4}-\d{2}-\d{2}$/.test(qs) && /^\d{4}-\d{2}-\d{2}$/.test(qe)) {
    s.query = { start: qs, end: qe, search: p.get('qq') ?? '', humanReadable: p.get('qhr') !== '0', compare: p.get('qc') === '1' };
  }
  return s;
}
