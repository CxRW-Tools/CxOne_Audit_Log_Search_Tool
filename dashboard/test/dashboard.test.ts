import { describe, it, expect, beforeEach } from 'vitest';
import { datasetFromApiEvents, parseCsvExport } from '../src/apiExport';
import { decodeDataset } from '../src/loader';
import {
  setData,
  rows,
  setFilter,
  resetFilter,
  addFacet,
  removeFacet,
  getFilter,
  periodEvents,
  previousPeriodEvents,
  previousRows,
  setCompareSplit,
  midpointSplit,
  setTimeZone,
  getField,
  isFilterActive,
} from '../src/state';
import { computeHighlights, densestBurst } from '../src/highlights';
import { toCsv, toApiEvent, csvCell, toJson } from '../src/export';
import { encodeUrlState, decodeUrlState } from '../src/urlState';
import { topWithRest } from '../src/components/chartUtils';
import { fmtValue, splitActor, actorShort, fmtTimestamp } from '../src/format';
import type { DecodedEvent } from '../src/types';

// ── Fixture: API-shaped events ──────────────────────────────────────────────
const U = { jane: 'Jane Doe (jdoe)', raj: 'Raj Patel (rpatel)', id: '3f2a91bc-1111-2222-3333-444455556666' };
let n = 0;
const ev = (date: string, type: string, user: string, data: Record<string, unknown> = {}, ip?: string) => ({
  eventID: `e${n++}`,
  eventDate: date,
  eventType: type,
  actionType: type.split('.')[1],
  auditResource: type.split('.')[0],
  actionUserId: user,
  ...(ip ? { ipAddress: ip } : {}),
  data,
});

function load(items: ReturnType<typeof ev>[]): DecodedEvent[] {
  const ds = datasetFromApiEvents(items, 'acme');
  const events = decodeDataset(ds);
  setData(ds, events);
  return events;
}

const BASE = [
  ev('2026-11-10T09:00:00Z', 'users.login', U.jane, { status: 'OK' }, '10.0.0.1'),
  ev('2026-11-10T10:00:00Z', 'users.login', U.raj, { status: 'FAIL' }, '10.0.0.9'),
  ev('2026-11-11T11:00:00Z', 'users.login', U.raj, { status: 'FAILED_OTHER', note: 'contains FAIL text' }, '10.0.0.9'),
  ev('2026-11-12T12:00:00Z', 'scans.create', U.jane, { projectName: 'alpha', engines: ['sast', 'sca'] }),
  ev('2026-11-13T23:30:00Z', 'projects.create', U.id, { projectName: 'beta' }),
  ev('2026-11-13T08:00:00Z', 'source-code.download', U.jane, { projectName: 'alpha' }, '10.0.0.1'),
];

describe('filter state', () => {
  beforeEach(() => load(BASE));

  it('field filters match exact values (fixes the FAIL text-search mismatch)', () => {
    setFilter({ type: 'users.login' });
    addFacet({ field: 'data.status', value: 'FAIL', exclude: false });
    expect(rows().map((e) => e.data.status)).toEqual(['FAIL']); // not FAILED_OTHER / "contains FAIL text"
  });

  it('exclude filters remove matching events', () => {
    addFacet({ field: 'user', value: U.jane, exclude: true });
    expect(rows().every((e) => e.user !== U.jane)).toBe(true);
    expect(rows().length).toBe(3);
    removeFacet(0);
    expect(rows().length).toBe(6);
  });

  it('a second include on the same field replaces the first', () => {
    addFacet({ field: 'data.projectName', value: 'alpha', exclude: false });
    addFacet({ field: 'data.projectName', value: 'beta', exclude: false });
    expect(getFilter().facets).toEqual([{ field: 'data.projectName', value: 'beta', exclude: false }]);
  });

  it('IP and array values are filterable', () => {
    addFacet({ field: 'ip', value: '10.0.0.9', exclude: false });
    expect(rows().length).toBe(2);
    resetFilter();
    expect(getField(rows().find((e) => e.type === 'scans.create')!, 'data.engines')).toBe('sast, sca');
  });

  it('search is case-insensitive and covers usernames and IPs', () => {
    setFilter({ q: 'RPATEL' });
    expect(rows().length).toBe(2);
    setFilter({ q: '10.0.0.1' });
    expect(rows().length).toBe(2);
  });

  it('hour and highlight filters', () => {
    setFilter({ hour: 23 });
    expect(rows().map((e) => e.type)).toEqual(['projects.create']);
    resetFilter();
    const ids = new Set(rows().filter((e) => e.user === U.raj).map((e) => e.idx));
    setFilter({ highlight: { id: 'x', label: 'x', ids } });
    expect(rows().length).toBe(2);
    expect(isFilterActive()).toBe(true);
  });

  it('rows() is cached until the filter changes', () => {
    const a = rows();
    expect(rows()).toBe(a);
    setFilter({ q: 'alpha' });
    expect(rows()).not.toBe(a);
  });
});

describe('time zone', () => {
  it('day/hour follow the selected zone; day/hour filters reset', () => {
    const events = load([ev('2026-11-13T23:30:00Z', 'a.b', U.jane)]);
    expect(events[0].day).toBe('2026-11-13');
    expect(events[0].hour).toBe(23);
    setFilter({ hour: 23 });
    setTimeZone('local');
    const d = new Date(Date.UTC(2026, 10, 13, 23, 30));
    expect(events[0].hour).toBe(d.getHours());
    expect(getFilter().hour).toBeNull();
    expect(fmtTimestamp(events[0], 'utc')).toBe('2026-11-13 23:30:00 UTC');
    setTimeZone('utc');
  });
});

describe('comparison', () => {
  it('splits into current and previous periods', () => {
    load(BASE); // 2026-11-10 → 2026-11-13: 4 days
    const split = midpointSplit()!;
    expect(new Date(split).toISOString().slice(0, 10)).toBe('2026-11-12');
    setCompareSplit(split);
    expect(periodEvents().length).toBe(3);
    expect(previousPeriodEvents().length).toBe(3);
    setFilter({ type: 'users.login' });
    expect(rows().length).toBe(0);
    expect(previousRows().length).toBe(3);
    setCompareSplit(null);
    expect(periodEvents().length).toBe(6);
  });

  it('needs at least two days', () => {
    load([ev('2026-11-10T09:00:00Z', 'a.b', U.jane)]);
    expect(midpointSplit()).toBeNull();
  });
});

describe('highlights', () => {
  it('flags success after repeated failures, spraying, admin grants, deletions and off-hours', () => {
    const items = [
      ...Array.from({ length: 6 }, (_, i) => ev(`2026-11-10T10:0${i}:00Z`, 'users.login', U.raj, { status: 'FAIL' }, '1.2.3.4')),
      ev('2026-11-10T10:10:00Z', 'users.login', U.raj, { status: 'OK' }, '1.2.3.4'),
      ...Array.from({ length: 3 }, (_, i) => ev(`2026-11-10T10:2${i}:00Z`, 'users.login', U.jane, { status: 'FAIL' }, '1.2.3.4')),
      ...Array.from({ length: 3 }, (_, i) => ev(`2026-11-10T10:3${i}:00Z`, 'users.login', 'Third User (third)', { status: 'FAIL' }, '1.2.3.4')),
      ev('2026-11-11T12:00:00Z', 'assignment.create', U.jane, { assignedRoleNames: ['ast-admin'] }),
      ev('2026-11-11T12:30:00Z', 'projects.delete', U.jane, { projectName: 'old' }),
      ev('2026-11-14T13:00:00Z', 'tenant-settings.update', U.jane, {}), // Saturday
    ];
    const events = load(items);
    const hl = computeHighlights(events);
    const ids = hl.map((h) => h.id.split(':')[0]);
    expect(ids).toContain('fail-then-ok');
    expect(ids).toContain('spray');
    expect(ids).toContain('admin-grants');
    expect(ids).toContain('deletions');
    expect(ids).toContain('auth-config');
    expect(ids).toContain('off-hours');
    expect(hl[0].severity).toBe('high');
    const ok = hl.find((h) => h.id.startsWith('fail-then-ok'))!;
    expect(ok.ids.length).toBe(7);
    // Every highlight's ids point at real events
    for (const h of hl) for (const i of h.ids) expect(events[i]).toBeDefined();
  });

  it('ignores failures spread over a long period (bursts only)', () => {
    // 40 failures for one account, one per day: no 15-minute burst.
    const items = Array.from({ length: 40 }, (_, i) =>
      ev(new Date(Date.UTC(2026, 9, 1 + i, 9)).toISOString(), 'users.login', U.raj, { status: 'FAIL' }, '1.1.1.1'),
    );
    const ids = computeHighlights(load(items)).map((h) => h.id.split(':')[0]);
    expect(ids).not.toContain('fail-burst');
    expect(ids).not.toContain('spray');
  });

  it('densestBurst finds the largest run inside the window', () => {
    const at = (m: number) => ({ epoch: m * 60000 }) as DecodedEvent;
    const evs = [0, 1, 2, 30, 31, 32, 33, 34].map(at);
    expect(densestBurst(evs, 15 * 60000, 3).length).toBe(5);
    expect(densestBurst(evs, 15 * 60000, 6)).toEqual([]);
  });

  it('is quiet for ordinary activity', () => {
    const events = load([ev('2026-11-10T10:00:00Z', 'users.login', U.jane, { status: 'OK' }, '1.1.1.1'), ev('2026-11-10T11:00:00Z', 'scans.create', U.jane)]);
    expect(computeHighlights(events)).toEqual([]);
  });
});

describe('export', () => {
  it('neutralises spreadsheet formulas and quotes CSV cells', () => {
    expect(csvCell('=HYPERLINK("x")')).toBe(`"'=HYPERLINK(""x"")"`);
    expect(csvCell('+1')).toBe("'+1");
    expect(csvCell('a,b')).toBe('"a,b"');
    expect(csvCell('plain')).toBe('plain');
  });

  it('CSV round-trips back into the dashboard with all fields', () => {
    const events = load(BASE);
    const csv = toCsv(events);
    const back = decodeDataset(parseCsvExport(csv.replace(/^﻿/, ''), 'x.csv'));
    expect(back.length).toBe(events.length);
    const a = events.find((e) => e.type === 'scans.create')!;
    const b = back.find((e) => e.type === 'scans.create')!;
    expect(b.data).toEqual(a.data);
    expect(b.user).toBe(a.user);
    expect(back.find((e) => e.ip === '10.0.0.9')).toBeDefined();
  });

  it('JSON export is API-shaped', () => {
    const events = load(BASE);
    const obj = toApiEvent(events[0]);
    expect(obj).toMatchObject({ eventID: BASE[0].eventID, eventType: 'users.login', actionUserId: U.jane, ipAddress: '10.0.0.1' });
    expect(obj.eventDate.endsWith('Z')).toBe(true);
    expect(JSON.parse(toJson(events)).length).toBe(6);
  });
});

describe('URL state', () => {
  it('round-trips filters, time zone, comparison and query', () => {
    const s = {
      filter: {
        cat: 'Identity & Auth',
        type: 'users.login',
        user: U.jane,
        day: '2026-11-10',
        hour: 9,
        q: 'a&b c',
        facets: [
          { field: 'data.status' as const, value: 'FAIL', exclude: false },
          { field: 'ip' as const, value: '10.0.0.1', exclude: true },
        ],
        highlightId: 'spray:1.2.3.4',
      },
      tz: 'local' as const,
      compare: true,
      query: { start: '2026-11-01', end: '2026-11-07', search: 'x', humanReadable: false, compare: true },
    };
    const back = decodeUrlState(encodeUrlState(s));
    expect(back.filter).toEqual(s.filter);
    expect(back.tz).toBe('local');
    expect(back.compare).toBe(true);
    expect(back.query).toEqual(s.query);
  });

  it('ignores malformed values', () => {
    const back = decodeUrlState('#hour=99&qs=bad&qe=2026-01-01');
    expect(back.filter.hour).toBeNull();
    expect(back.query).toBeUndefined();
  });
});

describe('chart buckets and formatting', () => {
  it('topWithRest keeps the total and lists the rest', () => {
    const m = new Map([['a', 5], ['b', 4], ['c', 3], ['d', 2], ['e', 1]]);
    const b = topWithRest(m, 2);
    expect(b.map((x) => x.label)).toEqual(['a', 'b', 'Other (+3)']);
    expect(b.reduce((s, x) => s + x.value, 0)).toBe(15);
    expect(b[2].key).toBeNull();
    expect(b[2].rest!.map((r) => r.key)).toEqual(['c', 'd', 'e']);
  });

  it('formats values and actors', () => {
    expect(fmtValue(['a', 'b'])).toBe('a, b');
    expect(fmtValue({ x: 1 })).toBe('{"x":1}');
    expect(fmtValue(null)).toBe('');
    expect(splitActor(U.jane)).toEqual({ name: 'Jane Doe', username: 'jdoe' });
    expect(splitActor('svc')).toEqual({ name: 'svc', username: null });
    expect(actorShort(U.id)).toBe('3f2a91bc…');
  });
});
