import { describe, it, expect, afterEach, vi } from 'vitest';
import { buildQueryUrl, defaultRange, describeProgress, runQuery, type QueryProgress, type ServeConfig } from '../src/serve';

const cfg: ServeConfig = {
  token: 'tok',
  tenant: 'acme',
  baseUrl: 'https://ast.checkmarx.net',
  today: '2026-11-17',
  earliest: '2025-11-17',
};

describe('buildQueryUrl', () => {
  it('encodes params and omits an empty search', () => {
    expect(buildQueryUrl({ start: '2026-11-01', end: '2026-11-17', search: '  ', humanReadable: true })).toBe(
      '/api/events?start=2026-11-01&end=2026-11-17&humanReadable=1',
    );
    expect(buildQueryUrl({ start: 'a', end: 'b', search: 'x y&z', humanReadable: false })).toBe(
      '/api/events?start=a&end=b&humanReadable=0&search=x+y%26z',
    );
  });
});

describe('defaultRange', () => {
  it('is the last 7 days inclusive', () => {
    expect(defaultRange(cfg)).toEqual({ start: '2026-11-11', end: '2026-11-17' });
  });
  it('clamps to the retention window', () => {
    expect(defaultRange({ ...cfg, earliest: '2026-11-15' }).start).toBe('2026-11-15');
  });
});

describe('runQuery', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('sends the token header and builds a dataset', async () => {
    const fetchMock = vi.fn(async () =>
      new Response(
        JSON.stringify({
          meta: { tenant: 'acme', baseUrl: 'https://ast.checkmarx.net', elapsedSeconds: 1.5 },
          events: [{ eventDate: '2026-11-16T10:00:00Z', eventType: 'scans.create', actionUserId: 'Jane Doe (jdoe)', data: {} }],
        }),
        { status: 200 },
      ),
    );
    vi.stubGlobal('fetch', fetchMock);
    const r = await runQuery(cfg, { start: '2026-11-16', end: '2026-11-16', search: '', humanReadable: true });
    expect(r.count).toBe(1);
    expect(r.elapsedSeconds).toBe(1.5);
    expect(r.dataset.meta.tenant).toBe('acme');
    const [, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect((init.headers as Record<string, string>)['X-CxOne-Token']).toBe('tok');
  });

  it('surfaces the server error message', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ error: 'Start date is after end date.' }), { status: 400 })));
    await expect(runQuery(cfg, { start: 'b', end: 'a', search: '', humanReadable: false })).rejects.toThrow(
      'Start date is after end date.',
    );
  });

  it('explains when the server is unreachable', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('Failed to fetch'); }));
    await expect(runQuery(cfg, { start: 'a', end: 'b', search: '', humanReadable: false })).rejects.toThrow(/--serve/);
  });
});

describe('describeProgress', () => {
  const p = (x: Partial<QueryProgress>): QueryProgress => ({ running: true, stage: 'auth', ...x });

  it('starts at sign-in, indeterminate', () => {
    const v = describeProgress(p({ stage: 'auth' }), true);
    expect(v).toMatchObject({ title: 'Signing in to CxOne', percent: null, step: 1, steps: 3 });
  });

  it('is indeterminate until the first page reports a total', () => {
    expect(describeProgress(p({ stage: 'fetch', fetched: 0, total: null }), true)).toMatchObject({
      percent: null,
      detail: 'Waiting for the first page from CxOne…',
    });
  });

  it('shows fetched of total once known', () => {
    const v = describeProgress(p({ stage: 'fetch', fetched: 3000, total: 12000 }), false);
    expect(v.percent).toBe(25);
    expect(v.detail).toBe(`${(3000).toLocaleString()} of ${(12000).toLocaleString()} events`);
    expect(v.steps).toBe(2);
  });

  it('keeps the bar full while filtering (fetch is done)', () => {
    expect(describeProgress(p({ stage: 'filter', fetched: 280 }), true)).toMatchObject({ percent: 100, step: 1 });
  });

  it('handles an empty range', () => {
    expect(describeProgress(p({ stage: 'fetch', fetched: 0, total: 0 }), true).percent).toBe(100);
  });

  it('shows resolve progress with lookups as step 2 of 3', () => {
    const v = describeProgress(p({ stage: 'resolve', resolved: 50, resolveTotal: 200, lookups: 1 }), true);
    expect(v).toMatchObject({ step: 2, steps: 3, percent: 25 });
    expect(v.detail).toContain('1 name lookup');
    expect(v.detail).not.toContain('lookups');
  });

  it('passes notices through (e.g. rate limiting)', () => {
    const v = describeProgress(p({ stage: 'fetch', total: 10, fetched: 5, notice: 'Rate limited' }), true);
    expect(v.notice).toBe('Rate limited');
  });

  it('client phases take over as the final step', () => {
    expect(describeProgress(p({ stage: 'send', matched: 9 }), false, 'receiving')).toMatchObject({
      title: 'Downloading results',
      step: 2,
      steps: 2,
    });
    expect(describeProgress(null, true, 'building')).toMatchObject({ title: 'Building dashboard', step: 3 });
  });
});
