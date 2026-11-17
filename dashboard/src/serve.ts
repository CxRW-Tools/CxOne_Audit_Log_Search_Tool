// Client for the Search Tool's local server (`python main.py --serve`).
// The server injects window.__CXONE_SERVE__ into the page; when it's absent the
// dashboard is running as a plain file and none of this is used.
import type { Dataset } from './types.js';
import { datasetFromApiEvents } from './apiExport.js';

export interface ServeConfig {
  token: string;
  tenant: string;
  baseUrl: string;
  today: string; // YYYY-MM-DD (server's local date)
  earliest: string; // YYYY-MM-DD, today - 365 days
}

export interface QueryParams {
  start: string;
  end: string;
  search: string;
  humanReadable: boolean;
}

export interface QueryResult {
  dataset: Dataset;
  count: number;
  elapsedSeconds: number;
}

declare global {
  interface Window {
    __CXONE_SERVE__?: ServeConfig;
  }
}

export function getServeConfig(): ServeConfig | null {
  const c = window.__CXONE_SERVE__;
  return c && typeof c.token === 'string' ? c : null;
}

export function buildQueryUrl(p: QueryParams): string {
  const qs = new URLSearchParams({
    start: p.start,
    end: p.end,
    humanReadable: p.humanReadable ? '1' : '0',
  });
  if (p.search.trim()) qs.set('search', p.search.trim());
  return `/api/events?${qs.toString()}`;
}

/** Client-side phases after the server has answered. */
export type ClientPhase = 'receiving' | 'building';

export async function runQuery(
  cfg: ServeConfig,
  p: QueryParams,
  signal?: AbortSignal,
  onPhase?: (phase: ClientPhase) => void | Promise<void>,
): Promise<QueryResult> {
  let res: Response;
  try {
    res = await fetch(buildQueryUrl(p), { headers: { 'X-CxOne-Token': cfg.token }, signal });
  } catch (err) {
    if ((err as Error).name === 'AbortError') throw err;
    throw new Error('Could not reach the local server. Is `python main.py --serve` still running?');
  }
  if (res.ok) await onPhase?.('receiving');
  const body = await res.json().catch(() => null);
  if (!res.ok) {
    throw new Error(body?.error || `Server returned HTTP ${res.status}`);
  }
  await onPhase?.('building');
  const meta = body?.meta ?? {};
  const dataset = datasetFromApiEvents(body?.events ?? [], meta.tenant ?? cfg.tenant, meta.baseUrl ?? cfg.baseUrl);
  return { dataset, count: dataset.meta.total, elapsedSeconds: Number(meta.elapsedSeconds ?? 0) };
}

// ── Progress (/api/progress) ────────────────────────────────────────────────

/** Snapshot of the server-side query (see QueryProgress in src/pipeline.py). */
export interface QueryProgress {
  running: boolean;
  stage: 'idle' | 'auth' | 'fetch' | 'filter' | 'resolve' | 'send' | 'done' | 'error';
  humanReadable?: boolean;
  elapsedSeconds?: number;
  fetched?: number;
  total?: number | null;
  matched?: number;
  resolved?: number;
  resolveTotal?: number;
  lookups?: number;
  notice?: string | null;
  error?: string;
}

export async function fetchProgress(cfg: ServeConfig, signal?: AbortSignal): Promise<QueryProgress | null> {
  try {
    const res = await fetch('/api/progress', { headers: { 'X-CxOne-Token': cfg.token }, signal });
    return res.ok ? ((await res.json()) as QueryProgress) : null;
  } catch {
    return null; // transient; the caller keeps polling
  }
}

export interface ProgressView {
  title: string;
  detail: string;
  /** 0–100 for a determinate bar, null for an indeterminate one. */
  percent: number | null;
  step: number;
  steps: number;
  notice: string | null;
}

const n = (x: number | undefined | null) => (x ?? 0).toLocaleString();

/**
 * Turn a progress snapshot (or a client-side phase once the response has arrived) into
 * what the loading screen shows. Steps: Fetch → [Resolve names] → Prepare.
 */
export function describeProgress(p: QueryProgress | null, humanReadable: boolean, phase?: ClientPhase): ProgressView {
  const steps = humanReadable ? 3 : 2;
  const prepare = steps;
  const notice = p?.notice ?? null;

  if (phase === 'receiving') {
    return { title: 'Downloading results', detail: p?.matched != null ? `${n(p.matched)} events` : '', percent: null, step: prepare, steps, notice: null };
  }
  if (phase === 'building') {
    return { title: 'Building dashboard', detail: '', percent: null, step: prepare, steps, notice: null };
  }

  switch (p?.stage) {
    case 'fetch': {
      const total = p.total ?? null;
      if (total == null) {
        return { title: 'Fetching audit events', detail: p.fetched ? `${n(p.fetched)} events so far` : 'Waiting for the first page from CxOne…', percent: null, step: 1, steps, notice };
      }
      if (total === 0) return { title: 'Fetching audit events', detail: 'No events in this date range', percent: 100, step: 1, steps, notice };
      const pct = Math.min(100, ((p.fetched ?? 0) / total) * 100);
      return { title: 'Fetching audit events', detail: `${n(p.fetched)} of ${n(total)} events`, percent: pct, step: 1, steps, notice };
    }
    case 'filter':
      // Fetch is complete at this point; keep the bar full rather than jumping back to indeterminate.
      return { title: 'Filtering events', detail: `${n(p.fetched)} fetched`, percent: 100, step: 1, steps, notice };
    case 'resolve': {
      const total = p.resolveTotal ?? 0;
      const pct = total ? Math.min(100, ((p.resolved ?? 0) / total) * 100) : 100;
      const lookups = p.lookups ? ` · ${n(p.lookups)} name lookup${p.lookups === 1 ? '' : 's'}` : '';
      return { title: 'Resolving user, group and role names', detail: `${n(p.resolved)} of ${n(total)} events${lookups}`, percent: pct, step: 2, steps, notice };
    }
    case 'send':
    case 'done':
      return { title: 'Sending results to the browser', detail: p.matched != null ? `${n(p.matched)} events` : '', percent: null, step: prepare, steps, notice };
    case 'auth':
    default:
      return { title: 'Signing in to CxOne', detail: '', percent: null, step: 1, steps, notice };
  }
}

/** Default range: the last 7 days, clamped to the 365-day retention window. */
export function defaultRange(cfg: ServeConfig): { start: string; end: string } {
  const end = cfg.today;
  const d = new Date(`${end}T00:00:00Z`);
  d.setUTCDate(d.getUTCDate() - 6);
  const start = d.toISOString().slice(0, 10);
  return { start: start < cfg.earliest ? cfg.earliest : start, end };
}
