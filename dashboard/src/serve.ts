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

export async function runQuery(cfg: ServeConfig, p: QueryParams, signal?: AbortSignal): Promise<QueryResult> {
  let res: Response;
  try {
    res = await fetch(buildQueryUrl(p), { headers: { 'X-CxOne-Token': cfg.token }, signal });
  } catch (err) {
    if ((err as Error).name === 'AbortError') throw err;
    throw new Error('Could not reach the local server. Is `python main.py --serve` still running?');
  }
  const body = await res.json().catch(() => null);
  if (!res.ok) {
    throw new Error(body?.error || `Server returned HTTP ${res.status}`);
  }
  const meta = body?.meta ?? {};
  const dataset = datasetFromApiEvents(body?.events ?? [], meta.tenant ?? cfg.tenant, meta.baseUrl ?? cfg.baseUrl);
  return { dataset, count: dataset.meta.total, elapsedSeconds: Number(meta.elapsedSeconds ?? 0) };
}

/** Default range: the last 7 days, clamped to the 365-day retention window. */
export function defaultRange(cfg: ServeConfig): { start: string; end: string } {
  const end = cfg.today;
  const d = new Date(`${end}T00:00:00Z`);
  d.setUTCDate(d.getUTCDate() - 6);
  const start = d.toISOString().slice(0, 10);
  return { start: start < cfg.earliest ? cfg.earliest : start, end };
}
