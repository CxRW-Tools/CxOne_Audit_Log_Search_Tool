// Query bar shown only when the dashboard is served by `python main.py --serve`.
import {
  cancelQuery,
  defaultRange,
  fetchRange,
  presetRange,
  runQuery,
  type ClientPhase,
  type QueryResult,
  type ServeConfig,
} from '../serve.js';

export interface QueryInfo {
  start: string;
  end: string;
  search: string;
  humanReadable: boolean;
  compare: boolean;
  /** With comparison: the first day of the current period (UTC). */
  split: string | null;
}

export interface QueryBarHandlers {
  onStart: (opts: { humanReadable: boolean }) => void;
  /** Called when the response arrives and again before the dataset is built. */
  onPhase: (phase: ClientPhase) => void | Promise<void>;
  onResult: (r: QueryResult, info: QueryInfo) => void;
  onError: (message: string) => void;
  onCancelled: () => void;
}

const STORAGE_KEY = 'cxone-audit.lastQuery';
const PRESETS: [string, number][] = [
  ['Today', 1],
  ['7 days', 7],
  ['30 days', 30],
  ['90 days', 90],
];

function $(id: string): HTMLInputElement {
  return document.getElementById(id) as HTMLInputElement;
}

function loadLast(): Partial<QueryInfo> | null {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY) ?? 'null');
  } catch {
    return null;
  }
}

function saveLast(q: QueryInfo): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(q));
  } catch {
    /* storage unavailable: fine */
  }
}

export function initQueryBar(cfg: ServeConfig, h: QueryBarHandlers, initial?: Partial<QueryInfo>): { setValues: (q: Partial<QueryInfo>) => void } {
  const form = document.getElementById('query-bar') as HTMLFormElement | null;
  if (!form) return { setValues: () => {} };
  form.hidden = false;
  document.body.classList.add('serve-mode');

  const tenantEl = document.getElementById('query-tenant');
  if (tenantEl) tenantEl.textContent = cfg.tenant;

  const start = $('q-start');
  const end = $('q-end');
  const search = $('q-search');
  const human = $('q-human');
  const compare = $('q-compare');
  const run = document.getElementById('q-run') as HTMLButtonElement;
  const cancel = document.getElementById('q-cancel') as HTMLButtonElement;
  const status = document.getElementById('q-status')!;
  const presetsEl = document.getElementById('q-presets')!;

  for (const el of [start, end]) {
    el.min = cfg.earliest;
    el.max = cfg.today;
  }

  const clamp = (d: string | undefined) => (d && d >= cfg.earliest && d <= cfg.today ? d : undefined);
  const setValues = (q: Partial<QueryInfo>) => {
    const range = defaultRange(cfg);
    start.value = clamp(q.start) ?? range.start;
    end.value = clamp(q.end) ?? range.end;
    if (q.search !== undefined) search.value = q.search;
    if (q.humanReadable !== undefined) human.checked = q.humanReadable;
    if (q.compare !== undefined) compare.checked = q.compare;
  };
  // URL state wins over the remembered query, which wins over the default.
  setValues({ ...(loadLast() ?? {}), ...(initial ?? {}) });

  presetsEl.innerHTML = PRESETS.map(([label, days]) => `<button type="button" class="preset-btn" data-days="${days}">${label}</button>`).join('');
  presetsEl.addEventListener('click', (e) => {
    const btn = (e.target as HTMLElement).closest<HTMLElement>('[data-days]');
    if (!btn) return;
    const r = presetRange(cfg, Number(btn.dataset.days));
    start.value = r.start;
    end.value = r.end;
  });

  let running: AbortController | null = null;

  cancel.addEventListener('click', () => {
    if (!running) return;
    running.abort();
    void cancelQuery(cfg);
  });

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (running) return;
    if (start.value > end.value) {
      status.textContent = 'Start date is after end date.';
      status.className = 'query-status query-status-error';
      return;
    }

    const { fetchStart, split } = fetchRange(cfg, start.value, end.value, compare.checked);
    const info: QueryInfo = {
      start: start.value,
      end: end.value,
      search: search.value.trim(),
      humanReadable: human.checked,
      compare: compare.checked,
      split,
    };

    running = new AbortController();
    run.hidden = true;
    cancel.hidden = false;
    cancel.focus();
    status.textContent = '';
    status.className = 'query-status';
    h.onStart({ humanReadable: info.humanReadable });

    try {
      const result = await runQuery(
        cfg,
        { start: fetchStart, end: info.end, search: info.search, humanReadable: info.humanReadable },
        running.signal,
        h.onPhase,
      );
      status.textContent = `${result.count.toLocaleString()} events · ${result.elapsedSeconds}s`;
      saveLast(info);
      h.onResult(result, info);
    } catch (err) {
      if ((err as Error).name === 'AbortError') {
        status.textContent = 'Query cancelled';
        h.onCancelled();
      } else {
        const msg = err instanceof Error ? err.message : String(err);
        status.textContent = 'Query failed';
        status.className = 'query-status query-status-error';
        h.onError(msg);
      }
    } finally {
      running = null;
      run.hidden = false;
      cancel.hidden = true;
    }
  });

  return { setValues };
}
