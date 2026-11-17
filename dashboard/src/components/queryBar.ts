// Query bar shown only when the dashboard is served by `python main.py --serve`.
import { defaultRange, runQuery, type ClientPhase, type QueryResult, type ServeConfig } from '../serve.js';

export interface QueryBarHandlers {
  onStart: (opts: { humanReadable: boolean }) => void;
  /** Called when the response arrives and again before the dataset is built. */
  onPhase: (phase: ClientPhase) => void | Promise<void>;
  onResult: (r: QueryResult) => void;
  onError: (message: string) => void;
}

function $(id: string): HTMLInputElement {
  return document.getElementById(id) as HTMLInputElement;
}

export function initQueryBar(cfg: ServeConfig, h: QueryBarHandlers): void {
  const form = document.getElementById('query-bar') as HTMLFormElement | null;
  if (!form) return;
  form.hidden = false;
  document.body.classList.add('serve-mode');

  const tenantEl = document.getElementById('query-tenant');
  if (tenantEl) tenantEl.textContent = cfg.tenant;

  const start = $('q-start');
  const end = $('q-end');
  const search = $('q-search');
  const human = $('q-human');
  const run = document.getElementById('q-run') as HTMLButtonElement;
  const status = document.getElementById('q-status')!;

  const range = defaultRange(cfg);
  for (const el of [start, end]) {
    el.min = cfg.earliest;
    el.max = cfg.today;
  }
  start.value = range.start;
  end.value = range.end;

  let running = false;

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (running) return;
    if (start.value > end.value) {
      status.textContent = 'Start date is after end date.';
      status.className = 'query-status query-status-error';
      return;
    }

    running = true;
    run.disabled = true;
    run.textContent = 'Running…';
    status.textContent = '';
    status.className = 'query-status';
    h.onStart({ humanReadable: human.checked });

    try {
      const result = await runQuery(
        cfg,
        { start: start.value, end: end.value, search: search.value, humanReadable: human.checked },
        undefined,
        h.onPhase,
      );
      status.textContent = `${result.count.toLocaleString()} events · ${result.elapsedSeconds}s`;
      h.onResult(result);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      status.textContent = 'Query failed';
      status.className = 'query-status query-status-error';
      h.onError(msg);
    } finally {
      running = false;
      run.disabled = false;
      run.textContent = 'Run query';
    }
  });
}
