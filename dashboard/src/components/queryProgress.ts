// Live progress for a --serve query: polls /api/progress and renders stage, bar and counts
// on the loading screen. Only used in --serve mode.
import { describeProgress, fetchProgress, type ClientPhase, type QueryProgress, type ServeConfig } from '../serve.js';

const POLL_MS = 500;

export interface ProgressHandle {
  /** Switch to a client-side phase once the server has answered. Resolves after a paint. */
  setPhase(phase: ClientPhase): Promise<void>;
  stop(): void;
}

function el(id: string): HTMLElement {
  return document.getElementById(id)!;
}

function formatElapsed(s: number): string {
  const m = Math.floor(s / 60);
  return m ? `${m}m ${String(Math.floor(s % 60)).padStart(2, '0')}s` : `${Math.floor(s)}s`;
}

export function startQueryProgress(cfg: ServeConfig, humanReadable: boolean): ProgressHandle {
  const root = el('query-progress');
  const spinnerText = document.querySelector('#loading-state > p') as HTMLElement | null;
  root.hidden = false;
  if (spinnerText) spinnerText.hidden = true;

  const t0 = Date.now();
  let last: QueryProgress | null = null;
  // The first poll can land before the server has registered this query and return the
  // previous query's final state; ignore snapshots until this query shows as running.
  let sawRunning = false;
  let phase: ClientPhase | undefined;
  let stopped = false;
  const ctrl = new AbortController();

  const render = () => {
    const v = describeProgress(last, humanReadable, phase);
    el('qp-step').textContent = `Step ${v.step} of ${v.steps}`;
    el('qp-elapsed').textContent = formatElapsed((Date.now() - t0) / 1000);
    el('qp-title').textContent = v.title;
    el('qp-detail').textContent = v.detail;

    const bar = el('qp-bar');
    const fill = el('qp-fill');
    if (v.percent == null) {
      bar.classList.add('qp-indeterminate');
      bar.removeAttribute('aria-valuenow');
      fill.style.width = '';
    } else {
      bar.classList.remove('qp-indeterminate');
      bar.setAttribute('aria-valuenow', String(Math.round(v.percent)));
      fill.style.width = `${v.percent}%`;
    }

    const notice = el('qp-notice');
    notice.hidden = !v.notice;
    notice.textContent = v.notice ?? '';
  };

  const poll = async () => {
    while (!stopped) {
      if (!phase) {
        const p = await fetchProgress(cfg, ctrl.signal);
        if (p?.running) sawRunning = true;
        if (p && sawRunning) last = p;
      }
      if (stopped) break;
      render();
      await new Promise((r) => setTimeout(r, POLL_MS));
    }
  };

  render();
  void poll();

  return {
    async setPhase(next) {
      phase = next;
      render();
      // Give the browser a chance to paint the new text before heavy synchronous work (JSON
      // parse, dataset build). requestAnimationFrame never fires in a background tab, so race
      // it with a short timeout or the dashboard would wait until the tab is shown again.
      await new Promise<void>((r) => {
        const done = () => r();
        requestAnimationFrame(() => setTimeout(done, 0));
        setTimeout(done, 50);
      });
    },
    stop() {
      stopped = true;
      ctrl.abort();
      root.hidden = true;
      if (spinnerText) spinnerText.hidden = false;
    },
  };
}
