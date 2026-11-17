import { periodEvents, getFilter, resetFilter, setFilter, cachedData } from '../state.js';
import { computeHighlights, type Highlight } from '../highlights.js';
import { esc } from '../format.js';

let _cb: () => void = () => {};
let _expanded = false;
let _wired = false;
let _list: Highlight[] = [];
const COLLAPSED_COUNT = 6;

export function initHighlights(cb: () => void): void {
  _cb = cb;
  const el = document.getElementById('highlights');
  if (!el || _wired) return;
  _wired = true;
  el.addEventListener('click', (ev) => {
    const t = ev.target as HTMLElement;
    if (t.closest('#hl-toggle')) {
      _expanded = !_expanded;
      renderHighlights();
      return;
    }
    const item = t.closest<HTMLElement>('[data-hl]');
    if (!item) return;
    const h = _list.find((x) => x.id === item.dataset.hl);
    if (!h) return;
    const active = getFilter().highlight?.id === h.id;
    resetFilter();
    if (!active) setFilter({ highlight: { id: h.id, label: h.title, ids: new Set(h.ids) } });
    _cb();
  });
}

/** Look up a highlight by id (used to restore it from the URL). */
export function findHighlight(id: string): Highlight | undefined {
  return currentHighlights().find((h) => h.id === id);
}

function currentHighlights(): Highlight[] {
  // Highlights describe the whole period, independent of the current filter.
  return cachedData('highlights', () => computeHighlights(periodEvents()));
}

export function renderHighlights(): void {
  const el = document.getElementById('highlights');
  if (!el) return;
  _list = currentHighlights();
  const activeId = getFilter().highlight?.id;

  if (!_list.length) {
    el.innerHTML = `<div class="panel-title">Highlights</div><div class="panel-hint">Nothing stands out in this period: no failed-login bursts, privilege or credential changes, deletions, exports or off-hours changes.</div>`;
    return;
  }

  const counts = { high: 0, medium: 0, info: 0 };
  for (const h of _list) counts[h.severity]++;
  const shown = _expanded ? _list : _list.slice(0, COLLAPSED_COUNT);
  const summary = [counts.high && `${counts.high} high`, counts.medium && `${counts.medium} medium`, counts.info && `${counts.info} info`].filter(Boolean).join(' · ');

  el.innerHTML = `
    <div class="hl-head">
      <div>
        <div class="panel-title">Highlights</div>
        <div class="panel-hint">Patterns worth a look in this period (${summary}). Click one to see its events.</div>
      </div>
    </div>
    <ul class="hl-list">
      ${shown
        .map(
          (h) => `
        <li>
          <button type="button" class="hl-item hl-${h.severity}${h.id === activeId ? ' hl-active' : ''}" data-hl="${esc(h.id)}" aria-pressed="${h.id === activeId}">
            <span class="hl-sev">${h.severity}</span>
            <span class="hl-text"><span class="hl-title">${esc(h.title)}</span><span class="hl-detail">${esc(h.detail)}</span></span>
            <span class="hl-count">${h.ids.length.toLocaleString()}</span>
          </button>
        </li>`,
        )
        .join('')}
    </ul>
    ${_list.length > COLLAPSED_COUNT ? `<button type="button" id="hl-toggle" class="small-btn hl-toggle">${_expanded ? 'Show fewer' : `Show all ${_list.length}`}</button>` : ''}
  `;
}
