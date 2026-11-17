import { getFilter, setFilter, resetFilter, isFilterActive, removeFacet, fieldLabel, getTimeZone } from '../state.js';
import { actorShort, esc } from '../format.js';

type FilterChangeCallback = () => void;
let _cb: FilterChangeCallback = () => {};
let _wired = false;
const SEARCH_DEBOUNCE_MS = 200;

export function initBreadcrumb(cb: FilterChangeCallback): void {
  _cb = cb;
  renderBreadcrumb();
  // mountDashboard runs on every file load / query; bind the static controls only once.
  if (_wired) return;
  _wired = true;

  const searchEl = document.getElementById('search-input') as HTMLInputElement | null;
  if (searchEl) {
    let timer: number | undefined;
    // Debounced: filtering 100k+ events on every keystroke made typing stutter.
    searchEl.addEventListener('input', () => {
      window.clearTimeout(timer);
      timer = window.setTimeout(() => {
        setFilter({ q: searchEl.value });
        _cb();
      }, SEARCH_DEBOUNCE_MS);
    });
    searchEl.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        window.clearTimeout(timer);
        setFilter({ q: searchEl.value });
        _cb();
      }
    });
  }

  document.getElementById('reset-btn')?.addEventListener('click', () => {
    resetFilter();
    _cb();
  });

  document.getElementById('breadcrumb-path')?.addEventListener('click', (e) => {
    const btn = (e.target as HTMLElement).closest<HTMLElement>('.crumb-x');
    if (!btn) return;
    e.stopPropagation();
    const dim = btn.dataset.dim!;
    if (dim === 'cat') setFilter({ cat: null, type: null, user: null, day: null });
    else if (dim === 'type') setFilter({ type: null, day: null });
    else if (dim === 'user') setFilter({ user: null });
    else if (dim === 'day') setFilter({ day: null });
    else if (dim === 'hour') setFilter({ hour: null });
    else if (dim === 'highlight') setFilter({ highlight: null });
    else if (dim === 'facet') removeFacet(Number(btn.dataset.index));
    _cb();
  });
}

function chip(dim: string, label: string, opts: { index?: number; cls?: string; title?: string } = {}): string {
  const idx = opts.index !== undefined ? ` data-index="${opts.index}"` : '';
  return `<span class="crumb-sep">›</span><span class="crumb-chip ${opts.cls ?? ''}"${opts.title ? ` title="${esc(opts.title)}"` : ''}>${label} <button type="button" class="crumb-x" data-dim="${dim}"${idx} aria-label="Remove filter: ${esc(opts.title ?? label.replace(/<[^>]+>/g, ''))}">✕</button></span>`;
}

export function renderBreadcrumb(): void {
  const f = getFilter();
  const crumbEl = document.getElementById('breadcrumb-path');
  const resetBtn = document.getElementById('reset-btn');
  if (!crumbEl) return;

  const chips: string[] = [`<span class="crumb-base">All events</span>`];
  if (f.highlight) chips.push(chip('highlight', `★ ${esc(f.highlight.label)}`, { cls: 'crumb-highlight', title: `Highlight: ${f.highlight.label}` }));
  if (f.cat) chips.push(chip('cat', esc(f.cat)));
  if (f.type) chips.push(chip('type', esc(f.type)));
  if (f.user) chips.push(chip('user', esc(actorShort(f.user, 40)), { title: f.user }));
  if (f.day) chips.push(chip('day', esc(f.day)));
  if (f.hour !== null) {
    const h = String(f.hour).padStart(2, '0');
    chips.push(chip('hour', `${h}:00–${h}:59 ${getTimeZone() === 'utc' ? 'UTC' : 'local'}`));
  }
  f.facets.forEach((facet, i) => {
    const name = fieldLabel(facet.field);
    const value = facet.field === 'user' ? actorShort(facet.value, 40) : facet.value;
    chips.push(
      chip('facet', `${facet.exclude ? 'not ' : ''}${esc(name)}: ${esc(value.length > 40 ? value.slice(0, 39) + '…' : value)}`, {
        index: i,
        cls: facet.exclude ? 'crumb-exclude' : '',
        title: `${facet.exclude ? 'Exclude' : 'Only'} ${name} = ${facet.value}`,
      }),
    );
  });

  crumbEl.innerHTML = chips.join('');

  const searchEl = document.getElementById('search-input') as HTMLInputElement | null;
  if (searchEl && document.activeElement !== searchEl && searchEl.value !== f.q) searchEl.value = f.q;

  if (resetBtn) resetBtn.style.display = isFilterActive() ? 'inline-flex' : 'none';
}
