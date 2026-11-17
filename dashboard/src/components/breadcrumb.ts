import { getFilter, setFilter, resetFilter, isFilterActive } from '../state.js';

type FilterChangeCallback = () => void;
let _cb: FilterChangeCallback = () => {};
let _wired = false;

export function initBreadcrumb(cb: FilterChangeCallback): void {
  _cb = cb;
  renderBreadcrumb();
  // mountDashboard runs on every file load / query; bind the static controls only once.
  if (_wired) return;
  _wired = true;

  const searchEl = document.getElementById('search-input') as HTMLInputElement | null;
  if (searchEl) {
    searchEl.addEventListener('input', () => {
      setFilter({ q: searchEl.value });
      _cb();
    });
  }

  const resetBtn = document.getElementById('reset-btn');
  if (resetBtn) {
    resetBtn.addEventListener('click', () => {
      resetFilter();
      const si = document.getElementById('search-input') as HTMLInputElement | null;
      if (si) si.value = '';
      _cb();
    });
  }
}

export function renderBreadcrumb(): void {
  const f = getFilter();
  const crumbEl = document.getElementById('breadcrumb-path');
  const resetBtn = document.getElementById('reset-btn');

  if (!crumbEl) return;

  const chips: string[] = [];
  chips.push(`<span class="crumb-base">All events</span>`);

  if (f.cat) {
    chips.push(`<span class="crumb-sep">›</span><span class="crumb-chip" data-dim="cat">${esc(f.cat)} <button class="crumb-x" data-dim="cat">✕</button></span>`);
  }
  if (f.type) {
    chips.push(`<span class="crumb-sep">›</span><span class="crumb-chip" data-dim="type">${esc(f.type)} <button class="crumb-x" data-dim="type">✕</button></span>`);
  }
  if (f.user) {
    chips.push(`<span class="crumb-sep">›</span><span class="crumb-chip" data-dim="user">${esc(f.user)} <button class="crumb-x" data-dim="user">✕</button></span>`);
  }
  if (f.day) {
    chips.push(`<span class="crumb-sep">›</span><span class="crumb-chip" data-dim="day">${esc(f.day)} <button class="crumb-x" data-dim="day">✕</button></span>`);
  }

  crumbEl.innerHTML = chips.join('');

  // Attach chip remove handlers
  crumbEl.querySelectorAll('.crumb-x').forEach((btn) => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const dim = (btn as HTMLElement).dataset.dim as 'cat' | 'type' | 'user' | 'day';
      clearDimension(dim);
    });
  });

  if (resetBtn) {
    resetBtn.style.display = isFilterActive() ? 'inline-flex' : 'none';
  }
}

function clearDimension(dim: 'cat' | 'type' | 'user' | 'day'): void {
  if (dim === 'cat') setFilter({ cat: null, type: null, user: null, day: null });
  else if (dim === 'type') setFilter({ type: null, day: null });
  else if (dim === 'user') setFilter({ user: null });
  else if (dim === 'day') setFilter({ day: null });
  renderBreadcrumb();
  _cb();
}

function esc(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
