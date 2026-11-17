import './theme.css';
import { loadFromUrl, loadFromFile, decodeDataset, applyTimeZone } from './loader.js';
import {
  setData,
  scopeSummary,
  getFilter,
  setFilter,
  addFacet,
  getTimeZone,
  setTimeZone,
  getCompareSplit,
  setCompareSplit,
  midpointSplit,
  getDataset,
  type FieldKey,
} from './state.js';
import type { Dataset, DecodedEvent, TimeZoneMode } from './types.js';
import { categoryFor } from './parser.js';
import { esc, tzLabel } from './format.js';
import { renderKpis, initKpis } from './components/kpis.js';
import { initBreadcrumb, renderBreadcrumb } from './components/breadcrumb.js';
import { initDrillChart, renderDrillChart } from './components/drillChart.js';
import { initActorChart, renderActorChart } from './components/actorChart.js';
import { initTrendChart, renderTrendChart } from './components/trendChart.js';
import { initHourChart, renderHourChart } from './components/hourChart.js';
import { initEventLog, renderEventLog, resetEventLogPage } from './components/eventLog.js';
import { initHighlights, renderHighlights, findHighlight } from './components/highlightsPanel.js';
import { initFacetBar, renderFacetBar } from './components/facetBar.js';
import { initQueryBar, type QueryInfo } from './components/queryBar.js';
import { startQueryProgress, type ProgressHandle } from './components/queryProgress.js';
import { getServeConfig } from './serve.js';
import { decodeUrlState, encodeUrlState, type UrlState } from './urlState.js';

const _serve = getServeConfig();
const FILE_HINT = 'Drop a <code>.csv</code>, <code>.json</code> or <code>.log</code> file to load data manually.';
const LANDING_HINT = _serve
  ? 'Choose a date range above and click <strong>Run query</strong>, or drop a <code>.csv</code>, <code>.json</code> or <code>.log</code> export here.'
  : 'Drop a <code>.csv</code>, <code>.json</code> or <code>.log</code> export here, or click <strong>Load file</strong> to get started.';
const PREFS = { tz: 'cxone-audit.tz', charts: 'cxone-audit.chartsHidden' };

/** URL state from page load, applied to the first dataset that mounts. */
let _pendingUrl: UrlState | null = decodeUrlState(location.hash);
/** Split from the last comparison query (first day of the current period). */
let _querySplit: number | null = null;
let _lastQuery: QueryInfo | null = null;
let _mounted = false;
let _chartsHidden = readPref(PREFS.charts) === '1';
let _queryBar: { setValues: (q: Partial<QueryInfo>) => void } | null = null;

function syncTzButtons(): void {
  document.querySelectorAll<HTMLElement>('[data-tz]').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.tz === getTimeZone())));
}

/**
 * A link pasted into a tab that already has the dashboard open only changes the hash (no
 * reload): fill the query bar and apply the filters to the loaded data right away.
 * (Our own history.replaceState calls don't fire hashchange.)
 */
function onHashChange(): void {
  const u = decodeUrlState(location.hash);
  if (u.query) _queryBar?.setValues(u.query);
  if (_mounted) {
    applyUrlState(u);
    refresh();
  } else {
    _pendingUrl = u;
  }
}

function readPref(key: string): string | null {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}
function writePref(key: string, value: string): void {
  try {
    localStorage.setItem(key, value);
  } catch {
    /* storage unavailable */
  }
}

// ── Rendering ───────────────────────────────────────────────────────────────

function refresh(): void {
  resetEventLogPage();
  renderKpis();
  renderHighlights();
  renderBreadcrumb();
  renderScopeRow();
  if (!_chartsHidden) {
    renderDrillChart();
    renderActorChart();
    renderTrendChart();
    renderHourChart();
  }
  renderEventLog();
  writeUrl();
}

function renderScopeRow(): void {
  const ds = getDataset();
  const banner = document.getElementById('source-banner');
  if (banner && ds) {
    const src = ds.meta.source;
    const tenant = ds.meta.tenant ? `<strong>${esc(ds.meta.tenant)}</strong> · ` : '';
    let text: string;
    if (src?.kind === 'query') {
      text = `Live query · ${tenant}${esc(src.start)} → ${esc(src.end)}${src.compare ? ' (+ previous period)' : ''} · ${src.humanReadable ? 'names resolved' : 'names not resolved'}${src.search ? ` · server filter “${esc(src.search)}”` : ''}`;
    } else if (src?.kind === 'file') {
      text = `File · ${tenant}<strong>${esc(src.name)}</strong> · ${esc(ds.meta.dateMin)} → ${esc(ds.meta.dateMax)}`;
    } else if (src?.kind === 'url') {
      text = `URL · ${tenant}${esc(src.url)}`;
    } else {
      text = `${tenant}${esc(ds.meta.dateMin)} → ${esc(ds.meta.dateMax)}`;
    }
    banner.innerHTML = `<span class="source-kind">Source</span> ${text} · times in ${esc(tzLabel(getTimeZone()))}`;
  }

  const el = document.getElementById('scope-summary');
  if (el) {
    const s = scopeSummary();
    el.innerHTML = `Viewing <strong>${s.count.toLocaleString()}</strong> of <strong>${s.total.toLocaleString()}</strong> events · <strong>${s.eventTypes}</strong> event types · <strong>${s.namedActors}</strong> named actors · <strong>${s.activeDays}</strong> active days${s.dateMin ? ` (${s.dateMin} → ${s.dateMax})` : ''}`;
  }

  // Compare toggle
  const toggle = document.getElementById('compare-toggle') as HTMLInputElement | null;
  const label = document.getElementById('compare-toggle-label');
  const text = document.getElementById('compare-toggle-text');
  const split = getCompareSplit();
  const available = _querySplit ?? midpointSplit();
  if (toggle && label && text) {
    toggle.checked = split !== null;
    toggle.disabled = available === null;
    label.classList.toggle('disabled', available === null);
    if (split !== null && ds) {
      const day = (ms: number) => new Date(ms).toISOString().slice(0, 10);
      const days = Math.round((Date.parse(ds.meta.dateMax + 'T00:00:00Z') - split) / 86400000) + 1;
      text.textContent = `Comparing ${day(split)} → ${ds.meta.dateMax} with the ${days} days before`;
    } else {
      text.textContent = _querySplit !== null ? 'Compare with previous period' : 'Compare halves of the loaded range';
    }
  }
}

function writeUrl(): void {
  if (_pendingUrl) return; // don't overwrite the incoming URL before it's applied
  const f = getFilter();
  const { highlight, ...rest } = f;
  const hash = encodeUrlState({
    filter: { ...rest, highlightId: highlight?.id },
    tz: getTimeZone(),
    compare: getCompareSplit() !== null,
    query: _lastQuery ?? undefined,
  });
  if (hash !== location.hash && !(hash === '' && location.hash === '')) {
    try {
      history.replaceState(null, '', location.pathname + location.search + hash);
    } catch {
      // Some file:// / opaque-origin pages refuse replaceState; the URL is a convenience only.
    }
  }
}

// ── Mounting ────────────────────────────────────────────────────────────────

function mountDashboard(dataset: Dataset, events: DecodedEvent[], split: number | null = null): void {
  applyTimeZone(events, getTimeZone());
  setData(dataset, events);
  _querySplit = split;
  if (split !== null) setCompareSplit(split);
  _mounted = true;

  document.getElementById('loading-state')!.style.display = 'none';
  document.getElementById('error-state')!.style.display = 'none';
  document.getElementById('dashboard')!.style.display = 'block';

  document.title = dataset.meta.tenant ? `Audit Dashboard — ${dataset.meta.tenant}` : 'CxOne Audit Log Dashboard';
  const titleEl = document.querySelector('.header-title');
  if (titleEl) titleEl.textContent = dataset.meta.tenant ? `Audit Log Dashboard · ${dataset.meta.tenant}` : 'Audit Log Dashboard';

  initKpis(refresh);
  initBreadcrumb(refresh);
  initDrillChart(refresh);
  initActorChart(refresh);
  initTrendChart(refresh);
  initHourChart(refresh);
  initHighlights(refresh);
  initFacetBar(refresh);
  initEventLog(onPivot);
  renderFacetBar();

  applyPendingUrl();
  refresh();
  updateStickyOffsets();
}

/** Apply filters from the URL the page was opened with (once, to the first dataset). */
function applyPendingUrl(): void {
  const u = _pendingUrl;
  _pendingUrl = null;
  if (u) applyUrlState(u);
}

function applyUrlState(u: UrlState): void {
  if (u.tz && u.tz !== getTimeZone()) {
    setTimeZone(u.tz);
    syncTzButtons();
  }
  if (u.compare && getCompareSplit() === null) {
    const s = _querySplit ?? midpointSplit();
    if (s !== null) setCompareSplit(s);
  } else if (!u.compare && getCompareSplit() !== null) {
    setCompareSplit(null);
  }
  const { highlightId, ...f } = u.filter;
  setFilter({ cat: null, type: null, user: null, day: null, ...f, facets: f.facets ?? [], hour: f.hour ?? null, q: f.q ?? '', highlight: null });
  if (highlightId) {
    const h = findHighlight(highlightId);
    if (h) setFilter({ highlight: { id: h.id, label: h.title, ids: new Set(h.ids) } });
  }
}

function onPivot(field: FieldKey, value: string, exclude: boolean): void {
  if (!exclude && field === 'user') setFilter({ user: value });
  else if (!exclude && field === 'type') setFilter({ type: value, cat: categoryFor(value) });
  else if (!exclude && field === 'cat') setFilter({ cat: value, type: null, user: null });
  else addFacet({ field, value, exclude });
  refresh();
}

function showError(msg: string): void {
  document.getElementById('loading-state')!.style.display = 'none';
  document.getElementById('dashboard')!.style.display = 'none';
  const errEl = document.getElementById('error-state')!;
  errEl.style.display = 'flex';
  errEl.querySelector('p')!.innerHTML = `<strong class="err">Failed to load audit data.</strong><br>${msg}<br><br>${FILE_HINT}`;
}

function showLoading(message: string): void {
  document.getElementById('error-state')!.style.display = 'none';
  document.getElementById('dashboard')!.style.display = 'none';
  const el = document.getElementById('loading-state')!;
  el.style.display = 'flex';
  el.querySelector('p')!.textContent = message;
}

/** Back to whatever was showing before a cancelled query. */
function restoreView(): void {
  document.getElementById('loading-state')!.style.display = 'none';
  if (_mounted) {
    document.getElementById('dashboard')!.style.display = 'block';
    updateStickyOffsets();
  } else showLanding();
}

// ── --serve mode ────────────────────────────────────────────────────────────

function initServeMode(): void {
  if (!_serve) return;
  const cfg = _serve;

  // The query bar becomes the header: move the header actions (time zone, load file) into it.
  const slot = document.getElementById('query-actions-slot');
  const actions = document.getElementById('header-actions');
  if (slot && actions) slot.appendChild(actions);

  let progress: ProgressHandle | null = null;
  const stopProgress = () => {
    progress?.stop();
    progress = null;
  };
  _queryBar = initQueryBar(
    cfg,
    {
      onStart: ({ humanReadable }) => {
        showLoading('Querying CxOne…');
        progress = startQueryProgress(cfg, humanReadable);
      },
      onPhase: (phase) => progress?.setPhase(phase),
      onResult: ({ dataset }, info) => {
        stopProgress();
        if (dataset.meta.total === 0) {
          showError('No audit events matched that date range and search.');
          return;
        }
        _lastQuery = { ...info };
        dataset.meta.source = { kind: 'query', start: info.start, end: info.end, search: info.search, humanReadable: info.humanReadable, compare: info.compare };
        const split = info.split ? Date.parse(info.split + 'T00:00:00Z') : null;
        mountDashboard(dataset, decodeDataset(dataset, getTimeZone()), split);
      },
      onError: (message) => {
        stopProgress();
        showError(esc(message));
      },
      onCancelled: () => {
        stopProgress();
        restoreView();
      },
    },
    _pendingUrl?.query,
  );
}

// ── Controls ────────────────────────────────────────────────────────────────

function initControls(): void {
  // Time zone
  const saved = readPref(PREFS.tz);
  const urlTz = _pendingUrl?.tz;
  const tz: TimeZoneMode = urlTz === 'local' || (!location.hash && saved === 'local') ? 'local' : 'utc';
  if (tz !== getTimeZone()) setTimeZone(tz);
  syncTzButtons();
  window.addEventListener('hashchange', onHashChange);
  document.addEventListener('click', (e) => {
    const b = (e.target as HTMLElement).closest<HTMLElement>('[data-tz]');
    if (!b) return;
    setTimeZone(b.dataset.tz as TimeZoneMode);
    writePref(PREFS.tz, getTimeZone());
    syncTzButtons();
    if (_mounted) refresh();
  });

  // Compare toggle
  document.getElementById('compare-toggle')?.addEventListener('change', (e) => {
    const on = (e.target as HTMLInputElement).checked;
    setCompareSplit(on ? (_querySplit ?? midpointSplit()) : null);
    refresh();
  });

  // Charts toggle
  const charts = document.getElementById('charts')!;
  const btn = document.getElementById('charts-toggle')!;
  const applyCharts = () => {
    charts.hidden = _chartsHidden;
    btn.textContent = _chartsHidden ? 'Show charts' : 'Hide charts';
    btn.setAttribute('aria-expanded', String(!_chartsHidden));
  };
  applyCharts();
  btn.addEventListener('click', () => {
    _chartsHidden = !_chartsHidden;
    writePref(PREFS.charts, _chartsHidden ? '1' : '0');
    applyCharts();
    if (!_chartsHidden && _mounted) {
      renderDrillChart();
      renderActorChart();
      renderTrendChart();
      renderHourChart();
    }
  });

  // Jump link: scroll without leaving the filter hash
  document.getElementById('jump-events')?.addEventListener('click', (e) => {
    e.preventDefault();
    document.getElementById('events')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  });

  window.addEventListener('resize', updateStickyOffsets);
}

/** Sticky header heights vary (wrapping query bar); expose them to CSS. */
function updateStickyOffsets(): void {
  const top = document.getElementById(_serve ? 'query-bar' : 'app-header');
  const filterBar = document.getElementById('filter-bar');
  const topH = top && top.offsetParent !== null ? top.getBoundingClientRect().height : 0;
  const fbH = filterBar ? filterBar.getBoundingClientRect().height : 0;
  document.documentElement.style.setProperty('--sticky-top', `${Math.round(topH)}px`);
  document.documentElement.style.setProperty('--sticky-stack', `${Math.round(topH + fbH)}px`);
}

// ── File loading ────────────────────────────────────────────────────────────

async function handleFileLoad(file: File): Promise<void> {
  try {
    showLoading('Loading audit data…');
    const { dataset, events } = await loadFromFile(file);
    dataset.meta.source = { kind: 'file', name: file.name };
    _lastQuery = null;
    mountDashboard(dataset, events);
  } catch (err) {
    showError(esc(err instanceof Error ? err.message : String(err)));
  }
}

function wireFileInput(inputId: string): void {
  const input = document.getElementById(inputId) as HTMLInputElement | null;
  if (!input) return;
  input.addEventListener('change', () => {
    if (input.files?.[0]) void handleFileLoad(input.files[0]);
    input.value = ''; // allow re-loading the same file
  });
}

function wireDragDrop(zoneId: string): void {
  const zone = document.getElementById(zoneId);
  if (!zone) return;
  zone.addEventListener('dragover', (e) => {
    e.preventDefault();
    zone.classList.add('drag-over');
  });
  zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));
  zone.addEventListener('drop', (e) => {
    e.preventDefault();
    e.stopPropagation();
    zone.classList.remove('drag-over');
    const file = (e as DragEvent).dataTransfer?.files[0];
    if (file) void handleFileLoad(file);
  });
}

function showLanding(): void {
  document.getElementById('loading-state')!.style.display = 'none';
  document.getElementById('dashboard')!.style.display = 'none';
  document.getElementById('error-state')!.style.display = 'flex';
  document.querySelector('#error-state p')!.innerHTML = LANDING_HINT;
}

async function init(): Promise<void> {
  wireFileInput('file-input');
  wireFileInput('error-file-input');
  wireDragDrop('file-drop-zone');
  wireDragDrop('error-file-label');
  initControls();
  initServeMode();

  // Whole page is a drop target.
  document.body.addEventListener('dragover', (e) => e.preventDefault());
  document.body.addEventListener('drop', (e) => {
    e.preventDefault();
    const file = e.dataTransfer?.files[0];
    if (file) void handleFileLoad(file);
  });

  // Only auto-fetch when an explicit ?data= URL is provided
  const dataUrl = new URLSearchParams(window.location.search).get('data');
  if (dataUrl) {
    try {
      const { dataset, events } = await loadFromUrl(dataUrl);
      dataset.meta.source = { kind: 'url', url: dataUrl };
      mountDashboard(dataset, events);
    } catch (err) {
      showError(`Could not fetch <code>${esc(dataUrl)}</code>: ${esc(String(err))}`);
    }
  } else {
    showLanding();
  }
}

void init();
