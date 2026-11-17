import './theme.css';
import { loadFromUrl, loadFromFile, decodeDataset } from './loader.js';
import { setData, scopeSummary, getFilter } from './state.js';
import type { Dataset, DecodedEvent } from './types.js';
import { renderKpis, initKpis } from './components/kpis.js';
import { initBreadcrumb, renderBreadcrumb } from './components/breadcrumb.js';
import { initDrillChart, renderDrillChart } from './components/drillChart.js';
import { initActorChart, renderActorChart } from './components/actorChart.js';
import { initTrendChart, renderTrendChart } from './components/trendChart.js';
import { renderHourChart } from './components/hourChart.js';
import { renderEventLog, resetEventLogPage } from './components/eventLog.js';
import { initQueryBar } from './components/queryBar.js';
import { startQueryProgress, type ProgressHandle } from './components/queryProgress.js';
import { getServeConfig } from './serve.js';

let _allEvents: DecodedEvent[] = [];
const _serve = getServeConfig();
const FILE_HINT = 'Drop a <code>.csv</code>, <code>.json</code> or <code>.log</code> file to load data manually.';
const LANDING_HINT = _serve
  ? 'Choose a date range above and click <strong>Run query</strong>, or drop a <code>.csv</code>, <code>.json</code> or <code>.log</code> export here.'
  : 'Drop a <code>.csv</code>, <code>.json</code> or <code>.log</code> export here, or click <strong>Load file</strong> to get started.';

function refresh(): void {
  resetEventLogPage();
  syncSearchInput();
  renderKpis(_allEvents);
  renderBreadcrumb();
  renderScopeSummary();
  renderDrillChart();
  renderActorChart();
  renderTrendChart();
  renderHourChart();
  renderEventLog();
}

// Keep the search input text in sync when q is set programmatically (e.g. KPI click)
function syncSearchInput(): void {
  const el = document.getElementById('search-input') as HTMLInputElement | null;
  if (el) el.value = getFilter().q;
}

function renderScopeSummary(): void {
  const el = document.getElementById('scope-summary');
  if (!el) return;
  const s = scopeSummary();
  el.innerHTML = `Viewing <strong>${s.count.toLocaleString()}</strong> of <strong>${s.total.toLocaleString()}</strong> events · <strong>${s.eventTypes}</strong> event types · <strong>${s.namedActors}</strong> named actors · <strong>${s.activeDays}</strong> active days (${s.dateMin} → ${s.dateMax})`;
}

function mountDashboard(dataset: Dataset, events: DecodedEvent[]): void {
  _allEvents = events;
  setData(dataset, events);

  document.getElementById('loading-state')!.style.display = 'none';
  document.getElementById('error-state')!.style.display = 'none';
  document.getElementById('dashboard')!.style.display = 'block';

  // Update page title with tenant info
  if (dataset.meta.tenant) {
    document.title = `Audit Dashboard — ${dataset.meta.tenant}`;
    const titleEl = document.querySelector('.header-title');
    if (titleEl) titleEl.textContent = `Audit Log Dashboard · ${dataset.meta.tenant}`;
  }

  initKpis(refresh);
  initBreadcrumb(refresh);
  initDrillChart(refresh);
  initActorChart(refresh);
  initTrendChart(refresh);
  refresh();
}

function showError(msg: string): void {
  document.getElementById('loading-state')!.style.display = 'none';
  const errEl = document.getElementById('error-state')!;
  errEl.style.display = 'flex';
  const p = errEl.querySelector('p')!;
  p.innerHTML = `<strong class="err">Failed to load audit data.</strong><br>${msg}<br><br>${FILE_HINT}`;
}

function showLoading(message: string): void {
  document.getElementById('error-state')!.style.display = 'none';
  document.getElementById('dashboard')!.style.display = 'none';
  const el = document.getElementById('loading-state')!;
  el.style.display = 'flex';
  el.querySelector('p')!.textContent = message;
}

function initServeMode(): void {
  if (!_serve) return;
  const cfg = _serve;
  let progress: ProgressHandle | null = null;
  const stopProgress = () => {
    progress?.stop();
    progress = null;
  };
  initQueryBar(cfg, {
    onStart: ({ humanReadable }) => {
      showLoading('Querying CxOne…');
      progress = startQueryProgress(cfg, humanReadable);
    },
    onPhase: (phase) => progress?.setPhase(phase),
    onResult: ({ dataset }) => {
      stopProgress();
      if (dataset.meta.total === 0) {
        showError('No audit events matched that date range and search.');
        return;
      }
      mountDashboard(dataset, decodeDataset(dataset));
    },
    onError: (message) => {
      stopProgress();
      showError(escapeHtml(message));
    },
  });
}

function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

async function handleFileLoad(file: File): Promise<void> {
  try {
    showLoading('Loading audit data…');
    const { dataset, events } = await loadFromFile(file);
    mountDashboard(dataset, events);
  } catch (err) {
    showError(escapeHtml(err instanceof Error ? err.message : String(err)));
  }
}

function wireFileInput(inputId: string): void {
  const input = document.getElementById(inputId) as HTMLInputElement | null;
  if (!input) return;
  input.addEventListener('change', () => {
    if (input.files?.[0]) handleFileLoad(input.files[0]);
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
    zone.classList.remove('drag-over');
    const file = (e as DragEvent).dataTransfer?.files[0];
    if (file) handleFileLoad(file);
  });
}

async function init(): Promise<void> {
  wireFileInput('file-input');
  wireFileInput('error-file-input');
  wireDragDrop('file-drop-zone');
  wireDragDrop('error-file-label');
  initServeMode();

  // Only auto-fetch when an explicit ?data= URL is provided
  const params = new URLSearchParams(window.location.search);
  const dataUrl = params.get('data');

  if (dataUrl) {
    try {
      const { dataset, events } = await loadFromUrl(dataUrl);
      mountDashboard(dataset, events);
    } catch (err) {
      showError(`Could not fetch <code>${dataUrl}</code>: ${String(err)}`);
    }
  } else {
    showLanding();
  }
}

function showLanding(): void {
  document.getElementById('loading-state')!.style.display = 'none';
  document.getElementById('dashboard')!.style.display = 'none';
  document.getElementById('error-state')!.style.display = 'flex';
  const p = document.querySelector('#error-state p')!;
  p.innerHTML = LANDING_HINT;

  // Full-page drop target while on landing screen
  document.body.addEventListener('dragover', (e) => e.preventDefault());
  document.body.addEventListener('drop', (e) => {
    e.preventDefault();
    const file = e.dataTransfer?.files[0];
    if (file) handleFileLoad(file);
  });
}

init();
