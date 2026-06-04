import './theme.css';
import { loadFromUrl, loadFromFile } from './loader.js';
import { setData, scopeSummary } from './state.js';
import type { Dataset, DecodedEvent } from './types.js';
import { renderKpis } from './components/kpis.js';
import { initBreadcrumb, renderBreadcrumb } from './components/breadcrumb.js';
import { initDrillChart, renderDrillChart } from './components/drillChart.js';
import { initActorChart, renderActorChart } from './components/actorChart.js';
import { initTrendChart, renderTrendChart } from './components/trendChart.js';
import { renderHourChart } from './components/hourChart.js';
import { renderEventLog, resetEventLogPage } from './components/eventLog.js';

let _allEvents: DecodedEvent[] = [];

function refresh(): void {
  resetEventLogPage();
  renderBreadcrumb();
  renderScopeSummary();
  renderDrillChart();
  renderActorChart();
  renderTrendChart();
  renderHourChart();
  renderEventLog();
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

  renderKpis(_allEvents);
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
  p.innerHTML = `<strong>Failed to load audit data.</strong><br>${msg}<br><br>Drop a <code>.json</code> or <code>.log</code> file to load data manually.`;
}

async function handleFileLoad(file: File): Promise<void> {
  try {
    document.getElementById('loading-state')!.style.display = 'flex';
    document.getElementById('error-state')!.style.display = 'none';
    document.getElementById('dashboard')!.style.display = 'none';
    const { dataset, events } = await loadFromFile(file);
    mountDashboard(dataset, events);
  } catch (err) {
    showError(String(err));
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
  p.innerHTML = `Drop a <code>.json</code> or <code>.log</code> export here, or click <strong>Load file</strong> to get started.`;

  // Full-page drop target while on landing screen
  document.body.addEventListener('dragover', (e) => e.preventDefault());
  document.body.addEventListener('drop', (e) => {
    e.preventDefault();
    const file = e.dataTransfer?.files[0];
    if (file) handleFileLoad(file);
  });
}

init();
