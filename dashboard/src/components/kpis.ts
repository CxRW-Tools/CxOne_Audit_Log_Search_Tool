import type { DecodedEvent } from '../types.js';
import { getFilter, setFilter, resetFilter } from '../state.js';

type Callback = () => void;
let _cb: Callback = () => {};

export function initKpis(cb: Callback): void {
  _cb = cb;
}

export function renderKpis(allEvents: DecodedEvent[]): void {
  const el = document.getElementById('kpis');
  if (!el) return;

  const f = getFilter();

  const total = allEvents.length;
  const scansCreated = allEvents.filter((e) => e.type === 'scans.create').length;
  const projectsCreated = allEvents.filter((e) => e.type === 'projects.create').length;
  const logins = allEvents.filter((e) => e.type === 'users.login');
  const loginsTotal = logins.length;
  const loginsOk = logins.filter((e) => e.data.status === 'OK').length;
  const loginsFail = logins.filter((e) => e.data.status === 'FAIL').length;
  const downloads = allEvents.filter((e) => e.type === 'source-code.download').length;

  // Determine which card (if any) is active
  const activeScans = f.type === 'scans.create' && !f.q;
  const activeProjects = f.type === 'projects.create' && !f.q;
  const activeLogins = f.type === 'users.login' && !f.q;
  const activeFailedLogins = f.type === 'users.login' && f.q === 'FAIL';
  const activeDownloads = f.type === 'source-code.download' && !f.q;
  const activeTotal = !f.cat && !f.type && !f.user && !f.day && !f.q;

  el.innerHTML = `
    <div class="kpi-card kpi-total${activeTotal ? ' kpi-active' : ''}" data-kpi="total" title="Show all events">
      <div class="kpi-label">Total Events</div>
      <div class="kpi-value">${total.toLocaleString()}</div>
    </div>
    <div class="kpi-card kpi-scans${activeScans ? ' kpi-active' : ''}" data-kpi="scans" title="Filter to scans.create">
      <div class="kpi-label">Scans Created</div>
      <div class="kpi-value">${scansCreated.toLocaleString()}</div>
    </div>
    <div class="kpi-card kpi-projects${activeProjects ? ' kpi-active' : ''}" data-kpi="projects" title="Filter to projects.create">
      <div class="kpi-label">Projects Created</div>
      <div class="kpi-value">${projectsCreated.toLocaleString()}</div>
    </div>
    <div class="kpi-card kpi-logins${activeLogins ? ' kpi-active' : ''}" data-kpi="logins" title="Filter to users.login">
      <div class="kpi-label">Logins</div>
      <div class="kpi-value">${loginsTotal.toLocaleString()}</div>
      <div class="kpi-sub">${loginsOk.toLocaleString()} successful</div>
    </div>
    <div class="kpi-card ${loginsFail > 0 ? 'kpi-warn' : 'kpi-logins'}${activeFailedLogins ? ' kpi-active' : ''}" data-kpi="failed-logins" title="Filter to failed logins">
      <div class="kpi-label">Failed Logins</div>
      <div class="kpi-value">${loginsFail.toLocaleString()}</div>
    </div>
    <div class="kpi-card ${downloads > 0 ? 'kpi-alert' : 'kpi-downloads'}${activeDownloads ? ' kpi-active' : ''}" data-kpi="downloads" title="Filter to source-code.download">
      <div class="kpi-label">Source-Code Downloads</div>
      <div class="kpi-value">${downloads.toLocaleString()}</div>
    </div>
  `;

  el.querySelectorAll('.kpi-card').forEach((card) => {
    card.addEventListener('click', () => {
      const kpi = (card as HTMLElement).dataset.kpi!;
      handleKpiClick(kpi);
    });
  });
}

function handleKpiClick(kpi: string): void {
  const f = getFilter();

  if (kpi === 'total') {
    resetFilter();
  } else if (kpi === 'scans') {
    if (f.type === 'scans.create' && !f.q) resetFilter();
    else setFilter({ cat: 'Scanning', type: 'scans.create', user: null, day: null, q: '' });
  } else if (kpi === 'projects') {
    if (f.type === 'projects.create' && !f.q) resetFilter();
    else setFilter({ cat: 'Project Mgmt', type: 'projects.create', user: null, day: null, q: '' });
  } else if (kpi === 'logins') {
    if (f.type === 'users.login' && !f.q) resetFilter();
    else setFilter({ cat: 'Identity & Auth', type: 'users.login', user: null, day: null, q: '' });
  } else if (kpi === 'failed-logins') {
    if (f.type === 'users.login' && f.q === 'FAIL') resetFilter();
    else setFilter({ cat: 'Identity & Auth', type: 'users.login', user: null, day: null, q: 'FAIL' });
  } else if (kpi === 'downloads') {
    if (f.type === 'source-code.download' && !f.q) resetFilter();
    else setFilter({ cat: 'Data Access', type: 'source-code.download', user: null, day: null, q: '' });
  }

  _cb();
}
