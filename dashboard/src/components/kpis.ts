import type { DecodedEvent } from '../types.js';

export function renderKpis(allEvents: DecodedEvent[]): void {
  const el = document.getElementById('kpis');
  if (!el) return;

  const total = allEvents.length;
  const scansCreated = allEvents.filter((e) => e.type === 'scans.create').length;
  const projectsCreated = allEvents.filter((e) => e.type === 'projects.create').length;
  const logins = allEvents.filter((e) => e.type === 'users.login');
  const loginsTotal = logins.length;
  const loginsOk = logins.filter((e) => e.data.status === 'OK').length;
  const loginsFail = logins.filter((e) => e.data.status === 'FAIL').length;
  const downloads = allEvents.filter((e) => e.type === 'source-code.download').length;

  el.innerHTML = `
    <div class="kpi-card kpi-total">
      <div class="kpi-label">Total Events</div>
      <div class="kpi-value">${total.toLocaleString()}</div>
    </div>
    <div class="kpi-card kpi-scans">
      <div class="kpi-label">Scans Created</div>
      <div class="kpi-value">${scansCreated.toLocaleString()}</div>
    </div>
    <div class="kpi-card kpi-projects">
      <div class="kpi-label">Projects Created</div>
      <div class="kpi-value">${projectsCreated.toLocaleString()}</div>
    </div>
    <div class="kpi-card kpi-logins">
      <div class="kpi-label">Logins</div>
      <div class="kpi-value">${loginsTotal.toLocaleString()}</div>
      <div class="kpi-sub">${loginsOk.toLocaleString()} successful</div>
    </div>
    <div class="kpi-card ${loginsFail > 0 ? 'kpi-warn' : 'kpi-logins'}">
      <div class="kpi-label">Failed Logins</div>
      <div class="kpi-value">${loginsFail.toLocaleString()}</div>
    </div>
    <div class="kpi-card ${downloads > 0 ? 'kpi-alert' : 'kpi-downloads'}">
      <div class="kpi-label">Source-Code Downloads</div>
      <div class="kpi-value">${downloads.toLocaleString()}</div>
    </div>
  `;
}
