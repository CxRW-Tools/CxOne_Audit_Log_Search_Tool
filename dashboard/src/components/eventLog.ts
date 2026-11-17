import { rows, cached, cachedData, allEvents, getTimeZone, getDataset, type FieldKey } from '../state.js';
import type { DecodedEvent } from '../types.js';
import { esc, fmtTimestamp, fmtValue, isUuid, splitActor } from '../format.js';
import { copyText, download, exportFileName, toApiEvent, toCsv, toJson } from '../export.js';
import { CAT_COLORS } from './chartUtils.js';

type SortKey = 'ts' | 'type' | 'cat' | 'user' | 'ip';
type SortDir = 'asc' | 'desc';

/** Called when the user filters/excludes on a value from the detail view. */
export type PivotHandler = (field: FieldKey, value: string, exclude: boolean, e: DecodedEvent) => void;

let _sortKey: SortKey = 'ts';
let _sortDir: SortDir = 'desc';
let _page = 0;
let _pivot: PivotHandler = () => {};
const _open = new Set<number>(); // expanded rows, by event idx
const PAGE_SIZE = 100;

const KEY_DETAIL_PRIORITY = ['projectName', 'username', 'fileName', 'status', 'assignedRoleNames', 'scanId', 'projectId', 'initiator'];

function keyDetail(data: Record<string, unknown>): string {
  const keys = KEY_DETAIL_PRIORITY.filter((k) => data[k] !== undefined && data[k] !== '');
  const pick = (keys.length ? keys : Object.keys(data)).slice(0, 2);
  return pick.map((k) => `${k}: ${fmtValue(data[k])}`).join(' · ');
}

function sorted(): DecodedEvent[] {
  return cached(`sorted:${_sortKey}:${_sortDir}`, () => {
    const dir = _sortDir === 'asc' ? 1 : -1;
    const key = _sortKey;
    return [...rows()].sort((a, b) => {
      let cmp: number;
      if (key === 'ts') cmp = a.epoch - b.epoch;
      else if (key === 'ip') cmp = (a.ip ?? '').localeCompare(b.ip ?? '', undefined, { numeric: true });
      else cmp = a[key].localeCompare(b[key]);
      return (cmp || a.epoch - b.epoch) * dir;
    });
  });
}

function catPill(cat: string): string {
  const color = CAT_COLORS[cat] ?? '#a99fc0';
  return `<span class="cat-pill" style="background:${color}20;border-color:${color};color:${color}">${esc(cat)}</span>`;
}

function actorCell(user: string): string {
  if (isUuid(user)) return `<span class="actor-id" title="${esc(user)}">${esc(user.slice(0, 8))}…</span>`;
  const { name, username } = splitActor(user);
  return `${esc(name)}${username ? ` <span class="actor-username">${esc(username)}</span>` : ''}`;
}

function pivotButtons(field: FieldKey, value: string): string {
  const v = esc(value);
  return `<span class="pivot">
    <button type="button" class="pivot-btn" data-pivot="include" data-field="${esc(field)}" data-value="${v}" title="Show only events with this value" aria-label="Filter to ${v}">＋</button>
    <button type="button" class="pivot-btn" data-pivot="exclude" data-field="${esc(field)}" data-value="${v}" title="Hide events with this value" aria-label="Exclude ${v}">−</button>
  </span>`;
}

function detailField(label: string, value: string, field: FieldKey | null, raw = false): string {
  if (!value) return '';
  return `<div class="detail-field"><strong>${esc(label)}</strong><span class="detail-value">${raw ? value : esc(value)}</span>${field ? pivotButtons(field, value) : ''}</div>`;
}

function detailHtml(e: DecodedEvent, tz: ReturnType<typeof getTimeZone>): string {
  const fields = [
    detailField('Timestamp', `${fmtTimestamp(e, tz)}${tz === 'local' ? ` · ${e.ts}Z` : ''}`, null),
    detailField('Event type', e.type, 'type'),
    `<div class="detail-field"><strong>Category</strong><span class="detail-value">${catPill(e.cat)}</span>${pivotButtons('cat', e.cat)}</div>`,
    detailField('Actor', e.user, 'user'),
    detailField('IP address', e.ip ?? '', 'ip'),
    detailField('Action', e.action ?? '', 'action'),
    detailField('Resource', e.resource ?? '', 'resource'),
    detailField('Event ID', e.id ?? '', null),
    ...Object.entries(e.data).map(([k, v]) => detailField(k, fmtValue(v), `data.${k}`)),
  ];
  return `
    <div class="detail-expanded">${fields.join('')}</div>
    <div class="detail-actions">
      <button type="button" class="small-btn" data-copy="${e.idx}">Copy JSON</button>
      <span class="copy-status" aria-live="polite"></span>
    </div>`;
}

export function resetEventLogPage(): void {
  _page = 0;
}

export function initEventLog(onPivot: PivotHandler): void {
  _pivot = onPivot;
  const container = document.getElementById('event-log');
  if (!container || container.dataset.wired) return;
  container.dataset.wired = '1';

  // One delegated listener; the table is re-rendered often.
  container.addEventListener('click', (ev) => {
    const t = ev.target as HTMLElement;

    const sortBtn = t.closest<HTMLElement>('[data-sort]');
    if (sortBtn) {
      const key = sortBtn.dataset.sort as SortKey;
      if (_sortKey === key) _sortDir = _sortDir === 'asc' ? 'desc' : 'asc';
      else {
        _sortKey = key;
        _sortDir = key === 'ts' ? 'desc' : 'asc';
      }
      renderEventLog();
      container.querySelector<HTMLElement>(`[data-sort="${key}"]`)?.focus();
      return;
    }

    const pivot = t.closest<HTMLElement>('[data-pivot]');
    if (pivot) {
      const row = pivot.closest<HTMLElement>('[data-detail-for]');
      const e = row ? allEvents()[Number(row.dataset.detailFor)] : undefined;
      if (e) _pivot(pivot.dataset.field as FieldKey, pivot.dataset.value ?? '', pivot.dataset.pivot === 'exclude', e);
      return;
    }

    const copy = t.closest<HTMLElement>('[data-copy]');
    if (copy) {
      const e = allEvents()[Number(copy.dataset.copy)];
      const status = copy.parentElement?.querySelector('.copy-status');
      void copyText(JSON.stringify(toApiEvent(e), null, 2)).then((ok) => {
        if (status) status.textContent = ok ? 'Copied' : 'Copy failed';
      });
      return;
    }

    const exp = t.closest<HTMLElement>('[data-export]');
    if (exp) {
      const fmt = exp.dataset.export as 'csv' | 'json';
      const events = sorted();
      const tenant = getDataset()?.meta.tenant ?? '';
      if (fmt === 'csv') download(toCsv(events), exportFileName(tenant, 'csv'), 'text/csv;charset=utf-8');
      else download(toJson(events), exportFileName(tenant, 'json'), 'application/json');
      return;
    }

    if (t.closest('#show-more-btn')) {
      _page++;
      renderEventLog();
      return;
    }

    const row = t.closest<HTMLElement>('.log-row');
    if (row) toggleRow(row);
  });

  container.addEventListener('keydown', (ev) => {
    const row = (ev.target as HTMLElement).closest?.<HTMLElement>('.log-row');
    if (row && ev.target === row && (ev.key === 'Enter' || ev.key === ' ')) {
      ev.preventDefault();
      toggleRow(row);
    }
  });
}

function toggleRow(row: HTMLElement): void {
  const idx = Number(row.dataset.idx);
  const detailRow = row.nextElementSibling as HTMLElement | null;
  if (!detailRow) return;
  const open = !_open.has(idx);
  if (open) {
    _open.add(idx);
    detailRow.querySelector('td')!.innerHTML = detailHtml(allEvents()[idx], getTimeZone());
  } else _open.delete(idx);
  detailRow.hidden = !open;
  row.classList.toggle('row-open', open);
  row.setAttribute('aria-expanded', String(open));
}

export function renderEventLog(): void {
  const container = document.getElementById('event-log');
  if (!container) return;

  const scoped = sorted();
  const total = scoped.length;
  const showing = Math.min((_page + 1) * PAGE_SIZE, total);
  const visible = scoped.slice(0, showing);
  const tz = getTimeZone();
  const hasIp = cachedData('hasIp', () => allEvents().some((e) => e.ip));

  if (total === 0) {
    container.innerHTML = `<div class="empty-state">No events match the current filters.</div>`;
    return;
  }

  const th = (key: SortKey, label: string) => {
    const active = _sortKey === key;
    const aria = active ? (_sortDir === 'asc' ? 'ascending' : 'descending') : 'none';
    const ind = active ? (_sortDir === 'asc' ? ' ▲' : ' ▼') : '';
    return `<th aria-sort="${aria}"><button type="button" class="th-btn" data-sort="${key}">${label}${ind}</button></th>`;
  };
  const cols = hasIp ? 6 : 5;

  const body = visible
    .map((e) => {
      const open = _open.has(e.idx);
      return `
      <tr class="log-row${open ? ' row-open' : ''}" data-idx="${e.idx}" tabindex="0" aria-expanded="${open}">
        <td class="mono ts-cell">${esc(fmtTimestamp(e, tz))}</td>
        <td class="type-cell">${esc(e.type)}</td>
        <td>${catPill(e.cat)}</td>
        <td class="user-cell" title="${esc(e.user)}">${actorCell(e.user)}</td>
        ${hasIp ? `<td class="mono ip-cell">${esc(e.ip ?? '')}</td>` : ''}
        <td class="detail-cell">${esc(keyDetail(e.data))}</td>
      </tr>
      <tr class="log-detail-row" data-detail-for="${e.idx}"${open ? '' : ' hidden'}>
        <td colspan="${cols}">${open ? detailHtml(e, tz) : ''}</td>
      </tr>`;
    })
    .join('');

  container.innerHTML = `
    <div class="log-header">
      <span class="log-count">Showing ${showing.toLocaleString()} of ${total.toLocaleString()} events in scope</span>
      <span class="log-actions">
        <button type="button" class="small-btn" data-export="csv" title="Download all ${total.toLocaleString()} filtered events">Export CSV</button>
        <button type="button" class="small-btn" data-export="json" title="Download all ${total.toLocaleString()} filtered events (loads back into the dashboard)">Export JSON</button>
      </span>
    </div>
    <div class="table-wrapper">
      <table class="event-table">
        <thead>
          <tr>
            ${th('ts', 'Timestamp')}${th('type', 'Event Type')}${th('cat', 'Category')}${th('user', 'Actor')}${hasIp ? th('ip', 'IP') : ''}
            <th>Key Detail</th>
          </tr>
        </thead>
        <tbody>${body}</tbody>
      </table>
    </div>
    ${showing < total ? `<button type="button" id="show-more-btn" class="show-more-btn">Show ${Math.min(PAGE_SIZE, total - showing).toLocaleString()} more</button>` : ''}
  `;
}
