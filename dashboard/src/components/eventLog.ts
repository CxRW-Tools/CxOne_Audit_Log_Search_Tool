import { rows } from '../state.js';
import type { DecodedEvent } from '../types.js';
import { CAT_COLORS } from './chartUtils.js';

type SortKey = 'ts' | 'type' | 'cat' | 'user';
type SortDir = 'asc' | 'desc';

let _sortKey: SortKey = 'ts';
let _sortDir: SortDir = 'desc';
let _page = 0;
const PAGE_SIZE = 100;

const KEY_DETAIL_PRIORITY = [
  'projectName', 'username', 'fileName', 'scanId', 'projectId',
  'assignedRoleNames', 'status', 'initiator',
];

function keyDetail(data: Record<string, string>): string {
  const parts: string[] = [];
  for (const k of KEY_DETAIL_PRIORITY) {
    if (data[k]) {
      parts.push(`${k}: ${data[k]}`);
      if (parts.length >= 2) break;
    }
  }
  if (!parts.length) {
    const keys = Object.keys(data).slice(0, 2);
    for (const k of keys) parts.push(`${k}: ${data[k]}`);
  }
  return parts.join(' · ');
}

function sortEvents(events: DecodedEvent[]): DecodedEvent[] {
  return [...events].sort((a, b) => {
    let cmp = 0;
    if (_sortKey === 'ts') cmp = a.ts.localeCompare(b.ts);
    else if (_sortKey === 'type') cmp = a.type.localeCompare(b.type);
    else if (_sortKey === 'cat') cmp = a.cat.localeCompare(b.cat);
    else if (_sortKey === 'user') cmp = a.user.localeCompare(b.user);
    return _sortDir === 'asc' ? cmp : -cmp;
  });
}

function esc(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function catPill(cat: string): string {
  const color = CAT_COLORS[cat] ?? '#a99fc0';
  return `<span class="cat-pill" style="background:${color}20;border-color:${color};color:${color}">${esc(cat)}</span>`;
}

export function resetEventLogPage(): void {
  _page = 0;
}

export function renderEventLog(): void {
  const container = document.getElementById('event-log');
  if (!container) return;

  const scoped = sortEvents(rows());
  const total = scoped.length;
  const showing = Math.min((_page + 1) * PAGE_SIZE, total);
  const visible = scoped.slice(0, showing);

  if (total === 0) {
    container.innerHTML = `<div class="empty-state">No events match the current filters.</div>`;
    return;
  }

  const sortIndicator = (key: SortKey) =>
    _sortKey === key ? (_sortDir === 'asc' ? ' ▲' : ' ▼') : '';

  const rows_html = visible.map((e, i) => {
    const detail = keyDetail(e.data);
    return `
      <tr class="log-row" data-idx="${i}">
        <td class="mono ts-cell">${esc(e.ts)}</td>
        <td class="type-cell">${esc(e.type)}</td>
        <td>${catPill(e.cat)}</td>
        <td class="user-cell">${esc(e.user)}</td>
        <td class="detail-cell">${esc(detail)}</td>
      </tr>
      <tr class="log-detail-row" id="detail-${i}" style="display:none">
        <td colspan="5">
          <div class="detail-expanded">
            <div><strong>Timestamp:</strong> ${esc(e.ts + 'Z')}</div>
            <div><strong>Event Type:</strong> ${esc(e.type)}</div>
            <div><strong>Category:</strong> ${catPill(e.cat)}</div>
            <div><strong>Actor:</strong> ${esc(e.user)}</div>
            ${Object.entries(e.data).map(([k, v]) =>
              `<div><strong>${esc(k)}:</strong> ${esc(v)}</div>`
            ).join('')}
          </div>
        </td>
      </tr>
    `;
  }).join('');

  container.innerHTML = `
    <div class="log-header">
      <span class="log-count">Showing ${showing.toLocaleString()} of ${total.toLocaleString()} events in scope</span>
    </div>
    <div class="table-wrapper">
      <table class="event-table">
        <thead>
          <tr>
            <th class="sortable" data-sort="ts">Timestamp${sortIndicator('ts')}</th>
            <th class="sortable" data-sort="type">Event Type${sortIndicator('type')}</th>
            <th class="sortable" data-sort="cat">Category${sortIndicator('cat')}</th>
            <th class="sortable" data-sort="user">Actor${sortIndicator('user')}</th>
            <th>Key Detail</th>
          </tr>
        </thead>
        <tbody>${rows_html}</tbody>
      </table>
    </div>
    ${showing < total
      ? `<button id="show-more-btn" class="show-more-btn">Show ${Math.min(PAGE_SIZE, total - showing).toLocaleString()} more</button>`
      : ''}
  `;

  // Sort header click handlers
  container.querySelectorAll('th.sortable').forEach((th) => {
    th.addEventListener('click', () => {
      const key = (th as HTMLElement).dataset.sort as SortKey;
      if (_sortKey === key) {
        _sortDir = _sortDir === 'asc' ? 'desc' : 'asc';
      } else {
        _sortKey = key;
        _sortDir = key === 'ts' ? 'desc' : 'asc';
      }
      renderEventLog();
    });
  });

  // Row expand/collapse
  container.querySelectorAll('.log-row').forEach((row) => {
    row.addEventListener('click', () => {
      const idx = (row as HTMLElement).dataset.idx!;
      const detailRow = document.getElementById(`detail-${idx}`);
      if (detailRow) {
        const isOpen = detailRow.style.display !== 'none';
        detailRow.style.display = isOpen ? 'none' : 'table-row';
        row.classList.toggle('row-open', !isOpen);
      }
    });
  });

  // Show more
  const showMoreBtn = document.getElementById('show-more-btn');
  if (showMoreBtn) {
    showMoreBtn.addEventListener('click', () => {
      _page++;
      renderEventLog();
    });
  }
}
