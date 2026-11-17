// Export / copy of events in the CxOne API's shape, so exported JSON can be loaded back in.
import type { DecodedEvent } from './types.js';

export interface ApiShapedEvent {
  eventID?: string;
  eventDate: string;
  eventType: string;
  auditResource?: string;
  actionType?: string;
  actionUserId: string;
  ipAddress?: string;
  data: Record<string, unknown>;
}

export function toApiEvent(e: DecodedEvent): ApiShapedEvent {
  const out: ApiShapedEvent = { eventDate: e.ts + 'Z', eventType: e.type, actionUserId: e.user, data: e.data };
  if (e.id) out.eventID = e.id;
  if (e.resource) out.auditResource = e.resource;
  if (e.action) out.actionType = e.action;
  if (e.ip) out.ipAddress = e.ip;
  // Stable key order for readability.
  return {
    ...(out.eventID ? { eventID: out.eventID } : {}),
    eventDate: out.eventDate,
    eventType: out.eventType,
    ...(out.auditResource ? { auditResource: out.auditResource } : {}),
    ...(out.actionType ? { actionType: out.actionType } : {}),
    actionUserId: out.actionUserId,
    ...(out.ipAddress ? { ipAddress: out.ipAddress } : {}),
    data: out.data,
  };
}

/** Same columns as the CLI's --csv export, plus category, so it loads back into the dashboard. */
export const CSV_COLUMNS = ['eventID', 'eventDate', 'eventType', 'category', 'auditResource', 'actionType', 'actionUserId', 'ipAddress', 'data'] as const;

export function csvCell(v: string): string {
  // Quote when needed; neutralise spreadsheet formula injection (=, +, -, @ at the start).
  let s = v;
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export function toCsv(events: DecodedEvent[]): string {
  const lines = [CSV_COLUMNS.join(',')];
  for (const e of events) {
    const row = [e.id ?? '', e.ts + 'Z', e.type, e.cat, e.resource ?? '', e.action ?? '', e.user, e.ip ?? '', JSON.stringify(e.data)];
    lines.push(row.map(csvCell).join(','));
  }
  return '﻿' + lines.join('\r\n') + '\r\n'; // BOM so Excel opens it as UTF-8
}

export function toJson(events: DecodedEvent[]): string {
  return JSON.stringify(events.map(toApiEvent), null, 2);
}

export function exportFileName(tenant: string, ext: 'csv' | 'json', now = new Date()): string {
  const stamp = now.toISOString().slice(0, 19).replace(/[-:]/g, '').replace('T', '_');
  const t = (tenant || 'export').replace(/[^\w.-]+/g, '_');
  return `audit_events_${t}_${stamp}_filtered.${ext}`;
}

export function download(content: string, fileName: string, type: string): void {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = document.createElement('a');
  a.href = url;
  a.download = fileName;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    // Fallback for file:// pages or browsers without clipboard permission.
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand('copy');
    ta.remove();
    return ok;
  }
}
