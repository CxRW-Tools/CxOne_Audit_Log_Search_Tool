// Display formatting. Data is stored untouched; everything here is presentation only.
import type { DecodedEvent, TimeZoneMode } from './types.js';

export const UNRESOLVED = 'Unresolved / System';
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Format any event value for display: arrays joined, objects as compact JSON. */
export function fmtValue(v: unknown): string {
  if (v === null || v === undefined) return '';
  if (Array.isArray(v)) return v.map((x) => (x !== null && typeof x === 'object' ? JSON.stringify(x) : String(x))).join(', ');
  if (typeof v === 'object') return JSON.stringify(v);
  return String(v);
}

export function isUuid(s: string): boolean {
  return UUID_RE.test(s);
}

/** "Jane Doe (jdoe)" → { name: "Jane Doe", username: "jdoe" }. IDs and system keep the label as name. */
export function splitActor(label: string): { name: string; username: string | null } {
  const m = label.match(/^(.*\S)\s+\(([^()]*)\)$/);
  return m ? { name: m[1], username: m[2] } : { name: label, username: null };
}

/** Short form for chart axes: names stay readable, bare IDs are shortened. */
export function actorShort(label: string, max = 28): string {
  if (isUuid(label)) return label.slice(0, 8) + '…';
  return label.length > max ? label.slice(0, max - 1) + '…' : label;
}

export function truncate(s: string, maxLen: number): string {
  return s.length > maxLen ? s.slice(0, maxLen - 1) + '…' : s;
}

const pad = (n: number) => String(n).padStart(2, '0');

/** "2026-11-17 14:03:22 UTC" or local "2026-11-17 09:03:22 GMT-5". */
export function fmtTimestamp(e: Pick<DecodedEvent, 'epoch'>, tz: TimeZoneMode): string {
  const d = new Date(e.epoch);
  if (tz === 'utc') {
    return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())} UTC`;
  }
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())} ${tzOffsetLabel(d)}`;
}

/** "GMT-5", "GMT+5:30" for a given instant in the browser's zone. */
export function tzOffsetLabel(d = new Date()): string {
  const off = -d.getTimezoneOffset();
  const sign = off >= 0 ? '+' : '-';
  const h = Math.floor(Math.abs(off) / 60);
  const m = Math.abs(off) % 60;
  return `GMT${sign}${h}${m ? ':' + pad(m) : ''}`;
}

export function tzLabel(tz: TimeZoneMode): string {
  return tz === 'utc' ? 'UTC' : `local time (${tzOffsetLabel()})`;
}

export function esc(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

export const pct = (part: number, whole: number) => (whole ? Math.round((part / whole) * 100) : 0);
