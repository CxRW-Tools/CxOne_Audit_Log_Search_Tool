import type { Dataset, DecodedEvent, TimeZoneMode } from './types.js';
import { parseAuditLog } from './parser.js';
import { looksLikeRawExport, parseCsvExport, parseRawExport } from './apiExport.js';

export function decodeDataset(ds: Dataset, tz: TimeZoneMode = 'utc'): DecodedEvent[] {
  const events = ds.events.map(([ts, typeIdx, userIdx, data, extra], idx): DecodedEvent => {
    const type = ds.types[typeIdx];
    const cat = ds.cats[ds.typeCat[typeIdx]];
    const user = ds.users[userIdx];
    const e: DecodedEvent = {
      idx,
      ts,
      epoch: Date.parse(ts + 'Z'),
      typeIdx,
      userIdx,
      data: data ?? {},
      type,
      cat,
      user,
      id: extra?.id,
      ip: extra?.ip,
      action: extra?.action,
      resource: extra?.resource,
      day: '',
      hour: 0,
      weekday: 0,
      // Built once here so free-text search never re-serializes events per keystroke.
      search: [type, cat, user, extra?.ip ?? '', extra?.id ?? '', JSON.stringify(data ?? {})].join('\u0001').toLowerCase(),
    };
    return e;
  });
  applyTimeZone(events, tz);
  return events;
}

const pad = (n: number) => String(n).padStart(2, '0');

/** (Re)compute day / hour / weekday in the display time zone. */
export function applyTimeZone(events: DecodedEvent[], tz: TimeZoneMode): void {
  for (const e of events) {
    if (tz === 'utc' || Number.isNaN(e.epoch)) {
      e.day = e.ts.slice(0, 10);
      e.hour = parseInt(e.ts.slice(11, 13), 10) || 0;
      e.weekday = Number.isNaN(e.epoch) ? 0 : new Date(e.epoch).getUTCDay();
    } else {
      const d = new Date(e.epoch);
      e.day = `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
      e.hour = d.getHours();
      e.weekday = d.getDay();
    }
  }
}

export async function loadFromUrl(url: string): Promise<{ dataset: Dataset; events: DecodedEvent[] }> {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);
  const dataset: Dataset = await res.json();
  return { dataset, events: decodeDataset(dataset) };
}

/** PowerShell `>` redirects write UTF-16LE with a BOM; everything else is UTF-8. TextDecoder strips the BOM. */
async function readText(file: File): Promise<string> {
  const buf = await file.arrayBuffer();
  const b = new Uint8Array(buf);
  const encoding = b[0] === 0xff && b[1] === 0xfe ? 'utf-16le' : 'utf-8';
  return new TextDecoder(encoding).decode(buf);
}

function isDataset(v: unknown): v is Dataset {
  const o = v as Partial<Dataset> | null;
  return !!o && !Array.isArray(o) && Array.isArray(o.types) && Array.isArray(o.events) && !!o.meta;
}

function isCsv(name: string, text: string): boolean {
  if (name.toLowerCase().endsWith('.csv')) return true;
  const first = text.slice(0, text.indexOf('\n') >>> 0).split(',').map((s) => s.trim());
  return first.includes('eventDate') && first.includes('eventType');
}

/**
 * Accepts every Search Tool output, detected by content rather than extension:
 *   - formatted stdout redirected to a file (.log/.txt)
 *   - --raw stdout redirected to a file, or a bare JSON event array
 *   - --csv export
 *   - the dashboard's own pre-processed Dataset JSON
 */
export function parseText(text: string, fileName = ''): Dataset {
  if (isCsv(fileName, text)) return parseCsvExport(text, fileName);

  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    parsed = undefined;
  }
  if (isDataset(parsed)) return parsed;
  if (parsed !== undefined || looksLikeRawExport(text)) return parseRawExport(text);

  const ds = parseAuditLog(text);
  if (ds.events.length === 0) {
    throw new Error('No audit events found in this file. Supported: Search Tool console output, --raw JSON, or --csv.');
  }
  return ds;
}

export async function loadFromFile(file: File): Promise<{ dataset: Dataset; events: DecodedEvent[] }> {
  const dataset = parseText(await readText(file), file.name);
  return { dataset, events: decodeDataset(dataset) };
}
