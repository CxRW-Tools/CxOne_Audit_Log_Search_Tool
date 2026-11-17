// Import for the CxOne Audit Log Search Tool's API-shaped exports:
//   --raw  → JSON array of audit events on stdout (usually redirected to a file,
//            so it is wrapped in the tool's banner and "Done in …" footer)
//   --csv  → UTF-8 CSV with eventDate, eventType, actionUserId and a JSON `data` column
import type { Dataset } from './types.js';
import { actorLabel, buildDataset, MAX_VAL_LEN, type RawEvent } from './parser.js';

type ApiEvent = Record<string, unknown>;

function flatten(v: unknown): string {
  if (v === null || v === undefined) return '';
  if (Array.isArray(v)) return v.map((x) => (x !== null && typeof x === 'object' ? JSON.stringify(x) : String(x))).join(', ');
  if (typeof v === 'object') return JSON.stringify(v);
  return String(v);
}

function toRawEvents(items: ApiEvent[]): RawEvent[] {
  const out: RawEvent[] = [];
  for (const it of items) {
    if (!it || typeof it !== 'object') continue;
    const ts = String(it.eventDate ?? '').trim();
    const eventType = String(it.eventType ?? '').trim();
    if (!ts || !eventType) continue;
    const data: Record<string, string> = {};
    const d = it.data;
    if (d && typeof d === 'object' && !Array.isArray(d)) {
      for (const [k, v] of Object.entries(d as Record<string, unknown>)) {
        data[k] = flatten(v).slice(0, MAX_VAL_LEN);
      }
    }
    out.push({ ts, eventType, actorLabel: actorLabel(String(it.actionUserId ?? '')), data });
  }
  return out;
}

/** Read `Tenant:` / `Base URL:` lines from the tool's startup banner, if present. */
function bannerMeta(text: string): { tenant: string; baseUrl: string } {
  const tenant = text.match(/^Tenant:[ \t]*(.*)$/m)?.[1]?.trim() ?? '';
  const baseUrl = text.match(/^Base URL:[ \t]*(.*)$/m)?.[1]?.trim() ?? '';
  return { tenant, baseUrl };
}

/**
 * Extract the JSON array from redirected `--raw` stdout. json.dumps(indent=2) puts the
 * opening `[` and closing `]` on their own lines at column 0, which nothing in the
 * banner or footer does.
 */
function extractJsonArray(text: string): string | null {
  const start = text.search(/^\[\s*$/m);
  if (start < 0) return null;
  const tail = text.slice(start);
  const ends = [...tail.matchAll(/^\]\s*$/gm)];
  if (ends.length === 0) return null;
  const last = ends[ends.length - 1];
  return tail.slice(0, last.index! + 1);
}

/** True when the text looks like Search Tool `--raw` output (bare or with banner). */
export function looksLikeRawExport(text: string): boolean {
  const t = text.trimStart();
  return t.startsWith('[') || (/^Tenant:/m.test(text) && /^\[\s*$/m.test(text));
}

/** Parse Search Tool `--raw` output: a bare JSON array, {events:[…]}, or redirected stdout. */
export function parseRawExport(text: string): Dataset {
  const { tenant, baseUrl } = bannerMeta(text);
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    const arr = extractJsonArray(text);
    if (!arr) throw new Error('No JSON event array found. Run the Search Tool with --raw (or use --csv).');
    parsed = JSON.parse(arr);
  }
  const items = Array.isArray(parsed) ? parsed : (parsed as { events?: unknown })?.events;
  if (!Array.isArray(items)) throw new Error('Unrecognized JSON: expected an array of audit events.');
  return buildDataset(toRawEvents(items as ApiEvent[]), tenant, baseUrl);
}

/** RFC 4180 CSV: quoted fields, doubled quotes, embedded newlines. */
export function parseCsvRows(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = '';
  let quoted = false;
  const flush = () => {
    row.push(field);
    field = '';
    if (row.some((f) => f !== '')) rows.push(row);
    row = [];
  };
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quoted) {
      if (c === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i++;
        } else quoted = false;
      } else field += c;
    } else if (c === '"') quoted = true;
    else if (c === ',') {
      row.push(field);
      field = '';
    } else if (c === '\n') flush();
    else if (c === '\r') {
      if (text[i + 1] === '\n') i++;
      flush();
    } else field += c;
  }
  flush();
  return rows;
}

/**
 * Parse Search Tool `--csv` output. The tenant comes from the default file name
 * (audit_events_<tenant>_<timestamp>.csv) when it matches.
 */
export function parseCsvExport(text: string, fileName = ''): Dataset {
  const rows = parseCsvRows(text);
  if (rows.length === 0) throw new Error('CSV is empty.');
  const header = rows[0].map((h) => h.trim());
  if (!header.includes('eventDate') || !header.includes('eventType')) {
    throw new Error('Unrecognized CSV: expected eventDate and eventType columns.');
  }
  const items: ApiEvent[] = rows.slice(1).map((r) => {
    const o: ApiEvent = {};
    header.forEach((h, i) => (o[h] = r[i] ?? ''));
    const raw = o.data;
    if (typeof raw === 'string' && raw.trim()) {
      try {
        o.data = JSON.parse(raw);
      } catch {
        o.data = { data: raw };
      }
    } else {
      o.data = {};
    }
    return o;
  });
  const base = fileName.split(/[\\/]/).pop() ?? '';
  const tenant = base.match(/^audit_events_(.+)_\d{8}[_-]?\d{4,6}\.csv$/i)?.[1] ?? '';
  return buildDataset(toRawEvents(items), tenant, '');
}
