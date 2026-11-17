import type { Dataset, DecodedEvent } from './types.js';
import { parseAuditLog } from './parser.js';
import { looksLikeRawExport, parseCsvExport, parseRawExport } from './apiExport.js';

export function decodeDataset(ds: Dataset): DecodedEvent[] {
  return ds.events.map(([ts, typeIdx, userIdx, data]) => ({
    ts,
    typeIdx,
    userIdx,
    data,
    type: ds.types[typeIdx],
    cat: ds.cats[ds.typeCat[typeIdx]],
    user: ds.users[userIdx],
    day: ts.slice(0, 10),
    hour: parseInt(ts.slice(11, 13), 10),
  }));
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
