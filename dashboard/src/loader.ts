import type { Dataset, DecodedEvent } from './types.js';
import { parseAuditLog } from './parser.js';

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

export async function loadFromFile(file: File): Promise<{ dataset: Dataset; events: DecodedEvent[] }> {
  const isLog = file.name.endsWith('.log') || file.name.endsWith('.txt');
  const isJson = file.name.endsWith('.json');

  if (isJson) {
    const text = await file.text();
    const dataset: Dataset = JSON.parse(text);
    return { dataset, events: decodeDataset(dataset) };
  }

  if (isLog) {
    const buf = await file.arrayBuffer();
    const bytes = new Uint8Array(buf);
    let text: string;
    // Detect UTF-16LE BOM: 0xFF 0xFE
    if (bytes[0] === 0xff && bytes[1] === 0xfe) {
      text = new TextDecoder('utf-16le').decode(buf);
    } else {
      text = new TextDecoder('utf-8').decode(buf);
    }
    const dataset = parseAuditLog(text);
    return { dataset, events: decodeDataset(dataset) };
  }

  // Try JSON first, then log parsing
  const text = await file.text();
  try {
    const dataset: Dataset = JSON.parse(text);
    return { dataset, events: decodeDataset(dataset) };
  } catch {
    const dataset = parseAuditLog(text);
    return { dataset, events: decodeDataset(dataset) };
  }
}
