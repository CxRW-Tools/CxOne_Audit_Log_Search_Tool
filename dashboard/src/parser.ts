import type { Dataset } from './types.js';

const CATEGORY_MAP: Record<string, string> = {
  users: 'Identity & Auth',
  mfa: 'Identity & Auth',
  'identity-provider': 'Identity & Auth',
  'oauth2-client': 'Identity & Auth',
  realm: 'Identity & Auth',
  role: 'Access Control',
  groups: 'Access Control',
  assignment: 'Access Control',
  scans: 'Scanning',
  'sca-results': 'Scanning',
  'source-code': 'Data Access',
  'contributing-developers': 'Data Access',
  projects: 'Project Mgmt',
  'project-settings': 'Project Mgmt',
  applications: 'Project Mgmt',
  environment: 'Config',
  'tenant-settings': 'Config',
  link: 'Config',
};

export function categoryFor(eventType: string): string {
  const prefix = eventType.split('.')[0];
  return CATEGORY_MAP[prefix] ?? 'Other';
}

export function actorLabel(actionUser: string): string {
  const trimmed = actionUser.trim();
  if (!trimmed || trimmed === 'Unresolved User ID') return 'Unresolved / System';
  const match = trimmed.match(/^(.*) \(.*\)$/);
  if (match) return match[1].trim();
  // bare UUID or unrecognized
  return trimmed.slice(0, 8) + '…';
}

export function isNamed(label: string): boolean {
  return label !== 'Unresolved / System' && !label.includes('…');
}

const SEPARATOR = '----------------------------------------';
const MAX_VAL_LEN = 120;

export function parseAuditLog(text: string): Dataset {
  // Normalize CRLF -> LF
  const normalized = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  const lines = normalized.split('\n');

  let tenant = '';
  let baseUrl = '';

  // Split into blocks by separator
  const blocks: string[][] = [];
  let currentBlock: string[] = [];
  let headerDone = false;

  for (const line of lines) {
    if (line === SEPARATOR) {
      if (currentBlock.length > 0) {
        blocks.push(currentBlock);
        currentBlock = [];
      }
      headerDone = true;
    } else {
      if (!headerDone) {
        // Parse header metadata
        if (line.startsWith('Tenant:')) tenant = line.slice(7).trim();
        if (line.startsWith('Base URL:')) baseUrl = line.slice(9).trim();
      } else {
        currentBlock.push(line);
      }
    }
  }
  if (currentBlock.length > 0) blocks.push(currentBlock);

  // Parse each block into raw event tuples
  interface RawEvent {
    ts: string;
    eventType: string;
    actorLabel: string;
    data: Record<string, string>;
  }

  const rawEvents: RawEvent[] = [];

  for (const block of blocks) {
    let ts = '';
    let eventType = '';
    let actor = '';
    const data: Record<string, string> = {};
    let inData = false;

    for (const line of block) {
      if (line.startsWith('Event Date:')) {
        ts = line.slice(11).trim();
      } else if (line.startsWith('Event Type:')) {
        eventType = line.slice(11).trim();
      } else if (line.startsWith('Action User:')) {
        actor = line.slice(12).trim();
      } else if (line === 'Data:') {
        inData = true;
      } else if (inData && line.startsWith('  ')) {
        const inner = line.slice(2);
        const colonIdx = inner.indexOf(':');
        if (colonIdx > 0) {
          const key = inner.slice(0, colonIdx).trim();
          let val = inner.slice(colonIdx + 1).trim();
          if (val.length > MAX_VAL_LEN) val = val.slice(0, MAX_VAL_LEN);
          data[key] = val;
        }
      } else if (line.trim() !== '') {
        inData = false;
      }
    }

    if (ts && eventType) {
      rawEvents.push({ ts, eventType, actorLabel: actorLabel(actor), data });
    }
  }

  // Build sorted type and user arrays
  const typeSet = new Set<string>();
  const userSet = new Set<string>();
  for (const e of rawEvents) {
    typeSet.add(e.eventType);
    userSet.add(e.actorLabel);
  }

  const types = Array.from(typeSet).sort();
  const users = Array.from(userSet).sort();
  const typeIdx = new Map(types.map((t, i) => [t, i]));
  const userIdx = new Map(users.map((u, i) => [u, i]));

  // Build category list and typeCat mapping
  const catSet = new Set<string>();
  for (const t of types) catSet.add(categoryFor(t));
  const cats = Array.from(catSet).sort();
  const catIdx = new Map(cats.map((c, i) => [c, i]));
  const typeCat = types.map((t) => catIdx.get(categoryFor(t))!);

  // Build named array
  const named = users.map((u) => (isNamed(u) ? 1 : 0));

  // Build events array: trim timestamp to second precision, drop Z
  const events: [string, number, number, Record<string, string>][] = rawEvents.map((e) => {
    // ISO 8601: "2026-05-01T00:38:29.637426Z" -> "2026-05-01T00:38:29"
    const tsTrimmed = e.ts.replace(/\.\d+Z?$/, '').replace(/Z$/, '');
    return [tsTrimmed, typeIdx.get(e.eventType)!, userIdx.get(e.actorLabel)!, e.data];
  });

  // Derive date range from events
  let dateMin = '';
  let dateMax = '';
  for (const [ts] of events) {
    const day = ts.slice(0, 10);
    if (!dateMin || day < dateMin) dateMin = day;
    if (!dateMax || day > dateMax) dateMax = day;
  }

  // Count distinct days
  const daySet = new Set<string>();
  for (const [ts] of events) daySet.add(ts.slice(0, 10));

  const namedActors = users.filter((u) => isNamed(u)).length;

  return {
    meta: {
      tenant,
      baseUrl,
      dateMin,
      dateMax,
      total: events.length,
      eventTypes: types.length,
      namedActors,
      days: daySet.size,
    },
    cats,
    types,
    typeCat,
    users,
    named,
    events,
  };
}
