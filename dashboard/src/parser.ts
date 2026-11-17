import type { Dataset, EventData, EventExtra } from './types.js';
import { isUuid, UNRESOLVED } from './format.js';

const CATEGORY_MAP: Record<string, string> = {
  users: 'Identity & Auth',
  user: 'Identity & Auth',
  mfa: 'Identity & Auth',
  'identity-provider': 'Identity & Auth',
  'oauth2-client': 'Identity & Auth',
  realm: 'Identity & Auth',
  'api-keys': 'Identity & Auth',
  'api-key': 'Identity & Auth',
  clients: 'Identity & Auth',
  role: 'Access Control',
  roles: 'Access Control',
  groups: 'Access Control',
  group: 'Access Control',
  assignment: 'Access Control',
  assignments: 'Access Control',
  scans: 'Scanning',
  scan: 'Scanning',
  'sca-results': 'Scanning',
  results: 'Scanning',
  'source-code': 'Data Access',
  'contributing-developers': 'Data Access',
  reports: 'Data Access',
  projects: 'Project Mgmt',
  project: 'Project Mgmt',
  'project-settings': 'Project Mgmt',
  applications: 'Project Mgmt',
  application: 'Project Mgmt',
  environment: 'Config',
  'tenant-settings': 'Config',
  tenant: 'Config',
  link: 'Config',
  webhooks: 'Config',
  webhook: 'Config',
  presets: 'Config',
  policies: 'Config',
  queries: 'Config',
};

export function categoryFor(eventType: string): string {
  const prefix = eventType.split('.')[0];
  return CATEGORY_MAP[prefix] ?? 'Other';
}

/**
 * Normalize the exported actor. The full "First Last (username)" form is kept so two people
 * with the same display name stay separate and the username stays searchable; bare user IDs
 * are kept whole (charts shorten them for display only).
 */
export function actorLabel(actionUser: string): string {
  const trimmed = actionUser.trim();
  if (!trimmed || trimmed === 'Unresolved User ID' || trimmed === 'N/A') return UNRESOLVED;
  return trimmed;
}

/** True for resolved people/service accounts; false for system and bare IDs. */
export function isNamed(label: string): boolean {
  return label !== UNRESOLVED && !isUuid(label);
}

const SEPARATOR = '----------------------------------------';

export interface RawEvent {
  ts: string;
  eventType: string;
  actorLabel: string;
  data: EventData;
  extra?: EventExtra;
}

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
    } else if (!headerDone) {
      if (line.startsWith('Tenant:')) tenant = line.slice(7).trim();
      if (line.startsWith('Base URL:')) baseUrl = line.slice(9).trim();
    } else {
      currentBlock.push(line);
    }
  }
  if (currentBlock.length > 0) blocks.push(currentBlock);

  const rawEvents: RawEvent[] = [];
  for (const block of blocks) {
    let ts = '';
    let eventType = '';
    let actor = '';
    const data: EventData = {};
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
        if (colonIdx > 0) data[inner.slice(0, colonIdx).trim()] = inner.slice(colonIdx + 1).trim();
      } else if (line.trim() !== '') {
        inData = false;
      }
    }

    if (ts && eventType) rawEvents.push({ ts, eventType, actorLabel: actorLabel(actor), data });
  }

  return buildDataset(rawEvents, tenant, baseUrl);
}

/** Turn normalized events into the dashboard's compact Dataset shape. */
export function buildDataset(rawEvents: RawEvent[], tenant: string, baseUrl: string): Dataset {
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

  const catSet = new Set<string>();
  for (const t of types) catSet.add(categoryFor(t));
  const cats = Array.from(catSet).sort();
  const catIdx = new Map(cats.map((c, i) => [c, i]));
  const typeCat = types.map((t) => catIdx.get(categoryFor(t))!);

  const named = users.map((u) => (isNamed(u) ? 1 : 0));

  // Trim timestamps to second precision, drop Z: "2026-05-01T00:38:29.637426Z" -> "2026-05-01T00:38:29"
  const events: Dataset['events'] = rawEvents.map((e) => {
    const tsTrimmed = e.ts.replace(/\.\d+Z?$/, '').replace(/Z$/, '');
    const tuple: Dataset['events'][number] = [tsTrimmed, typeIdx.get(e.eventType)!, userIdx.get(e.actorLabel)!, e.data];
    if (e.extra && Object.keys(e.extra).length) tuple.push(e.extra);
    return tuple;
  });

  let dateMin = '';
  let dateMax = '';
  const daySet = new Set<string>();
  for (const [ts] of events) {
    const day = ts.slice(0, 10);
    daySet.add(day);
    if (!dateMin || day < dateMin) dateMin = day;
    if (!dateMax || day > dateMax) dateMax = day;
  }

  return {
    meta: {
      tenant,
      baseUrl,
      dateMin,
      dateMax,
      total: events.length,
      eventTypes: types.length,
      namedActors: users.filter(isNamed).length,
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
