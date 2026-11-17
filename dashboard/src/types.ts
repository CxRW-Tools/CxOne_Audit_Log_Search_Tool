/** Where the loaded data came from (shown in the source banner). */
export type DataSource =
  | { kind: 'file'; name: string }
  | { kind: 'query'; start: string; end: string; search: string; humanReadable: boolean; compare: boolean }
  | { kind: 'url'; url: string };

export interface Meta {
  tenant: string;
  baseUrl: string;
  dateMin: string;
  dateMax: string;
  total: number;
  eventTypes: number;
  namedActors: number;
  days: number;
  source?: DataSource;
}

/** API fields kept alongside each event. All optional: .log exports don't carry them. */
export interface EventExtra {
  id?: string;
  ip?: string;
  action?: string;
  resource?: string;
}

/**
 * Event values are kept exactly as the API returned them (strings, numbers, arrays, objects);
 * formatting for display happens at render time (see format.ts).
 */
export type EventData = Record<string, unknown>;

export interface Dataset {
  meta: Meta;
  cats: string[];
  types: string[];
  typeCat: number[];
  users: string[];
  named: number[];
  /** [timestamp (UTC, seconds, no Z), typeIdx, userIdx, data, extra?] — extra is absent in older files. */
  events: [string, number, number, EventData, EventExtra?][];
}

export type TimeZoneMode = 'utc' | 'local';

export interface DecodedEvent {
  /** Position in the loaded dataset; stable id for highlights and pivots. */
  idx: number;
  /** UTC timestamp, "YYYY-MM-DDTHH:MM:SS" (no Z). */
  ts: string;
  /** Milliseconds since epoch (UTC). */
  epoch: number;
  typeIdx: number;
  userIdx: number;
  data: EventData;
  type: string;
  cat: string;
  /** Actor exactly as exported: "First Last (username)", a user ID, or "Unresolved / System". */
  user: string;
  id?: string;
  ip?: string;
  action?: string;
  resource?: string;
  /** Day / hour / weekday in the selected display time zone (see applyTimeZone). */
  day: string;
  hour: number;
  weekday: number;
  /** Lower-cased text for free-text search, built once at load. */
  search: string;
}
