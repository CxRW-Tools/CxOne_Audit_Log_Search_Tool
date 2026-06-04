export interface Meta {
  tenant: string;
  baseUrl: string;
  dateMin: string;
  dateMax: string;
  total: number;
  eventTypes: number;
  namedActors: number;
  days: number;
}

export interface Dataset {
  meta: Meta;
  cats: string[];
  types: string[];
  typeCat: number[];
  users: string[];
  named: number[];
  events: [string, number, number, Record<string, string>][];
}

export interface DecodedEvent {
  ts: string;
  typeIdx: number;
  userIdx: number;
  data: Record<string, string>;
  type: string;
  cat: string;
  user: string;
  day: string;
  hour: number;
}
