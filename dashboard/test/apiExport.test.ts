import { describe, it, expect } from 'vitest';
import { parseCsvExport, parseCsvRows, parseRawExport } from '../src/apiExport';
import { parseText } from '../src/loader';

// Shapes mirror the Search Tool's json.dumps(events, indent=2) and csv_export.py.
const events = [
  {
    eventID: 'e1',
    eventDate: '2026-05-01T00:38:29.637426Z',
    eventType: 'scans.create',
    auditResource: 'scans',
    actionType: 'create',
    actionUserId: 'Jane Doe (jdoe)',
    ipAddress: '10.0.0.1',
    data: { projectId: 'p1', engines: ['sast', 'sca'], nested: { a: 1 } },
  },
  {
    eventID: 'e2',
    eventDate: '2026-05-02T13:00:00Z',
    eventType: 'users.login',
    actionUserId: '3f2a91bc-1111-2222-3333-444455556666',
    data: { status: 'FAIL' },
  },
];

const banner = [
  '='.repeat(120),
  'CxOne Audit Log Search',
  '='.repeat(120),
  'Tenant: acme',
  'Base URL: https://ast.checkmarx.net',
  'Date range: 2026-05-01 to 2026-05-31',
  'Output directory: ./output',
  '='.repeat(120),
].join('\n');

describe('parseRawExport', () => {
  it('parses a bare JSON array', () => {
    const ds = parseRawExport(JSON.stringify(events));
    expect(ds.meta.total).toBe(2);
    expect(ds.types).toEqual(['scans.create', 'users.login']);
  });

  it('parses redirected stdout with banner and footer', () => {
    const text = `${banner}\n${JSON.stringify(events, null, 2)}\n\nDone in 3.2s\n`;
    const ds = parseRawExport(text);
    expect(ds.meta.tenant).toBe('acme');
    expect(ds.meta.baseUrl).toBe('https://ast.checkmarx.net');
    expect(ds.meta.total).toBe(2);
  });

  it('maps actors, timestamps and data values (kept as returned)', () => {
    const ds = parseRawExport(JSON.stringify(events));
    const [ts, , userIdx, data] = ds.events[0];
    expect(ts).toBe('2026-05-01T00:38:29');
    expect(ds.users[userIdx]).toBe('Jane Doe (jdoe)');
    expect(ds.named[userIdx]).toBe(1);
    expect(data.engines).toEqual(['sast', 'sca']);
    expect(data.nested).toEqual({ a: 1 });
    const uuidUser = ds.users[ds.events[1][2]];
    expect(uuidUser).toBe('3f2a91bc-1111-2222-3333-444455556666');
    expect(ds.named[ds.events[1][2]]).toBe(0);
    expect(ds.events[1][3].status).toBe('FAIL');
  });

  it('keeps event ID, IP, action type and resource', () => {
    const withExtras = [{ ...events[0], ipAddress: '10.1.2.3' }];
    const ds = parseRawExport(JSON.stringify(withExtras));
    expect(ds.events[0][4]).toEqual({ id: 'e1', ip: '10.1.2.3', action: 'create', resource: 'scans' });
  });

  it('rejects JSON without an event array', () => {
    expect(() => parseRawExport('{"foo":1}')).toThrow(/array of audit events/);
  });
});

describe('parseCsvRows', () => {
  it('handles quotes, doubled quotes, commas, CRLF and embedded newlines', () => {
    const rows = parseCsvRows('a,b,c\r\n"x,1","say ""hi""","line1\nline2"\r\n');
    expect(rows).toEqual([
      ['a', 'b', 'c'],
      ['x,1', 'say "hi"', 'line1\nline2'],
    ]);
  });
});

describe('parseCsvExport', () => {
  const header = 'eventID,eventDate,eventType,auditResource,actionType,actionUserId,ipAddress,data';
  const q = (s: string) => `"${s.replace(/"/g, '""')}"`;
  const csv =
    header +
    '\r\n' +
    events
      .map((e) =>
        [e.eventID, e.eventDate, e.eventType, '', '', e.actionUserId, '', q(JSON.stringify(e.data))].join(','),
      )
      .join('\r\n') +
    '\r\n';

  it('parses rows and the JSON data column', () => {
    const ds = parseCsvExport(csv, 'audit_events_acme_20260601_120000.csv');
    expect(ds.meta.tenant).toBe('acme');
    expect(ds.meta.total).toBe(2);
    expect(ds.events[0][3].projectId).toBe('p1');
    expect(ds.events[1][3].status).toBe('FAIL');
  });

  it('leaves tenant empty for a custom file name', () => {
    expect(parseCsvExport(csv, 'my-export.csv').meta.tenant).toBe('');
  });

  it('rejects CSVs without the expected columns', () => {
    expect(() => parseCsvExport('a,b\n1,2', 'x.csv')).toThrow(/eventDate and eventType/);
  });
});

describe('parseText format detection', () => {
  it('detects CSV by header even without a .csv extension', () => {
    const csv = 'eventDate,eventType,actionUserId,data\n2026-05-01T00:00:00Z,scans.create,x,\n';
    expect(parseText(csv, 'export.txt').meta.total).toBe(1);
  });

  it('detects redirected --raw output saved as .log', () => {
    const text = `${banner}\n${JSON.stringify(events, null, 2)}\nDone in 1.0s\n`;
    expect(parseText(text, 'events.log').meta.total).toBe(2);
  });

  it('still parses formatted console output', () => {
    const text = `${banner}\n${'-'.repeat(40)}\nEvent Date: 2026-05-01T00:00:00Z\nEvent Type: scans.create\nAction User: Jane Doe (jdoe)\nData:\n  projectId: p1\n${'-'.repeat(40)}\n`;
    const ds = parseText(text, 'events.log');
    expect(ds.meta.tenant).toBe('acme');
    expect(ds.meta.total).toBe(1);
  });

  it('errors clearly when nothing is recognized', () => {
    expect(() => parseText('hello world', 'x.log')).toThrow(/No audit events found/);
  });
});
