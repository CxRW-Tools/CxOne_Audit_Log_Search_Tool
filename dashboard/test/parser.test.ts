import { describe, it, expect } from 'vitest';
import { categoryFor, actorLabel, isNamed, parseAuditLog } from '../src/parser';
import * as fs from 'fs';
import * as path from 'path';

// ── Category map ──
describe('categoryFor', () => {
  it('maps known prefixes correctly', () => {
    expect(categoryFor('users.login')).toBe('Identity & Auth');
    expect(categoryFor('mfa.enable')).toBe('Identity & Auth');
    expect(categoryFor('identity-provider.create')).toBe('Identity & Auth');
    expect(categoryFor('oauth2-client.create')).toBe('Identity & Auth');
    expect(categoryFor('realm.update')).toBe('Identity & Auth');
    expect(categoryFor('role.assign')).toBe('Access Control');
    expect(categoryFor('groups.create')).toBe('Access Control');
    expect(categoryFor('assignment.add')).toBe('Access Control');
    expect(categoryFor('scans.create')).toBe('Scanning');
    expect(categoryFor('sca-results.read')).toBe('Scanning');
    expect(categoryFor('source-code.download')).toBe('Data Access');
    expect(categoryFor('contributing-developers.list')).toBe('Data Access');
    expect(categoryFor('projects.create')).toBe('Project Mgmt');
    expect(categoryFor('project-settings.update')).toBe('Project Mgmt');
    expect(categoryFor('applications.assign')).toBe('Project Mgmt');
    expect(categoryFor('environment.update')).toBe('Config');
    expect(categoryFor('tenant-settings.update')).toBe('Config');
    expect(categoryFor('link.create')).toBe('Config');
    expect(categoryFor('unknown.thing')).toBe('Other');
  });
});

// ── Actor label ──
describe('actorLabel', () => {
  it('handles Unresolved User ID', () => {
    expect(actorLabel('Unresolved User ID')).toBe('Unresolved / System');
  });
  it('handles empty string', () => {
    expect(actorLabel('')).toBe('Unresolved / System');
  });
  it('extracts name from Name (email) format', () => {
    expect(actorLabel('John Smith (john@example.com)')).toBe('John Smith');
  });
  it('truncates bare UUID', () => {
    const uuid = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890';
    expect(actorLabel(uuid)).toBe('a1b2c3d4…');
  });
  it('handles name with parentheses in it', () => {
    expect(actorLabel('Some User (some.user@cx.com)')).toBe('Some User');
  });
});

// ── isNamed ──
describe('isNamed', () => {
  it('named actors return true', () => {
    expect(isNamed('John Smith')).toBe(true);
    expect(isNamed('Alice Wonder')).toBe(true);
  });
  it('Unresolved / System returns false', () => {
    expect(isNamed('Unresolved / System')).toBe(false);
  });
  it('truncated UUID returns false', () => {
    expect(isNamed('a1b2c3d…')).toBe(false);
  });
});

// ── Inline fixture ──
const FIXTURE = `CxOne Audit Log Search
Tenant: test-tenant
Base URL: https://ast.checkmarx.net
Date range: 2026-05-01 to 2026-05-03
Stage 1: Fetch audit events ... events_fetched: 4
Stage 2: Resolve UUIDs (human-readable) ... events: 4
----------------------------------------
Event Date: 2026-05-01T10:00:00.000000Z
Event Type: scans.create
Action User: Alice Smith (alice@cx.com)
Data:
  scanId: scan-001
  projectName: my-project
----------------------------------------
Event Date: 2026-05-01T11:00:00.000000Z
Event Type: users.login
Action User: Bob Jones (bob@cx.com)
Data:
  status: OK
----------------------------------------
Event Date: 2026-05-02T09:00:00.000000Z
Event Type: users.login
Action User: Unresolved User ID
Data:
  status: FAIL
----------------------------------------
Event Date: 2026-05-03T08:00:00.000000Z
Event Type: source-code.download
Action User: Alice Smith (alice@cx.com)
Data:
  projectName: my-project
  fileName: repo.zip
`;

describe('parseAuditLog (inline fixture)', () => {
  const ds = parseAuditLog(FIXTURE);

  it('parses correct event count', () => {
    expect(ds.meta.total).toBe(4);
    expect(ds.events.length).toBe(4);
  });

  it('extracts metadata', () => {
    expect(ds.meta.tenant).toBe('test-tenant');
    expect(ds.meta.baseUrl).toBe('https://ast.checkmarx.net');
  });

  it('derives date range from events (not header)', () => {
    expect(ds.meta.dateMin).toBe('2026-05-01');
    expect(ds.meta.dateMax).toBe('2026-05-03');
  });

  it('counts distinct event types', () => {
    expect(ds.types).toContain('scans.create');
    expect(ds.types).toContain('users.login');
    expect(ds.types).toContain('source-code.download');
    expect(ds.meta.eventTypes).toBe(3);
  });

  it('builds category list', () => {
    expect(ds.cats).toContain('Scanning');
    expect(ds.cats).toContain('Identity & Auth');
    expect(ds.cats).toContain('Data Access');
  });

  it('maps each type to its category', () => {
    const scansIdx = ds.types.indexOf('scans.create');
    const catIdx = ds.typeCat[scansIdx];
    expect(ds.cats[catIdx]).toBe('Scanning');

    const loginIdx = ds.types.indexOf('users.login');
    expect(ds.cats[ds.typeCat[loginIdx]]).toBe('Identity & Auth');

    const dlIdx = ds.types.indexOf('source-code.download');
    expect(ds.cats[ds.typeCat[dlIdx]]).toBe('Data Access');
  });

  it('normalizes actors correctly', () => {
    expect(ds.users).toContain('Alice Smith');
    expect(ds.users).toContain('Bob Jones');
    expect(ds.users).toContain('Unresolved / System');
  });

  it('marks named vs unnamed correctly', () => {
    const aliceIdx = ds.users.indexOf('Alice Smith');
    const sysIdx = ds.users.indexOf('Unresolved / System');
    expect(ds.named[aliceIdx]).toBe(1);
    expect(ds.named[sysIdx]).toBe(0);
    expect(ds.meta.namedActors).toBe(2); // Alice + Bob
  });

  it('trims timestamps to second precision without Z', () => {
    for (const [ts] of ds.events) {
      expect(ts).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$/);
    }
  });

  it('stores data fields correctly', () => {
    const scansIdx = ds.types.indexOf('scans.create');
    const scanEvent = ds.events.find(([, ti]) => ti === scansIdx);
    expect(scanEvent).toBeDefined();
    expect(scanEvent![3].scanId).toBe('scan-001');
    expect(scanEvent![3].projectName).toBe('my-project');
  });

  it('counts distinct days', () => {
    expect(ds.meta.days).toBe(3);
  });
});

// ── Real fixture (if available) ──
const FIXTURE_PATH = path.join(__dirname, 'fixtures', 'audit.log');

if (fs.existsSync(FIXTURE_PATH)) {
  describe('parseAuditLog (real fixture)', () => {
    const buf = fs.readFileSync(FIXTURE_PATH);
    let text: string;
    if (buf[0] === 0xff && buf[1] === 0xfe) {
      text = buf.toString('utf16le');
    } else {
      text = buf.toString('utf8');
    }
    const ds = parseAuditLog(text);

    it('total events = 12510', () => expect(ds.meta.total).toBe(12510));
    it('distinct event types = 45', () => expect(ds.meta.eventTypes).toBe(45));
    it('named actors = 20', () => expect(ds.meta.namedActors).toBe(20));
    it('categories = 6', () => expect(ds.cats.length).toBe(6));
    it('date range 2026-05-01 → 2026-06-04', () => {
      expect(ds.meta.dateMin).toBe('2026-05-01');
      expect(ds.meta.dateMax).toBe('2026-06-04');
    });

    it('users.login count = 2880', () => {
      const loginIdx = ds.types.indexOf('users.login');
      const count = ds.events.filter(([, ti]) => ti === loginIdx).length;
      expect(count).toBe(2880);
    });

    it('scans.create count = 2605', () => {
      const idx = ds.types.indexOf('scans.create');
      expect(ds.events.filter(([, ti]) => ti === idx).length).toBe(2605);
    });

    it('projects.assign count = 2021', () => {
      const idx = ds.types.indexOf('projects.assign');
      expect(ds.events.filter(([, ti]) => ti === idx).length).toBe(2021);
    });

    it('projects.create count = 2019', () => {
      const idx = ds.types.indexOf('projects.create');
      expect(ds.events.filter(([, ti]) => ti === idx).length).toBe(2019);
    });

    it('source-code.download count = 399', () => {
      const idx = ds.types.indexOf('source-code.download');
      expect(ds.events.filter(([, ti]) => ti === idx).length).toBe(399);
    });

    it('users.login status split OK=2784 / FAIL=96', () => {
      const loginIdx = ds.types.indexOf('users.login');
      const loginEvents = ds.events.filter(([, ti]) => ti === loginIdx);
      const ok = loginEvents.filter(([, , , d]) => d.status === 'OK').length;
      const fail = loginEvents.filter(([, , , d]) => d.status === 'FAIL').length;
      expect(ok).toBe(2784);
      expect(fail).toBe(96);
    });
  });
}
