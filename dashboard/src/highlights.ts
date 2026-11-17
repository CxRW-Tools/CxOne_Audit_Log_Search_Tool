// Security highlights: patterns in the loaded events worth an auditor's attention.
// Pure functions over DecodedEvent[]; each highlight carries the exact events behind it.
import type { DecodedEvent } from './types.js';
import { actorShort } from './format.js';
import { isNamed } from './parser.js';

export type Severity = 'high' | 'medium' | 'info';

export interface Highlight {
  id: string;
  severity: Severity;
  title: string;
  detail: string;
  /** Event idx values (DecodedEvent.idx). */
  ids: number[];
}

export interface HighlightOptions {
  /** Failed logins for one account within `burstWindowMinutes` before it's flagged. */
  failedLoginThreshold?: number;
  /** Window for failed-login bursts and password spraying. */
  burstWindowMinutes?: number;
  /** Failed logins from one IP (across 2+ accounts) before it's flagged. */
  sprayThreshold?: number;
  /** Distinct login IPs per user before it's flagged. */
  manyIpsThreshold?: number;
  /** Working hours [start, end) in the display time zone; weekends always count as off-hours. */
  workHours?: [number, number];
}

const RANK: Record<Severity, number> = { high: 0, medium: 1, info: 2 };
const n = (x: number) => x.toLocaleString();
const plural = (x: number, one: string, many = one + 's') => `${n(x)} ${x === 1 ? one : many}`;

const isLogin = (e: DecodedEvent) => e.type === 'users.login';
const isFail = (e: DecodedEvent) => isLogin(e) && String(e.data.status ?? '').toUpperCase() === 'FAIL';
const isOk = (e: DecodedEvent) => isLogin(e) && String(e.data.status ?? '').toUpperCase() === 'OK';

const PRIV_TYPE = /^(assignment|assignments|role|roles|groups?)\.(create|add|assign|update)/;
const CRED_TYPE = /^(api-keys?|oauth2-client|clients|webhooks?)\.(create|update|delete|regenerate)/;
const AUTH_CFG_TYPE = /^(mfa|identity-provider|realm|tenant-settings|tenant)\./;
const EXPORT_TYPE = /(export|download)/;

function groupBy<K>(events: DecodedEvent[], key: (e: DecodedEvent) => K | undefined): Map<K, DecodedEvent[]> {
  const m = new Map<K, DecodedEvent[]>();
  for (const e of events) {
    const k = key(e);
    if (k === undefined) continue;
    const list = m.get(k);
    if (list) list.push(e);
    else m.set(k, [e]);
  }
  return m;
}

/**
 * Densest run of events within `windowMs` (events sorted by time): the largest set where
 * last - first <= windowMs. Returns [] if no run reaches `min`.
 */
export function densestBurst(sorted: DecodedEvent[], windowMs: number, min: number): DecodedEvent[] {
  let best: [number, number] = [0, -1];
  let lo = 0;
  for (let hi = 0; hi < sorted.length; hi++) {
    while (sorted[hi].epoch - sorted[lo].epoch > windowMs) lo++;
    if (hi - lo > best[1] - best[0]) best = [lo, hi];
  }
  const run = sorted.slice(best[0], best[1] + 1);
  return run.length >= min ? run : [];
}

function fmtWindow(minutes: number): string {
  return minutes >= 60 && minutes % 60 === 0 ? `${minutes / 60} hour${minutes === 60 ? '' : 's'}` : `${minutes} minutes`;
}

function breakdown(events: DecodedEvent[], max = 3): string {
  const counts = new Map<string, number>();
  for (const e of events) counts.set(e.type, (counts.get(e.type) ?? 0) + 1);
  const top = [...counts.entries()].sort((a, b) => b[1] - a[1]);
  const shown = top.slice(0, max).map(([t, c]) => `${t} (${n(c)})`);
  return shown.join(', ') + (top.length > max ? `, +${top.length - max} more` : '');
}

export function computeHighlights(events: DecodedEvent[], opts: HighlightOptions = {}): Highlight[] {
  const failTh = opts.failedLoginThreshold ?? 5;
  const windowMin = opts.burstWindowMinutes ?? 15;
  const windowMs = windowMin * 60000;
  const sprayTh = opts.sprayThreshold ?? 10;
  const manyIpsTh = opts.manyIpsThreshold ?? 5;
  const [workStart, workEnd] = opts.workHours ?? [7, 20];
  const out: Highlight[] = [];

  // ── Logins ────────────────────────────────────────────────────────────────
  const logins = events.filter(isLogin);
  const byUser = groupBy(logins, (e) => e.user);

  // Rates over a long period are noisy (everyone mistypes a password eventually), so login
  // findings look for *bursts*: many failures within a short window.

  // Success right after a burst of failures: possible guessed password.
  for (const [user, evs] of byUser) {
    const sorted = [...evs].sort((a, b) => a.epoch - b.epoch);
    let run: DecodedEvent[] = [];
    for (const e of sorted) {
      if (isFail(e)) {
        run.push(e);
        while (run.length && e.epoch - run[0].epoch > windowMs) run.shift();
      } else if (isOk(e)) {
        if (run.length >= failTh && e.epoch - run[run.length - 1].epoch <= windowMs) {
          out.push({
            id: `fail-then-ok:${user}:${e.idx}`,
            severity: 'high',
            title: `Login succeeded right after ${plural(run.length, 'failed attempt')}`,
            detail: `${actorShort(user, 40)}${e.ip ? ` from ${e.ip}` : ''} · within ${fmtWindow(windowMin)}`,
            ids: [...run.map((x) => x.idx), e.idx],
          });
        }
        run = [];
      }
    }
  }

  // Bursts of failures for one account (top 5 by size).
  const bursts = [...byUser.entries()]
    .map(([user, evs]) => [user, densestBurst(evs.filter(isFail).sort((a, b) => a.epoch - b.epoch), windowMs, failTh)] as const)
    .filter(([, run]) => run.length)
    .sort((a, b) => b[1].length - a[1].length);
  for (const [user, run] of bursts.slice(0, 5)) {
    out.push({
      id: `fail-burst:${user}`,
      severity: run.length >= failTh * 2 ? 'high' : 'medium',
      title: `${plural(run.length, 'failed login')} within ${fmtWindow(windowMin)}`,
      detail: `${actorShort(user, 40)} · starting ${run[0].ts.replace('T', ' ')} UTC`,
      ids: run.map((e) => e.idx),
    });
  }

  // Failures from one IP across several accounts within an hour: password spraying.
  const failByIp = groupBy(logins.filter(isFail), (e) => e.ip);
  for (const [ip, fails] of failByIp) {
    const run = densestBurst([...fails].sort((a, b) => a.epoch - b.epoch), 60 * 60000, sprayTh);
    const accounts = new Set(run.map((e) => e.user)).size;
    if (run.length && accounts >= 3) {
      out.push({
        id: `spray:${ip}`,
        severity: 'high',
        title: `${plural(run.length, 'failed login')} from one IP across ${n(accounts)} accounts within an hour`,
        detail: `IP ${ip} · starting ${run[0].ts.replace('T', ' ')} UTC`,
        ids: run.map((e) => e.idx),
      });
    }
  }

  // Accounts logging in from many IPs (common with VPNs; informational, top 5).
  const manyIps = [...byUser.entries()]
    .map(([user, evs]) => [user, evs.filter((e) => isOk(e) && e.ip)] as const)
    .map(([user, ok]) => [user, ok, new Set(ok.map((e) => e.ip)).size] as const)
    .filter(([, , size]) => size >= manyIpsTh)
    .sort((a, b) => b[2] - a[2]);
  for (const [user, ok, size] of manyIps.slice(0, 5)) {
    out.push({
      id: `many-ips:${user}`,
      severity: 'info',
      title: `Successful logins from ${n(size)} different IPs`,
      detail: actorShort(user, 40),
      ids: ok.map((e) => e.idx),
    });
  }

  // New IP on the last day for an account with earlier history (top 5).
  const lastDay = events.reduce((m, e) => (e.day > m ? e.day : m), '');
  let newIpCount = 0;
  for (const [user, evs] of byUser) {
    if (newIpCount >= 5) break;
    const ok = evs.filter((e) => isOk(e) && e.ip);
    const earlier = new Set(ok.filter((e) => e.day < lastDay).map((e) => e.ip));
    if (!earlier.size) continue;
    const fresh = ok.filter((e) => e.day === lastDay && !earlier.has(e.ip));
    if (fresh.length) {
      newIpCount++;
      const ips = [...new Set(fresh.map((e) => e.ip))];
      out.push({
        id: `new-ip:${user}`,
        severity: 'medium',
        title: `Login from a new IP on ${lastDay}`,
        detail: `${actorShort(user, 40)}: ${ips.slice(0, 3).join(', ')}${ips.length > 3 ? '…' : ''}`,
        ids: fresh.map((e) => e.idx),
      });
    }
  }

  // ── Privilege, credential and configuration changes ──────────────────────
  const priv = events.filter((e) => PRIV_TYPE.test(e.type));
  const adminPriv = priv.filter((e) => /admin/i.test(e.search));
  if (adminPriv.length) {
    out.push({
      id: 'admin-grants',
      severity: 'high',
      title: `${plural(adminPriv.length, 'admin-level role or group change')}`,
      detail: breakdown(adminPriv),
      ids: adminPriv.map((e) => e.idx),
    });
  }
  if (priv.length > adminPriv.length) {
    const rest = priv.filter((e) => !adminPriv.includes(e));
    out.push({ id: 'access-changes', severity: 'info', title: `${plural(rest.length, 'other access change')}`, detail: breakdown(rest), ids: rest.map((e) => e.idx) });
  }

  const creds = events.filter((e) => CRED_TYPE.test(e.type));
  if (creds.length) {
    out.push({ id: 'credentials', severity: 'medium', title: `${plural(creds.length, 'API key, client or webhook change')}`, detail: breakdown(creds), ids: creds.map((e) => e.idx) });
  }

  const authCfg = events.filter((e) => AUTH_CFG_TYPE.test(e.type));
  if (authCfg.length) {
    out.push({ id: 'auth-config', severity: 'medium', title: `${plural(authCfg.length, 'MFA, identity-provider or tenant setting change')}`, detail: breakdown(authCfg), ids: authCfg.map((e) => e.idx) });
  }

  const deletes = events.filter((e) => /\.delete$/.test(e.type));
  if (deletes.length) {
    out.push({ id: 'deletions', severity: 'medium', title: `${plural(deletes.length, 'deletion')}`, detail: breakdown(deletes), ids: deletes.map((e) => e.idx) });
  }

  // ── Data access ───────────────────────────────────────────────────────────
  const dataOut = events.filter((e) => e.type !== 'users.login' && EXPORT_TYPE.test(e.type));
  if (dataOut.length) {
    const perUser = [...groupBy(dataOut, (e) => e.user).entries()].sort((a, b) => b[1].length - a[1].length);
    const counts = perUser.map(([, v]) => v.length).sort((a, b) => a - b);
    const median = counts[Math.floor(counts.length / 2)] ?? 0;
    const heavy = perUser.filter(([, v]) => v.length >= Math.max(10, median * 3)).slice(0, 3);
    for (const [user, evs] of heavy) {
      out.push({
        id: `heavy-download:${user}`,
        severity: 'medium',
        title: `${plural(evs.length, 'download/export')} by one actor`,
        detail: `${actorShort(user, 40)} — ${breakdown(evs, 2)}`,
        ids: evs.map((e) => e.idx),
      });
    }
    out.push({
      id: 'data-out',
      severity: 'info',
      title: `${plural(dataOut.length, 'source-code download or data export')}`,
      detail: `${n(perUser.length)} ${perUser.length === 1 ? 'actor' : 'actors'} · ${breakdown(dataOut, 2)}`,
      ids: dataOut.map((e) => e.idx),
    });
  }

  // ── Off-hours changes by people (scans and logins excluded: often automated) ─
  const offHours = events.filter(
    (e) =>
      isNamed(e.user) &&
      e.cat !== 'Scanning' &&
      !isLogin(e) &&
      e.type !== 'users.logout' &&
      (e.weekday === 0 || e.weekday === 6 || e.hour < workStart || e.hour >= workEnd),
  );
  if (offHours.length) {
    out.push({
      id: 'off-hours',
      severity: 'info',
      title: `${plural(offHours.length, 'change')} outside working hours or on weekends`,
      detail: `${String(workStart).padStart(2, '0')}:00–${String(workEnd).padStart(2, '0')}:00, Mon–Fri · ${breakdown(offHours, 2)}`,
      ids: offHours.map((e) => e.idx),
    });
  }

  return out.sort((a, b) => RANK[a.severity] - RANK[b.severity] || b.ids.length - a.ids.length);
}
