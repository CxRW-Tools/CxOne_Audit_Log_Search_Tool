# CxOne Audit Log Search Tool

Search, export and visualize **Checkmarx One** audit events using the REST API **`GET /api/audit-events/`** (replaces the legacy `GET /api/audit/` flow). Events are retrieved for a date range (up to the **previous 365 days**), with optional filtering and human-readable UUID resolution.

Three ways to use it:

- **CLI** — print events, or export **CSV** / raw JSON for scripts and spreadsheets. See [Usage](#usage).
- **Web dashboard** — `python main.py --serve` opens an interactive dashboard in your browser with a query bar. See [Web dashboard](#web-dashboard---serve).
- **Standalone dashboard** — open [`web/CxOne_Audit_Log_Dashboard.html`](web/CxOne_Audit_Log_Dashboard.html) in any browser and drop in a file the CLI exported. No Python or server needed. See [Standalone dashboard](#standalone-dashboard).

The API is documented in the [Checkmarx One API Reference — Get a list of audit events](https://checkmarx.stoplight.io/docs/checkmarx-one-api-reference-guide/ofyf0dxa4e6w2-get-a-list-of-audit-events). Some tenants or regions may still be rolling out this endpoint; if calls fail, confirm availability in your environment.

## Requirements

- Python 3.10+
- Dependencies: see [requirements.txt](requirements.txt)

```bash
pip install -r requirements.txt
```

## Configuration

Copy [example.env](example.env) to `.env` and set:

| Variable | Description |
|----------|-------------|
| `CXONE_BASE_URL` | Region base URL (e.g. `https://ast.checkmarx.net`) |
| `CXONE_TENANT` | Tenant name |
| `CXONE_API_KEY` | API key (refresh token used with `ast-app`) |
| `CXONE_DEBUG` | `true` / `false` (optional) |
| `CXONE_IAM_BASE_URL` | Override IAM host if needed (optional) |
| `CXONE_OUTPUT_DIR` | Output directory for CSV and debug logs (optional, default `./output`) |
| `CXONE_PAGE_SIZE` | Page size for audit requests (optional, max **1000**) |
| `CXONE_START_DATE` | Start of range (optional), `YYYY-MM-DD` — use with `CXONE_END_DATE` to run without date flags |
| `CXONE_END_DATE` | End of range (optional), `YYYY-MM-DD` |

CLI arguments override `.env` values.

## Usage

The tool loads **`--env-file`** (default **`.env`**) on startup. Copy [example.env](example.env) to `.env` and set at least **credentials** and a **date range** (either in the file or on the command line).

```bash
python main.py --start-date YYYY-MM-DD --end-date YYYY-MM-DD [options]
```

```bash
# Same thing if .env contains CXONE_START_DATE, CXONE_END_DATE, and credentials
python main.py
```

### Required inputs (`.env` and/or CLI)

- **Date range** — `CXONE_START_DATE` and `CXONE_END_DATE` in `.env`, **or** `--start-date` / `--end-date` on the CLI (inclusive `YYYY-MM-DD`; end dates in the future are capped to today).
- **Credentials** — `CXONE_BASE_URL`, `CXONE_TENANT`, `CXONE_API_KEY` in `.env`, **or** the matching flags below.

You can supply **base URL, tenant, and API key** via `.env` or:

- `--base-url`
- `--tenant-name`
- `--api-key`

### Optional arguments

| Flag | Meaning |
|------|---------|
| `--env-file` | Path to env file (default `.env`) |
| `--iam-base-url` | IAM base URL (default: derived from `ast` → `iam.checkmarx.net`) |
| `--debug` | Verbose console output and a debug log file under the output directory |
| `--search-string` | Keep only events whose full JSON serialization contains this substring |
| `--raw` | Print events as JSON to stdout (see **CSV** below for interaction with `--csv`) |
| `--human-readable` | Resolve UUIDs in event payloads via Keycloak admin APIs (users, groups, roles) |
| `--csv` | Write a UTF-8 CSV under the output directory (`audit_events_<tenant>_<timestamp>.csv`) |
| `--csv-path` | Explicit CSV file path |
| `--print-events` | With `--csv`, also print formatted or raw events to stdout (default with `--csv` is summary only) |
| `--output-dir` | Directory for CSV and debug logs |

### Examples

```bash
# Load credentials from .env; fetch one week and print formatted events
python main.py --start-date 2026-03-01 --end-date 2026-03-07
```

```bash
# Filter, resolve UUIDs, export CSV (summary line only on the console)
python main.py --base-url https://ast.checkmarx.net --tenant-name mytenant --api-key "$CXONE_API_KEY" ^
  --start-date 2026-01-01 --end-date 2026-01-31 --search-string "project" --human-readable --csv
```

```bash
# CSV plus JSON on stdout
python main.py --start-date 2026-03-01 --end-date 2026-03-02 --csv --raw --print-events
```

## Web dashboard (`--serve`)

```bash
python main.py --serve
```

This starts a local server at `http://127.0.0.1:8765/` and opens it in your browser. Pick a date range (or a preset: Today, 7, 30, 90 days) and click **Run query**. While it runs, the page shows the current step (fetching, resolving names, preparing results) with a progress bar and counts, plus any rate-limit waits or retries; **Cancel** stops it. You can run as many queries as you like; press **Ctrl+C** in the terminal to stop the server.

Query options:

- **Server filter** — only fetch events containing this text (case-insensitive; the CLI's `--search-string` stays case-sensitive).
- **Resolve names** — same as `--human-readable` (on by default). Name lookups are cached for the life of the server, so later queries are faster.
- **Compare with previous period** — also fetches the equally long period before, so KPIs show the change and the timeline overlays the previous period.

Only credentials are required (from `.env` or the CLI flags); dates are chosen in the browser. The last query is remembered, and the URL holds the query and filters, so a view can be bookmarked (data is never put in the URL).

### What the dashboard shows

- **Source banner** — what's loaded (live query, file or URL), the range, whether names are resolved, and the time zone.
- **KPI strip** — total events, scans created, projects created, logins, failed logins, source-code downloads. Click a card to filter to exactly the events it counts; with comparison on, each card shows the change vs the previous period.
- **Highlights** — patterns worth a look, ranked by severity: a login that succeeds right after a burst of failures, bursts of failed logins for one account, failed logins from one IP across several accounts (password spraying), logins from a new or many IPs, admin-level role changes, API key / OAuth client / webhook changes, MFA / identity-provider / tenant setting changes, deletions, heavy downloads or exports, and changes outside working hours. Click one to see its events.
- **Drill-down chart** — category → event type → actor; smaller entries are grouped as "Other (+N)" so totals add up.
- **Top Actors** — actors by event count, including unresolved IDs (shown grey); two people with the same display name stay separate.
- **Activity Timeline** and **Hourly Distribution** — click a bar to filter by day or hour.
- **Event Log** — timestamp, type, category, actor (name and username), IP and key detail. Expand a row to see every field, filter to or exclude any value, or copy the event as JSON. **Export CSV / JSON** downloads all filtered events (the JSON loads back into the dashboard).

Filtering: click charts and cards, use **Add filter** (any field, including IP, project, status, action, resource and payload keys; "Only" or "Exclude"), or the search box (case-insensitive across all fields, including usernames and IPs). Switch between **UTC** and **Local** time; hide the charts to work in the table.

| Flag | Meaning |
|------|---------|
| `--serve` | Run the local web dashboard |
| `--port` | Port to listen on (default `8765`; `0` picks a free port) |
| `--no-browser` | Don't open a browser automatically |
| `--dashboard-html` | Serve a different build of `CxOne_Audit_Log_Dashboard.html` (default: [web/](web/)) |

**Security:** the server listens on `127.0.0.1` only and your API key never leaves the Python process — the browser only receives audit events. Requests must carry a random per-run token that is embedded in the served page, and requests with a non-local `Host` header are rejected, so other websites open in your browser can't query it. Anyone with access to your machine's loopback interface while it runs (for example other users on a shared host) could load the page, so stop it when you're done.

## Standalone dashboard

[`web/CxOne_Audit_Log_Dashboard.html`](web/CxOne_Audit_Log_Dashboard.html) is a single self-contained file. Open it in a browser (or send it to someone) and drag in, or **Load file**, any CLI export. Everything runs in the browser; no data leaves the machine. Everything above works the same, except live queries; **Compare periods** splits the loaded range into two equal halves.

CSV and `--raw` JSON exports include the event ID, IP address, action type and resource; the formatted console output (`.log`) doesn't, so those columns and IP-based highlights are only available with CSV or JSON.

Use `--human-readable` so actors show as names instead of UUIDs:

```bash
# CSV (recommended) — written to ./output/audit_events_<tenant>_<timestamp>.csv
python main.py --start-date 2026-05-01 --end-date 2026-05-31 --human-readable --csv
```

```bash
# Raw JSON — redirect stdout; the banner around the JSON is handled
python main.py --start-date 2026-05-01 --end-date 2026-05-31 --human-readable --raw > events.json
```

```bash
# Formatted console output — redirect stdout
python main.py --start-date 2026-05-01 --end-date 2026-05-31 --human-readable > events.log
```

The format is detected from the file's content, and UTF-16 files from PowerShell redirects work.

## API behavior (summary)

- **Endpoint:** `{CXONE_BASE_URL}/api/audit-events/`
- **Headers:** `Authorization: Bearer <token>`, `Accept: application/json; version=1.0`
- **Query:** `startDate`, `endDate` (RFC3339), `limit` (≤ 1000), `offset` — the tool **pages until all matching events** for the range are collected.
- **Response:** JSON with `events[]` and `totalFilteredCount`.

## CSV columns

When using `--csv`, each row includes:

`eventID`, `eventDate`, `eventType`, `auditResource`, `actionType`, `actionUserId`, `ipAddress`, and **`data`** (JSON string of the event payload). If **`--human-readable`** is also set, UUID resolution is applied before export, so CSV reflects resolved names where applicable.

## Project layout

- [main.py](main.py) — CLI entrypoint
- [src/pipeline.py](src/pipeline.py) — shared query pipeline (fetch → filter → sort → resolve) used by the CLI and `--serve`
- [src/server.py](src/server.py) — local web server for `--serve`
- [src/utils/](src/utils/) — config, auth, API client, CSV, file/debug helpers
- [src/operations/](src/operations/) — audit fetch and UUID resolution
- [tests/](tests/) — Python tests
- [dashboard/](dashboard/) — dashboard source (TypeScript, Vite, Chart.js); see [dashboard/README.md](dashboard/README.md)
- [web/](web/) — built dashboard, served by `--serve` and usable standalone. **Generated; don't edit by hand.**

## Development

```bash
python -m unittest discover -s tests -t .   # Python tests (no credentials needed)
```

The dashboard needs Node.js 22+ only if you change it. Python users never need Node, because the built HTML is committed in `web/`.

```bash
cd dashboard
npm ci
npm test         # unit tests
npm run build    # rebuilds ../web/CxOne_Audit_Log_Dashboard.html
```

Commit the rebuilt `web/` file together with your dashboard changes; CI fails if they differ.

## License

MIT License — see [LICENSE](LICENSE).
