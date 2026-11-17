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

This starts a local server at `http://127.0.0.1:8765/` and opens it in your browser. Pick a date range, optionally a search string, and click **Run query**. While it runs, the page shows the current step (fetching, resolving names, preparing results) with a progress bar and counts, plus any rate-limit waits or retries. You can run as many queries as you like; press **Ctrl+C** in the terminal to stop.

The dashboard shows:

- **KPI strip** — total events, scans created, projects created, logins (success/fail), source-code downloads. Click a card to filter to it.
- **Drill-down chart** — category → event type → actor; breadcrumb chips step back a level
- **Top Actors** — named identities ranked by event count; click to filter
- **Activity Timeline** — daily volume; click a bar to filter by day
- **Hourly Distribution** — events by UTC hour
- **Event Log** — sortable, paginated table with expandable rows and free-text search

Only credentials are required (from `.env` or the CLI flags); dates are chosen in the browser. Queries run the same pipeline as the CLI, so `--search-string` and `--human-readable` behave identically (the **Resolve names** checkbox, on by default). Name lookups are cached for the life of the server, so later queries are faster.

| Flag | Meaning |
|------|---------|
| `--serve` | Run the local web dashboard |
| `--port` | Port to listen on (default `8765`; `0` picks a free port) |
| `--no-browser` | Don't open a browser automatically |
| `--dashboard-html` | Serve a different build of `CxOne_Audit_Log_Dashboard.html` (default: [web/](web/)) |

**Security:** the server listens on `127.0.0.1` only and your API key never leaves the Python process — the browser only receives audit events. Requests must carry a random per-run token that is embedded in the served page, and requests with a non-local `Host` header are rejected, so other websites open in your browser can't query it. Anyone with access to your machine's loopback interface while it runs (for example other users on a shared host) could load the page, so stop it when you're done.

## Standalone dashboard

[`web/CxOne_Audit_Log_Dashboard.html`](web/CxOne_Audit_Log_Dashboard.html) is a single self-contained file. Open it in a browser (or send it to someone) and drag in, or **Load file**, any CLI export. Everything runs in the browser; no data leaves the machine.

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
