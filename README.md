# CxOne Audit Log Search Tool

Python CLI to search and export **Checkmarx One** audit events using the REST API **`GET /api/audit-events/`** (replaces the legacy `GET /api/audit/` flow). Events are retrieved for a date range (up to the **previous 365 days**), with optional filtering, human-readable UUID resolution, console output, and **CSV export**.

The API is documented in the [Checkmarx One API Reference — Get a list of audit events](https://checkmarx.stoplight.io/docs/checkmarx-one-api-reference-guide/ofyf0dxa4e6w2-get-a-list-of-audit-events). Some tenants or regions may still be rolling out this endpoint; if calls fail, confirm availability in your environment.

## Requirements

- Python 3.9+
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
- [src/utils/](src/utils/) — config, auth, API client, CSV, file/debug helpers
- [src/operations/](src/operations/) — audit fetch and UUID resolution

## License

MIT License — see [LICENSE](LICENSE).
