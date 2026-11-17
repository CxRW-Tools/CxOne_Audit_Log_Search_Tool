# CxOne Audit Log Dashboard

An interactive, single-file dashboard for visualizing Checkmarx One audit log exports. No installation, no server — just open the HTML file in any browser and drop in your data.

---

## Usage

### 1. Download the dashboard

Download [`CxOne_Audit_Log_Dashboard.html`](dist/CxOne_Audit_Log_Dashboard.html) from the `dist/` folder in this repo.

### 2. Generate a data file

Use the [CxOne Audit Log Search Tool](https://github.com/CxRW-Tools/CxOne_Audit_Log_Search_Tool) to export audit events from your tenant. Add `--human-readable` so actors show as names instead of UUIDs. Any of these work:

```bash
# CSV export (recommended) — written to ./output/audit_events_<tenant>_<timestamp>.csv
python main.py --start-date 2026-05-01 --end-date 2026-05-31 --human-readable --csv
```

```bash
# Raw JSON — redirect stdout to a file; the tool's banner around the JSON is handled
python main.py --start-date 2026-05-01 --end-date 2026-05-31 --human-readable --raw > events.json
```

```bash
# Formatted console output — redirect stdout to a file
python main.py --start-date 2026-05-01 --end-date 2026-05-31 --human-readable > events.log
```

The file type is detected from its content, and UTF-16 files from PowerShell redirects are supported.

### 3. Open and load

Open `CxOne_Audit_Log_Dashboard.html` in your browser, then either:
- **Drag and drop** your `.csv`, `.json` or `.log` file onto the page, or
- Click **Load file** to browse for it

The dashboard loads entirely in your browser — no data leaves your machine.

---

## What you get

- **KPI strip** — total events, scans created, projects created, logins (success/fail), source-code downloads
- **Drill-down chart** — click from category → event type → actor; breadcrumb chips let you step back at any level
- **Top Actors** — named identities ranked by event count; click to filter
- **Activity Timeline** — daily event volume across the full date range; click a bar to filter by day
- **Hourly Distribution** — event count by UTC hour
- **Event Log** — sortable, paginated table with expandable rows showing the full event record; free-text search across all fields

---

## For developers

```bash
npm install
npm run dev      # dev server → http://localhost:5173/CxOne_Audit_Log_Dashboard.html
npm run build    # produces dist/CxOne_Audit_Log_Dashboard.html
npm test         # vitest unit tests
```
