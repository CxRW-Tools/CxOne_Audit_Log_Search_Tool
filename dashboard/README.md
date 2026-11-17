# Dashboard source

Source for the CxOne Audit Log Dashboard: TypeScript, Vite and Chart.js. For what it does and how to use it, see the [main README](../README.md).

The build is one self-contained HTML file written to [`../web/CxOne_Audit_Log_Dashboard.html`](../web/CxOne_Audit_Log_Dashboard.html). That one file is both what `python main.py --serve` serves and the standalone dashboard people open in a browser.

## Commands

Requires Node.js 22+ (Vite 8).

```bash
npm ci
npm run dev      # dev server → http://localhost:5173/CxOne_Audit_Log_Dashboard.html (file loading only)
npm test         # vitest unit tests
npm run build    # rebuilds ../web/CxOne_Audit_Log_Dashboard.html — commit it with your change
```

CI fails if the committed `web/` file doesn't match a fresh build.

## How it fits together

| Path | Role |
|------|------|
| [src/main.ts](src/main.ts) | Entry point: landing screen, file loading, mounting, source banner, controls, URL sync |
| [src/loader.ts](src/loader.ts) | Detects the file format from its content, decodes UTF-16, builds `DecodedEvent`s (search text, time zone fields) |
| [src/parser.ts](src/parser.ts) | Parses formatted console output (`.log`); `buildDataset()` is shared by every format; category map |
| [src/apiExport.ts](src/apiExport.ts) | Parses `--csv` and `--raw` exports, plus API-shaped events from `--serve`; keeps event ID, IP, action, resource |
| [src/state.ts](src/state.ts) | Filter state (dimensions, include/exclude field filters, hour, highlight set), comparison periods, time zone, cached rows |
| [src/highlights.ts](src/highlights.ts) | Security highlights (pure functions; thresholds in `HighlightOptions`) |
| [src/export.ts](src/export.ts) | CSV / JSON export and copy, in the API's shape |
| [src/urlState.ts](src/urlState.ts) | Filters and query ⇄ URL hash |
| [src/format.ts](src/format.ts) | Display formatting: values, actors, timestamps |
| [src/serve.ts](src/serve.ts), [src/components/queryBar.ts](src/components/queryBar.ts), [src/components/queryProgress.ts](src/components/queryProgress.ts) | `--serve` mode: query bar, progress, cancel |
| [src/components/](src/components/) | KPIs, highlights panel, charts, breadcrumb, field filter, event log |

**Data model:** values are stored exactly as the API returned them (arrays and objects included) and formatted only for display, so nothing is truncated and exports round-trip. Actors keep their full `First Last (username)` label.

**Performance:** `rows()` and derived values are cached per filter version (`cached`) or per data version (`cachedData`, for things like highlights that don't depend on filters); charts update in place; the search box is debounced. With 100k events a filter change takes roughly 100–200 ms.

**`--serve` mode:** the Python server ([../src/server.py](../src/server.py)) inserts `window.__CXONE_SERVE__` (session token, tenant, date bounds) into the page before `</head>`. When that is present, the query bar appears and calls `GET /api/events`, `GET /api/progress` and `POST /api/cancel` with the token in the `X-CxOne-Token` header. When it's absent (the file opened directly), the dashboard only loads files.

**Pre-processed JSON:** `npm run ingest -- <audit.log> [--out path.json]` converts a `.log` export to the dashboard's compact `Dataset` JSON, which also loads directly.
