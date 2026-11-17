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
| [src/main.ts](src/main.ts) | Entry point: landing screen, file loading, mounting the dashboard |
| [src/loader.ts](src/loader.ts) | Detects the file format from its content and decodes UTF-16 |
| [src/parser.ts](src/parser.ts) | Parses formatted console output (`.log`); `buildDataset()` is shared by every format |
| [src/apiExport.ts](src/apiExport.ts) | Parses `--csv` and `--raw` exports, plus API-shaped events from `--serve` |
| [src/serve.ts](src/serve.ts), [src/components/queryBar.ts](src/components/queryBar.ts) | Query bar for `--serve` mode |
| [src/state.ts](src/state.ts) | Filter state and scoped rows |
| [src/components/](src/components/) | KPIs, charts, breadcrumb, event log |

**`--serve` mode:** the Python server ([../src/server.py](../src/server.py)) inserts `window.__CXONE_SERVE__` (session token, tenant, date bounds) into the page before `</head>`. When that is present, the query bar appears and calls `GET /api/events` with the token in the `X-CxOne-Token` header. When it's absent (the file opened directly), the dashboard only loads files.

**Pre-processed JSON:** `npm run ingest -- <audit.log> [--out path.json]` converts a `.log` export to the dashboard's compact `Dataset` JSON, which also loads directly.
