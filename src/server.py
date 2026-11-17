"""
Local web server for `python main.py --serve`.

Serves the CxOne Audit Log Dashboard and a single JSON endpoint that runs the same
query pipeline as the CLI. Credentials stay in this process; the browser never sees them.

Security model (local, single user):
  - Binds to 127.0.0.1 only.
  - Rejects requests whose Host header isn't 127.0.0.1/localhost:<port> (DNS rebinding).
  - /api/* requires a random per-run token sent in the X-CxOne-Token header. The token is
    injected into the served page; other websites can neither read that page (no CORS)
    nor send the custom header cross-origin (preflight is never answered).
"""

import gzip
import hmac
import json
import os
import secrets
import threading
import time
import webbrowser
from datetime import date, timedelta
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from src.pipeline import parse_date_range, run_query

DASHBOARD_FILENAME = "CxOne_Audit_Log_Dashboard.html"
DEFAULT_DASHBOARD_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "web", DASHBOARD_FILENAME
)
TOKEN_HEADER = "X-CxOne-Token"
_TRUE = {"1", "true", "yes", "on"}


def _inject_config(html: str, cfg: dict) -> str:
    """Insert window.__CXONE_SERVE__ before </head>. '</' is escaped so the JSON can't end the script."""
    payload = json.dumps(cfg).replace("</", "<\\/")
    tag = f"<script>window.__CXONE_SERVE__ = {payload};</script>"
    if "</head>" in html:
        return html.replace("</head>", tag + "</head>", 1)
    return tag + html


class _State:
    def __init__(self, ctx, html_path, token, port):
        self.ctx = ctx
        self.html_path = html_path
        self.token = token
        self.port = port
        self.query_lock = threading.Lock()
        self.allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}


def _make_handler(state: _State):
    config = state.ctx.config

    class Handler(BaseHTTPRequestHandler):
        server_version = "CxOneAuditSearch"
        sys_version = ""

        # ── plumbing ──────────────────────────────────────────────────────────
        def log_message(self, fmt, *args):
            if config.debug:
                super().log_message(fmt, *args)

        def _send(self, status, body: bytes, content_type: str):
            if len(body) > 1024 and "gzip" in (self.headers.get("Accept-Encoding") or ""):
                body = gzip.compress(body, compresslevel=5)
                gz = True
            else:
                gz = False
            try:
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                if gz:
                    self.send_header("Content-Encoding", "gzip")
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("X-Frame-Options", "DENY")
                self.end_headers()
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                pass  # browser went away (tab closed / reloaded mid-query)

        def _json(self, status, obj):
            body = json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8")
            self._send(status, body, "application/json; charset=utf-8")

        def _error(self, status, message):
            self._json(status, {"error": message})

        # ── routing ───────────────────────────────────────────────────────────
        def do_GET(self):
            if self.headers.get("Host") not in state.allowed_hosts:
                return self._error(HTTPStatus.FORBIDDEN, "Unexpected Host header.")

            url = urlparse(self.path)
            if url.path in ("/", "/" + DASHBOARD_FILENAME):
                return self._dashboard()
            if url.path == "/api/events":
                return self._events(parse_qs(url.query))
            if url.path == "/favicon.ico":
                return self._send(HTTPStatus.NO_CONTENT, b"", "image/x-icon")
            return self._error(HTTPStatus.NOT_FOUND, "Not found.")

        def _dashboard(self):
            try:
                with open(state.html_path, "r", encoding="utf-8") as f:
                    html = f.read()
            except OSError as e:
                return self._error(HTTPStatus.INTERNAL_SERVER_ERROR, f"Dashboard HTML not found: {e}")
            today = date.today()
            html = _inject_config(
                html,
                {
                    "token": state.token,
                    "tenant": config.tenant_name,
                    "baseUrl": config.base_url,
                    "today": today.isoformat(),
                    "earliest": (today - timedelta(days=365)).isoformat(),
                },
            )
            self._send(HTTPStatus.OK, html.encode("utf-8"), "text/html; charset=utf-8")

        def _events(self, qs):
            sent = self.headers.get(TOKEN_HEADER) or ""
            if not hmac.compare_digest(sent, state.token):
                return self._error(HTTPStatus.FORBIDDEN, "Missing or invalid session token. Reload the page.")

            def arg(name, default=""):
                return (qs.get(name) or [default])[0]

            try:
                start_date, end_date = parse_date_range(arg("start"), arg("end"))
            except ValueError as e:
                return self._error(HTTPStatus.BAD_REQUEST, str(e))
            search = arg("search").strip() or None
            human_readable = arg("humanReadable", "1").lower() in _TRUE

            if not state.query_lock.acquire(blocking=False):
                return self._error(HTTPStatus.CONFLICT, "Another query is already running. Wait for it to finish.")
            started = time.time()
            try:
                print(
                    f"Query: {start_date} to {end_date}"
                    + (f", search={search!r}" if search else "")
                    + (", human-readable" if human_readable else "")
                    + " ...",
                    flush=True,
                )
                events = run_query(state.ctx, start_date, end_date, search, human_readable)
            except Exception as e:  # report to the page; keep serving
                print(f"  failed: {e}", flush=True)
                return self._error(HTTPStatus.BAD_GATEWAY, str(e))
            finally:
                state.query_lock.release()

            elapsed = round(time.time() - started, 1)
            print(f"  {len(events)} events in {elapsed}s", flush=True)
            self._json(
                HTTPStatus.OK,
                {
                    "meta": {
                        "tenant": config.tenant_name,
                        "baseUrl": config.base_url,
                        "startDate": start_date.isoformat(),
                        "endDate": end_date.isoformat(),
                        "search": search or "",
                        "humanReadable": human_readable,
                        "count": len(events),
                        "elapsedSeconds": elapsed,
                    },
                    "events": events,
                },
            )

    return Handler


def create_server(ctx, html_path=None, port=8765, token=None):
    """Bind the server without starting it. Returns (httpd, url, token)."""
    html_path = os.path.abspath(html_path or DEFAULT_DASHBOARD_PATH)
    if not os.path.isfile(html_path):
        raise FileNotFoundError(
            f"Dashboard HTML not found at {html_path}. Pass --dashboard-html PATH "
            "or copy CxOne_Audit_Log_Dashboard.html from the Visualizer's dist/ folder into web/."
        )

    token = token or secrets.token_urlsafe(32)
    try:
        httpd = ThreadingHTTPServer(("127.0.0.1", port), None)
    except OSError as e:
        raise RuntimeError(f"Could not listen on 127.0.0.1:{port} ({e}). Try --port with another value.") from e
    actual_port = httpd.server_address[1]
    httpd.RequestHandlerClass = _make_handler(_State(ctx, html_path, token, actual_port))
    httpd.daemon_threads = True
    return httpd, f"http://127.0.0.1:{actual_port}/", token


def serve(ctx, html_path=None, port=8765, open_browser=True):
    """Run until Ctrl+C. `ctx` is an authenticated src.pipeline.QueryContext."""
    httpd, url, _ = create_server(ctx, html_path, port)
    print("\nDashboard:", url)
    print("Serving", os.path.abspath(html_path or DEFAULT_DASHBOARD_PATH))
    print("Press Ctrl+C to stop.\n", flush=True)
    if open_browser:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server.")
    finally:
        httpd.server_close()
