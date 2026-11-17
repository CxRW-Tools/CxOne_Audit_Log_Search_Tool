"""
Tests for the --serve web server. The CxOne query is replaced with a fake, so no network
or credentials are needed:  python -m unittest discover -s tests -t .
"""

import gzip
import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from datetime import date, timedelta
from types import SimpleNamespace
from unittest import mock

from src import server
from src.pipeline import parse_date_range

TOKEN = "test-token"
EVENTS = [
    {
        "eventID": "e1",
        "eventDate": "2026-05-01T00:38:29.637426Z",
        "eventType": "scans.create",
        "actionUserId": "Jane Doe (jdoe)",
        "data": {"projectId": "p1"},
    }
]


def _fake_ctx():
    cfg = SimpleNamespace(tenant_name="acme", base_url="https://ast.checkmarx.net", debug=False)
    return SimpleNamespace(config=cfg)


class ServerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.html = os.path.join(cls.tmp.name, "dash.html")
        with open(cls.html, "w", encoding="utf-8") as f:
            f.write("<!doctype html><html><head><title>x</title></head><body></body></html>")
        cls.httpd, cls.url, _ = server.create_server(_fake_ctx(), cls.html, port=0, token=TOKEN)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.tmp.cleanup()

    def get(self, path, headers=None):
        req = urllib.request.Request(self.url.rstrip("/") + path, headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, dict(r.headers), r.read()
        except urllib.error.HTTPError as e:
            with e:
                return e.code, dict(e.headers), e.read()

    def api(self, query, token=TOKEN, extra=None):
        headers = {"X-CxOne-Token": token} if token is not None else {}
        headers.update(extra or {})
        return self.get("/api/events?" + query, headers)

    @staticmethod
    def recent():
        d = date.today() - timedelta(days=1)
        return f"start={d.isoformat()}&end={d.isoformat()}"

    # ── dashboard ─────────────────────────────────────────────────────────────
    def test_serves_dashboard_with_injected_config(self):
        status, headers, body = self.get("/")
        self.assertEqual(status, 200)
        self.assertIn("text/html", headers["Content-Type"])
        html = body.decode()
        cfg = json.loads(html.split("window.__CXONE_SERVE__ = ", 1)[1].split(";</script>", 1)[0])
        self.assertEqual(cfg["token"], TOKEN)
        self.assertEqual(cfg["tenant"], "acme")
        self.assertLess(html.index("__CXONE_SERVE__"), html.index("</head>"))

    def test_injected_json_cannot_close_script(self):
        out = server._inject_config("<head></head>", {"tenant": "</script><script>alert(1)"})
        self.assertNotIn("</script><script>alert", out)

    def test_unknown_path_404(self):
        self.assertEqual(self.get("/nope")[0], 404)

    # ── security ──────────────────────────────────────────────────────────────
    def test_rejects_foreign_host_header(self):
        status, _, _ = self.get("/", {"Host": "evil.example:80"})
        self.assertEqual(status, 403)

    def test_api_requires_token(self):
        self.assertEqual(self.api(self.recent(), token=None)[0], 403)
        self.assertEqual(self.api(self.recent(), token="wrong")[0], 403)

    def test_no_cors_headers(self):
        with mock.patch.object(server, "run_query", return_value=[]):
            _, headers, _ = self.api(self.recent(), extra={"Origin": "https://evil.example"})
        self.assertNotIn("Access-Control-Allow-Origin", headers)

    # ── queries ───────────────────────────────────────────────────────────────
    def test_bad_dates_400(self):
        status, _, body = self.api("start=2026-13-01&end=2026-13-02")
        self.assertEqual(status, 400)
        self.assertIn("Invalid date format", json.loads(body)["error"])

    def test_start_after_end_400(self):
        today = date.today()
        q = f"start={today.isoformat()}&end={(today - timedelta(days=2)).isoformat()}"
        self.assertEqual(self.api(q)[0], 400)

    def test_query_success_passes_params(self):
        with mock.patch.object(server, "run_query", return_value=list(EVENTS)) as rq:
            status, _, body = self.api(self.recent() + "&search=scan&humanReadable=0")
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertEqual(payload["meta"]["count"], 1)
        self.assertEqual(payload["meta"]["tenant"], "acme")
        self.assertEqual(payload["events"][0]["eventType"], "scans.create")
        _, _, _, search, human = rq.call_args.args
        self.assertEqual(search, "scan")
        self.assertFalse(human)

    def test_human_readable_defaults_on(self):
        with mock.patch.object(server, "run_query", return_value=[]) as rq:
            self.api(self.recent())
        self.assertTrue(rq.call_args.args[4])

    def test_query_error_502_and_server_survives(self):
        with mock.patch.object(server, "run_query", side_effect=RuntimeError("boom")):
            status, _, body = self.api(self.recent())
        self.assertEqual(status, 502)
        self.assertEqual(json.loads(body)["error"], "boom")
        self.assertEqual(self.get("/")[0], 200)

    def test_gzip_when_accepted(self):
        big = [dict(EVENTS[0], eventID=str(i)) for i in range(200)]
        with mock.patch.object(server, "run_query", return_value=big):
            status, headers, body = self.api(self.recent(), extra={"Accept-Encoding": "gzip"})
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("Content-Encoding"), "gzip")
        self.assertEqual(len(json.loads(gzip.decompress(body))["events"]), 200)

    def test_concurrent_query_409(self):
        entered = threading.Event()  # set once the first query holds the lock
        release = threading.Event()

        def slow(*_a, **_k):
            entered.set()
            release.wait(5)
            return []

        results = {}
        with mock.patch.object(server, "run_query", side_effect=slow):
            t = threading.Thread(target=lambda: results.setdefault("first", self.api(self.recent())))
            t.start()
            self.assertTrue(entered.wait(5), "first query never started")
            results["second"] = self.api(self.recent())
            release.set()
            t.join(5)
        self.assertEqual(results["second"][0], 409)
        self.assertEqual(results["first"][0], 200)


class ParseDateRangeTest(unittest.TestCase):
    def test_caps_future_end_to_today(self):
        today = date.today()
        _, end = parse_date_range(today.isoformat(), (today + timedelta(days=5)).isoformat())
        self.assertEqual(end, today)

    def test_rejects_older_than_365_days(self):
        old = (date.today() - timedelta(days=400)).isoformat()
        with self.assertRaises(ValueError):
            parse_date_range(old, date.today().isoformat())

    def test_rejects_garbage(self):
        with self.assertRaises(ValueError):
            parse_date_range("yesterday", "")


if __name__ == "__main__":
    unittest.main()
