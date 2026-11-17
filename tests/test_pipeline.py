"""Progress reporting in the shared pipeline and API client (no network)."""

import unittest
from datetime import date
from types import SimpleNamespace
from unittest import mock

from src import pipeline
from src.pipeline import QueryProgress, run_query
from src.utils.api_client import APIClient


class RecordingProgress(QueryProgress):
    """QueryProgress that also keeps every update, to assert on the sequence."""

    def __init__(self):
        super().__init__()
        self.history = []

    def update(self, **fields):
        self.history.append(dict(fields))
        super().update(**fields)

    def stages(self):
        out = []
        for h in self.history:
            s = h.get("stage")
            if s and (not out or out[-1] != s):
                out.append(s)
        return out


def _events(n):
    return [
        {"eventDate": f"2026-11-0{1 + i % 9}T00:00:00Z", "eventType": "scans.create",
         "actionUserId": f"0000000{i % 3}-0000-0000-0000-000000000000", "data": {}}
        for i in range(n)
    ]


class FakeCollector:
    """Stands in for AuditEventsCollector: returns events in 2 pages, reporting each."""

    def __init__(self, *_a, **_k):
        pass

    def execute(self, start_date, end_date, on_page=None):
        evs = _events(5)
        if on_page:
            on_page(3, 5)
            on_page(5, 5)
        return evs


class FakeResolver:
    def __init__(self):
        self._seen = set()

    def cache_size(self):
        return len(self._seen)

    def resolve_in_event(self, ev):
        self._seen.add(ev["actionUserId"])
        ev["actionUserId"] = "Resolved User (u)"


def _ctx(resolver=None):
    return SimpleNamespace(
        config=SimpleNamespace(), auth=None, logger=None,
        api=SimpleNamespace(notice_callback=None),
        authenticate=lambda: None,
        resolver=resolver or FakeResolver(),
    )


class RunQueryProgressTest(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(pipeline, "AuditEventsCollector", FakeCollector)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_stage_sequence_with_name_resolution(self):
        prog = RecordingProgress()
        prog.start()
        events = run_query(_ctx(), date(2026, 11, 1), date(2026, 11, 9), human_readable=True, progress=prog)
        self.assertEqual(prog.stages(), ["auth", "fetch", "filter", "resolve", "send"])
        snap = prog.snapshot()
        self.assertEqual(snap["fetched"], 5)
        self.assertEqual(snap["total"], 5)
        self.assertEqual(snap["matched"], 5)
        self.assertEqual(snap["resolved"], 5)
        self.assertEqual(snap["resolveTotal"], 5)
        self.assertEqual(snap["lookups"], 3)  # 3 distinct user IDs
        self.assertTrue(all(e["actionUserId"] == "Resolved User (u)" for e in events))

    def test_page_progress_reported(self):
        prog = RecordingProgress()
        run_query(_ctx(), date(2026, 11, 1), date(2026, 11, 9), progress=prog)
        pages = [(h["fetched"], h["total"]) for h in prog.history if "total" in h and h.get("total") is not None]
        self.assertEqual(pages, [(3, 5), (5, 5)])

    def test_no_resolve_stage_without_human_readable(self):
        prog = RecordingProgress()
        run_query(_ctx(), date(2026, 11, 1), date(2026, 11, 9), human_readable=False, progress=prog)
        self.assertNotIn("resolve", prog.stages())

    def test_search_filter_sets_matched(self):
        prog = RecordingProgress()
        run_query(_ctx(), date(2026, 11, 1), date(2026, 11, 9), search_string="2026-11-01", progress=prog)
        self.assertEqual(prog.snapshot()["matched"], 1)

    def test_works_without_progress(self):
        self.assertEqual(len(run_query(_ctx(), date(2026, 11, 1), date(2026, 11, 9))), 5)

    def test_notice_callback_cleared_afterwards(self):
        ctx = _ctx()
        run_query(ctx, date(2026, 11, 1), date(2026, 11, 9), progress=QueryProgress())
        self.assertIsNone(ctx.api.notice_callback)


class QueryProgressTest(unittest.TestCase):
    def test_lifecycle(self):
        p = QueryProgress()
        self.assertEqual(p.snapshot(), {"running": False, "stage": "idle"})
        p.start(humanReadable=True)
        s = p.snapshot()
        self.assertTrue(s["running"])
        self.assertEqual(s["stage"], "auth")
        self.assertIn("elapsedSeconds", s)
        self.assertNotIn("startedAt", s)
        p.update(stage="fetch", notice="Rate limited")
        p.finish()
        s = p.snapshot()
        self.assertFalse(s["running"])
        self.assertEqual(s["stage"], "done")
        self.assertIsNone(s["notice"])

    def test_finish_with_error(self):
        p = QueryProgress()
        p.start()
        p.finish(error=RuntimeError("boom"))
        self.assertEqual(p.snapshot()["stage"], "error")
        self.assertEqual(p.snapshot()["error"], "boom")


class ApiClientPagingTest(unittest.TestCase):
    def _client(self):
        cfg = SimpleNamespace(page_size=2, max_retries=1, retry_delay=0, request_timeout=1)
        return APIClient("https://example.invalid", auth_manager=None, config=cfg)

    def test_on_page_called_per_page(self):
        client = self._client()
        pages = [
            {"events": [1, 2], "totalFilteredCount": 5},
            {"events": [3, 4], "totalFilteredCount": 5},
            {"events": [5], "totalFilteredCount": 5},
        ]
        calls = []
        with mock.patch.object(client, "_get_json", side_effect=pages):
            out = client.get_audit_events_all({}, on_page=lambda f, t: calls.append((f, t)))
        self.assertEqual(out, [1, 2, 3, 4, 5])
        self.assertEqual(calls, [(2, 5), (4, 5), (5, 5)])


if __name__ == "__main__":
    unittest.main()
