"""
Shared query pipeline used by both the CLI (main.py) and the local web server (--serve).

fetch (GET /api/audit-events/) -> search filter -> sort by date -> optional UUID resolution
"""

import threading
import time
from datetime import date, datetime

from src.operations.audit_events_collector import AuditEventsCollector
from src.operations.uuid_resolver import UuidResolver
from src.utils.api_client import APIClient
from src.utils.audit_output import filter_events, sort_events
from src.utils.auth import AuthManager
from src.utils.config import Config


def parse_date_range(start_s: str, end_s: str):
    """
    Parse inclusive YYYY-MM-DD bounds. End dates in the future are capped to today.
    Raises ValueError with a user-facing message when the range is invalid.
    """
    try:
        start_date = datetime.strptime(start_s, "%Y-%m-%d").date()
        end_date = datetime.strptime(end_s, "%Y-%m-%d").date()
    except (TypeError, ValueError):
        raise ValueError("Invalid date format. Use YYYY-MM-DD.") from None
    today = date.today()
    if end_date > today:
        end_date = today
    ok, err = Config.validate_date_range(start_date, end_date)
    if not ok:
        raise ValueError(err)
    return start_date, end_date


class QueryContext:
    """
    Authenticated API session. Create once and reuse: the access token refreshes itself,
    and the UUID resolver cache is kept across queries (useful for --serve).
    """

    def __init__(self, config, debug_logger=None):
        self.config = config
        self.logger = debug_logger
        self.auth = AuthManager(
            base_url=config.base_url,
            tenant_name=config.tenant_name,
            api_key=config.api_key,
            iam_base_url=config.iam_base_url,
            debug=config.debug,
        )
        self.api = APIClient(config.base_url, self.auth, config, config.debug, debug_logger)
        self._resolver = None

    def authenticate(self):
        self.auth.ensure_authenticated()

    @property
    def resolver(self):
        if self._resolver is None:
            self._resolver = UuidResolver(
                self.auth, self.api, self.config.tenant_name, debug=self.config.debug
            )
        return self._resolver


class QueryProgress:
    """
    Thread-safe progress of the query in flight, read by the --serve /api/progress endpoint
    while the query thread updates it.

    Stages, in order: auth -> fetch -> filter -> resolve (only with human_readable) -> send.
    Fields used by the dashboard:
      stage, running, error, humanReadable, startedAt / elapsedSeconds,
      fetched, total (totalFilteredCount, known after the first page), matched (after filter),
      resolved / resolveTotal (events processed), lookups (IAM name lookups made), notice.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._state = {"running": False, "stage": "idle"}

    def start(self, **fields):
        with self._lock:
            self._state = {"running": True, "stage": "auth", "startedAt": time.time(), **fields}

    def update(self, **fields):
        with self._lock:
            self._state.update(fields)

    def finish(self, error=None):
        with self._lock:
            self._state.update(running=False, stage="error" if error else "done", notice=None)
            if error:
                self._state["error"] = str(error)

    def snapshot(self):
        with self._lock:
            s = dict(self._state)
        if "startedAt" in s:
            s["elapsedSeconds"] = round(time.time() - s.pop("startedAt"), 1)
        return s


def run_query(
    ctx, start_date, end_date, search_string=None, human_readable=False, stages=None, progress=None
):
    """
    Fetch, filter, sort and optionally resolve audit events. Returns a list of event dicts
    in the API's shape (the same objects --raw prints).

    `stages` is an optional StageTracker for CLI progress output.
    `progress` is an optional QueryProgress, updated as the query advances (used by --serve).
    """

    def report(**fields):
        if progress:
            progress.update(**fields)

    report(stage="auth")
    ctx.authenticate()

    if stages:
        stages.start_stage("Stage 1: Fetch audit events")
    report(stage="fetch", fetched=0, total=None)
    collector = AuditEventsCollector(
        ctx.config, ctx.auth, api_client=ctx.api, progress=None, debug_logger=ctx.logger
    )
    ctx.api.notice_callback = (lambda msg: report(notice=msg)) if progress else None
    try:
        events = collector.execute(
            start_date,
            end_date,
            on_page=lambda fetched, total: report(fetched=fetched, total=total, notice=None),
        )
    finally:
        ctx.api.notice_callback = None
    if stages:
        stages.end_stage("Stage 1: Fetch audit events", events_fetched=len(events))

    report(stage="filter", fetched=len(events))
    events = sort_events(filter_events(events, search_string))
    report(matched=len(events))

    if human_readable:
        if stages:
            stages.start_stage("Stage 2: Resolve UUIDs (human-readable)")
        resolver = ctx.resolver
        cached_before = resolver.cache_size()
        report(stage="resolve", resolved=0, resolveTotal=len(events), lookups=0)
        for i, ev in enumerate(events, 1):
            resolver.resolve_in_event(ev)
            # Cheap dict update; reporting every event keeps the bar smooth.
            report(resolved=i, lookups=resolver.cache_size() - cached_before)
        if stages:
            stages.end_stage("Stage 2: Resolve UUIDs (human-readable)", events=len(events))

    report(stage="send")
    return events
