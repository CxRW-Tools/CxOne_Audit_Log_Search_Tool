"""
Shared query pipeline used by both the CLI (main.py) and the local web server (--serve).

fetch (GET /api/audit-events/) -> search filter -> sort by date -> optional UUID resolution
"""

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


def run_query(ctx, start_date, end_date, search_string=None, human_readable=False, stages=None):
    """
    Fetch, filter, sort and optionally resolve audit events. Returns a list of event dicts
    in the API's shape (the same objects --raw prints).

    `stages` is an optional StageTracker for CLI progress output.
    """
    if stages:
        stages.start_stage("Stage 1: Fetch audit events")
    collector = AuditEventsCollector(
        ctx.config, ctx.auth, api_client=ctx.api, progress=None, debug_logger=ctx.logger
    )
    events = collector.execute(start_date, end_date)
    if stages:
        stages.end_stage("Stage 1: Fetch audit events", events_fetched=len(events))

    events = sort_events(filter_events(events, search_string))

    if human_readable:
        if stages:
            stages.start_stage("Stage 2: Resolve UUIDs (human-readable)")
        resolver = ctx.resolver
        for ev in events:
            resolver.resolve_in_event(ev)
        if stages:
            stages.end_stage("Stage 2: Resolve UUIDs (human-readable)", events=len(events))

    return events
