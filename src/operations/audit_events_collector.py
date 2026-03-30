"""Fetch all audit events for a calendar date range via GET /api/audit-events/."""

from datetime import date, datetime, timezone

from .base import Operation


def _rfc3339_utc_bounds(start_date: date, end_date: date):
    start_dt = datetime.combine(start_date, datetime.min.time(), tzinfo=timezone.utc)
    end_dt = datetime.combine(
        end_date,
        datetime.max.time().replace(microsecond=999999),
        tzinfo=timezone.utc,
    )

    def to_z(dt: datetime) -> str:
        s = dt.isoformat()
        if s.endswith("+00:00"):
            return s[:-6] + "Z"
        return s

    return to_z(start_dt), to_z(end_dt)


class AuditEventsCollector(Operation):
    def execute(self, start_date: date, end_date: date):
        start_s, end_s = _rfc3339_utc_bounds(start_date, end_date)
        params = {"startDate": start_s, "endDate": end_s}
        if self.logger:
            self.logger.log(f"AuditEventsCollector: startDate={start_s} endDate={end_s}")
        events = self.api_client.get_audit_events_all(params)
        return events or []
