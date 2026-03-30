"""Write audit events to CSV (UTF-8)."""

import csv
import json

CSV_HEADER = [
    "eventID",
    "eventDate",
    "eventType",
    "auditResource",
    "actionType",
    "actionUserId",
    "ipAddress",
    "data",
]


def event_to_row(event: dict) -> dict:
    data = event.get("data")
    data_str = ""
    if data is not None:
        data_str = json.dumps(data, ensure_ascii=False, default=str)

    def s(v):
        if v is None:
            return ""
        return str(v)

    return {
        "eventID": s(event.get("eventID")),
        "eventDate": s(event.get("eventDate")),
        "eventType": s(event.get("eventType")),
        "auditResource": s(event.get("auditResource")),
        "actionType": s(event.get("actionType")),
        "actionUserId": s(event.get("actionUserId")),
        "ipAddress": s(event.get("ipAddress")),
        "data": data_str,
    }


def write_audit_events_csv(path: str, events: list) -> int:
    count = 0
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_HEADER, extrasaction="ignore")
        writer.writeheader()
        for ev in events:
            writer.writerow(event_to_row(ev))
            count += 1
    return count
