"""Filter, sort, and print audit events to the console."""

import json


def filter_events(events, search_string, ignore_case=False):
    """
    Keep events whose JSON contains `search_string`. Matching uses the unescaped text
    (ensure_ascii=False) so non-ASCII names like "José" match. The CLI is case-sensitive by
    default; the web dashboard passes ignore_case=True to match its own search box.
    """
    if not search_string:
        return list(events)
    needle = search_string.casefold() if ignore_case else search_string
    out = []
    for e in events:
        hay = json.dumps(e, default=str, ensure_ascii=False)
        if needle in (hay.casefold() if ignore_case else hay):
            out.append(e)
    return out


def sort_events(events):
    return sorted(events, key=lambda x: (x.get("eventDate") or ""))


def print_formatted_events(events):
    print("-" * 40)
    for log in events:
        event_date = log.get("eventDate", "N/A")
        event_type = log.get("eventType", "N/A")
        action_user = log.get("actionUserId", "N/A")
        print(f"Event Date: {event_date}")
        print(f"Event Type: {event_type}")
        print(f"Action User: {action_user}")
        data_fields = log.get("data") or {}
        if data_fields:
            print("Data:")
            for key, value in data_fields.items():
                if isinstance(value, list):
                    value = ", ".join(map(str, value))
                print(f"  {key}: {value}")
        print("-" * 40)
