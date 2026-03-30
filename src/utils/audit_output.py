"""Filter, sort, and print audit events to the console."""

import json


def filter_events(events, search_string):
    if not search_string:
        return list(events)
    out = []
    needle = search_string
    for e in events:
        if needle in json.dumps(e, default=str):
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
