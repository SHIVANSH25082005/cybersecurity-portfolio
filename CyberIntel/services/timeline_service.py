from timeline_reconstruction import get_case_timeline


def timeline_summary(case_id, limit=15):
    events = get_case_timeline(case_id)
    preview = list(reversed(events[-limit:]))
    counts = {}
    for event in events:
        event_type = event.get("event_type", "UNKNOWN")
        counts[event_type] = counts.get(event_type, 0) + 1
    return {
        "total": len(events),
        "shown": len(preview),
        "counts": counts,
        "events": preview
    }
