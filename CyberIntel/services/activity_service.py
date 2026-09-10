import sqlite3


DB_PATH = "database/cyberintel.db"


def get_recent_activity(case_id, limit=20):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT ts, kind, label, actor FROM (
            SELECT created_at AS ts, 'Note' AS kind,
                   note AS label, officer AS actor
            FROM investigation_notes WHERE case_id = ?
            UNION ALL
            SELECT created_at, 'Task', task, owner
            FROM investigation_tasks WHERE case_id = ?
            UNION ALL
            SELECT event_time, 'Evidence',
                   action || ' - ' || evidence_id, actor
            FROM evidence_events WHERE case_id = ?
            UNION ALL
            SELECT date_added, 'Entity',
                   entity_type || ': ' || entity_value, source
            FROM entities WHERE case_id = ?
            UNION ALL
            SELECT date_added, 'Complaint',
                   'Complaint by ' || complainant_name, complainant_name
            FROM complaints WHERE case_id = ?
        )
        ORDER BY ts DESC
        LIMIT ?
    """, (case_id, case_id, case_id, case_id, case_id, limit))
    rows = cursor.fetchall()
    conn.close()
    return {
        "activity": [
            {
                "time": ts,
                "kind": kind,
                "label": label,
                "actor": actor or "-"
            }
            for ts, kind, label, actor in rows
        ]
    }
