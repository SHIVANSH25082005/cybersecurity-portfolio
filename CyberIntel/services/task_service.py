import sqlite3


DB_PATH = "database/cyberintel.db"


def task_summary(case_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT status, COUNT(*)
        FROM investigation_tasks
        WHERE case_id = ?
        GROUP BY status
    """, (case_id,))
    counts = {status or "Open": count for status, count in cursor.fetchall()}
    conn.close()
    return {
        "open": counts.get("Open", 0),
        "completed": counts.get("Completed", 0),
        "total": sum(counts.values())
    }
