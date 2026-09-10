import sqlite3


DB_PATH = "database/cyberintel.db"


def note_summary(case_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT COUNT(*), MAX(created_at) FROM investigation_notes WHERE case_id = ?",
        (case_id,)
    )
    total, latest = cursor.fetchone()
    conn.close()
    return {"total": total or 0, "latest": latest}
