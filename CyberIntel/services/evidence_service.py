import sqlite3
import hashlib
import os
from datetime import datetime

DB_PATH = "database/cyberintel.db"


def log_custody_event(
    evidence_id, case_id, actor, action,
    notes="", prev_value=None, new_value=None
):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO evidence_events
        (evidence_id, case_id, actor, action, event_time, notes, prev_value, new_value)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        evidence_id,
        case_id,
        actor,
        action,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        notes,
        prev_value,
        new_value
    ))
    conn.commit()
    conn.close()


def get_audit_trail(evidence_id, page=1, per_page=20):
    offset = (page - 1) * per_page
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, action, actor, event_time, notes, prev_value, new_value
        FROM evidence_events
        WHERE evidence_id = ?
        ORDER BY event_time DESC, id DESC
        LIMIT ? OFFSET ?
    """, (evidence_id, per_page, offset))
    rows = cursor.fetchall()
    cursor.execute(
        "SELECT COUNT(*) FROM evidence_events WHERE evidence_id = ?",
        (evidence_id,)
    )
    total = cursor.fetchone()[0]
    conn.close()
    pages = max(1, (total + per_page - 1) // per_page)
    return {
        "events": [
            {
                "id": r[0],
                "action": r[1],
                "actor": r[2],
                "event_time": r[3],
                "notes": r[4],
                "prev_value": r[5],
                "new_value": r[6]
            }
            for r in rows
        ],
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": pages
    }


def verify_file_integrity(evidence_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT case_id, file_name, sha256_hash
        FROM evidence_items
        WHERE evidence_id = ?
    """, (evidence_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return {
            "verified": False,
            "stored_hash": None,
            "computed_hash": None,
            "reason": "Evidence record not found."
        }

    case_id, file_name, stored_hash = row
    file_path = os.path.join("uploads", "evidence", case_id, file_name)

    if not os.path.exists(file_path):
        return {
            "verified": False,
            "stored_hash": stored_hash,
            "computed_hash": None,
            "reason": "File not found on disk."
        }

    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
    computed = sha256.hexdigest()

    matched = computed == stored_hash
    return {
        "verified": matched,
        "stored_hash": stored_hash,
        "computed_hash": computed,
        "reason": "Hash match — file integrity confirmed." if matched
                  else "Hash mismatch — file may have been altered."
    }
