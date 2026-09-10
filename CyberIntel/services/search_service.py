import sqlite3


DB_PATH = "database/cyberintel.db"


def global_search(query):

    query = query.strip()

    if not query:
        return {}

    like = f"%{query}%"

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    results = {}

    results["cases"] = conn.execute(
        """
        SELECT *
        FROM cases
        WHERE
            case_id LIKE ?
            OR case_name LIKE ?
            OR case_type LIKE ?
            OR investigator LIKE ?
            OR status LIKE ?
        ORDER BY case_id
        """,
        (like, like, like, like, like)
    ).fetchall()

    results["complaints"] = conn.execute(
        """
        SELECT *
        FROM complaints
        WHERE
            complainant_name LIKE ?
            OR phone_number LIKE ?
            OR upi_id LIKE ?
            OR email LIKE ?
            OR telegram LIKE ?
            OR website LIKE ?
            OR complaint_details LIKE ?
            OR case_id LIKE ?
        """,
        (
            like,
            like,
            like,
            like,
            like,
            like,
            like,
            like
        )
    ).fetchall()

    results["entities"] = conn.execute(
        """
        SELECT *
        FROM entities
        WHERE
            entity_type LIKE ?
            OR entity_value LIKE ?
            OR case_id LIKE ?
        """,
        (
            like,
            like,
            like
        )
    ).fetchall()

    results["ipdr"] = conn.execute(
        """
        SELECT *
        FROM ipdr_records
        WHERE
            phone_number LIKE ?
            OR ip_address LIKE ?
            OR location LIKE ?
            OR timestamp LIKE ?
            OR case_id LIKE ?
        """,
        (
            like,
            like,
            like,
            like,
            like
        )
    ).fetchall()

    results["evidence"] = conn.execute(
        """
        SELECT *
        FROM evidence_items
        WHERE
            evidence_id LIKE ?
            OR case_id LIKE ?
            OR file_name LIKE ?
            OR description LIKE ?
            OR sha256_hash LIKE ?
        """,
        (
            like,
            like,
            like,
            like,
            like
        )
    ).fetchall()

    results["notes"] = conn.execute(
        """
        SELECT *
        FROM investigation_notes
        WHERE
            case_id LIKE ?
            OR note LIKE ?
            OR officer LIKE ?
        """,
        (
            like,
            like,
            like
        )
    ).fetchall()

    results["tasks"] = conn.execute(
        """
        SELECT *
        FROM investigation_tasks
        WHERE
            case_id LIKE ?
            OR task LIKE ?
            OR owner LIKE ?
            OR status LIKE ?
        """,
        (
            like,
            like,
            like,
            like
        )
    ).fetchall()

    conn.close()

    return results