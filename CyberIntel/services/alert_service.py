import sqlite3

DB_PATH = "database/cyberintel.db"


def _connect():
    return sqlite3.connect(DB_PATH)



def generate_case_alerts(case_id, limit=20):
    """Detect immediate intelligence alerts for a case.

    Alerts are intentionally rule-based and deterministic: reused complaint
    indicators, reused entity values, shared IP infrastructure, rapid IP
    switching signals, and missing follow-up evidence.
    """
    conn = _connect()
    cursor = conn.cursor()
    alerts = []

    cursor.execute("""
        SELECT phone_number, upi_id, email, telegram, website
        FROM complaints
        WHERE case_id = ?
    """, (case_id,))
    indicator_rows = cursor.fetchall()

    indicator_columns = [
        ("Phone", "phone_number", 0),
        ("UPI", "upi_id", 1),
        ("Email", "email", 2),
        ("Telegram", "telegram", 3),
        ("Website", "website", 4),
    ]
    for label, column, index in indicator_columns:
        values = sorted({row[index] for row in indicator_rows if row[index]})
        for value in values:
            cursor.execute(
                f"SELECT DISTINCT case_id FROM complaints "
                f"WHERE {column} = ? AND case_id != ? AND case_id IS NOT NULL "
                f"LIMIT 10",
                (value, case_id)
            )
            linked = [row[0] for row in cursor.fetchall()]
            if linked:
                severity = "HIGH" if label in ("UPI", "Phone") else "MEDIUM"
                alerts.append({
                    "severity": severity,
                    "type": f"Reused {label}",
                    "message": f"{label} {value} appears in {len(linked)} other case(s).",
                    "indicator": value,
                    "linked_cases": linked,
                    "action": "Open linked cases and preserve related subscriber/KYC records."
                })

    cursor.execute("""
        SELECT DISTINCT ip_address
        FROM ipdr_records
        WHERE case_id = ? AND ip_address IS NOT NULL AND ip_address != ''
    """, (case_id,))
    for (ip_address,) in cursor.fetchall():
        cursor.execute("""
            SELECT DISTINCT case_id
            FROM ipdr_records
            WHERE ip_address = ? AND case_id != ? AND case_id IS NOT NULL
            LIMIT 10
        """, (ip_address, case_id))
        linked = [row[0] for row in cursor.fetchall()]
        if linked:
            alerts.append({
                "severity": "HIGH",
                "type": "Shared Infrastructure",
                "message": f"IP {ip_address} is reused in {len(linked)} other case(s).",
                "indicator": ip_address,
                "linked_cases": linked,
                "action": "Preserve server/IPDR logs and coordinate with linked investigators."
            })

    cursor.execute("""
        SELECT phone_number, COUNT(DISTINCT ip_address) AS ip_count
        FROM ipdr_records
        WHERE case_id = ? AND phone_number IS NOT NULL AND phone_number != ''
        GROUP BY phone_number
        HAVING COUNT(DISTINCT ip_address) >= 3
    """, (case_id,))
    for phone, ip_count in cursor.fetchall():
        alerts.append({
            "severity": "MEDIUM",
            "type": "Infrastructure Switching",
            "message": f"Phone {phone} used {ip_count} unique IP address(es).",
            "indicator": phone,
            "linked_cases": [],
            "action": "Review timeline for VPN/proxy or device switching pattern."
        })

    cursor.execute(
        "SELECT COUNT(*) FROM evidence_items WHERE case_id = ?",
        (case_id,)
    )
    evidence_count = cursor.fetchone()[0]
    if evidence_count == 0:
        alerts.append({
            "severity": "LOW",
            "type": "Evidence Gap",
            "message": "No digital evidence has been uploaded for this case.",
            "indicator": case_id,
            "linked_cases": [],
            "action": "Upload screenshots, notices, transaction records or IPDR/CDR files."
        })

    conn.close()

    rank = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    alerts.sort(key=lambda item: (rank.get(item["severity"], 9), item["type"]))
    return alerts[:limit]


def alert_summary(case_id):
    alerts = generate_case_alerts(case_id)
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for alert in alerts:
        counts[alert["severity"]] = counts.get(alert["severity"], 0) + 1
    return {
        "total": len(alerts),
        "counts": counts,
        "alerts": alerts
    }
