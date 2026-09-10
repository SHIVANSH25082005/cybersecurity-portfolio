import sqlite3
from datetime import datetime
from services.cache_service import request_cached


@request_cached("time_proximity")
def calculate_time_proximity(ip_address, case_id=None, enable_cross_case=False):
    """
    Calculates the minimum time gap between different phone numbers sharing the same IP address.
    Filters by case_id to prevent cross-case contamination unless explicitly enabled.
    """
    conn = sqlite3.connect("database/cyberintel.db")
    cursor = conn.cursor()

    if case_id and not enable_cross_case:
        cursor.execute("""
            SELECT
                phone_number,
                timestamp,
                case_id
            FROM ipdr_records
            WHERE ip_address = ? AND case_id = ?
            ORDER BY timestamp
        """, (ip_address, case_id))
    else:
        cursor.execute("""
            SELECT
                phone_number,
                timestamp,
                case_id
            FROM ipdr_records
            WHERE ip_address = ?
            ORDER BY timestamp
        """, (ip_address,))

    records = cursor.fetchall()
    conn.close()

    closest_links = {}

    for i in range(len(records)):
        phone_a, time_a, cid_a = records[i]
        if not phone_a or not time_a:
            continue
        try:
            dt_a = datetime.strptime(time_a, "%Y-%m-%d %H:%M:%S")
        except:
            continue

        for j in range(i + 1, len(records)):
            phone_b, time_b, cid_b = records[j]
            if not phone_b or not time_b or phone_a == phone_b:
                continue

            try:
                dt_b = datetime.strptime(time_b, "%Y-%m-%d %H:%M:%S")
            except:
                continue

            difference = abs((dt_b - dt_a).total_seconds()) / 60
            pair = tuple(sorted([phone_a, phone_b]))

            # Track if either record is outside the current investigation case
            is_cross_case = False
            contributing_cases = {cid_a, cid_b}
            if case_id:
                if cid_a != case_id or cid_b != case_id:
                    is_cross_case = True

            if pair not in closest_links or difference < closest_links[pair]["minutes"]:
                closest_links[pair] = {
                    "minutes": difference,
                    "is_cross_case": is_cross_case,
                    "cases": list(contributing_cases)
                }

    results = []
    for pair, info in closest_links.items():
        diff = info["minutes"]
        is_cross = info["is_cross_case"]
        cases_involved = info["cases"]

        # Category-based temporal mapping:
        if diff <= 15:
            category = "Same Session"
            score = 1.0
            explanation = "Direct temporal link showing continuous threat actor session."
        elif diff <= 120:
            category = "Immediate Operational Activity"
            score = 0.8
            explanation = "Likely sequential tasks in the same campaign."
        elif diff <= 1440:
            category = "Operationally Related"
            score = 0.5
            explanation = "Multi-day coordinated actor session."
        else:
            category = "Delayed Activity"
            score = 0.2
            explanation = "Recurrent activity showing potential infrastructure reuse."

        results.append({
            "phone_a": pair[0],
            "phone_b": pair[1],
            "ip": ip_address,
            "minutes": round(diff, 2),
            "category": category,
            "score": score,
            "explanation": explanation,
            "is_cross_case": is_cross,
            "cases": cases_involved
        })

    return results