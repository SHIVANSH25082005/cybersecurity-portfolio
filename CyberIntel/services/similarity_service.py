import sqlite3
from datetime import datetime


DB_PATH = "database/cyberintel.db"

INDICATOR_WEIGHTS = {
    "Phone": 18,
    "UPI": 22,
    "Email": 10,
    "Telegram": 10,
    "Website": 8,
    "IP": 26,
    "Entity": 14,
    "Evidence": 20,
    "Hash": 28,
}

_CACHE = {}
_CACHE_MAX = 256


def _connect():
    return sqlite3.connect(DB_PATH)


def _cache_get(key):
    return _CACHE.get(key)


def _cache_put(key, value):
    if len(_CACHE) >= _CACHE_MAX:
        _CACHE.clear()
    _CACHE[key] = value


def _case_meta(cursor, case_id):
    cursor.execute(
        "SELECT case_id, case_name, case_type, investigator, status, created_date "
        "FROM cases WHERE case_id = ?",
        (case_id,)
    )
    row = cursor.fetchone()
    if not row:
        return None
    return {
        "case_id": row[0],
        "case_name": row[1],
        "case_type": row[2],
        "investigator": row[3],
        "status": row[4],
        "created_date": row[5],
    }


def _collect_features(cursor, case_id):
    features = []

    cursor.execute("""
        SELECT 'Phone', phone_number, 'Complaint'
        FROM complaints
        WHERE case_id = ? AND phone_number IS NOT NULL AND phone_number != ''
        UNION ALL
        SELECT 'UPI', upi_id, 'Complaint'
        FROM complaints
        WHERE case_id = ? AND upi_id IS NOT NULL AND upi_id != ''
        UNION ALL
        SELECT 'Email', email, 'Complaint'
        FROM complaints
        WHERE case_id = ? AND email IS NOT NULL AND email != ''
        UNION ALL
        SELECT 'Telegram', telegram, 'Complaint'
        FROM complaints
        WHERE case_id = ? AND telegram IS NOT NULL AND telegram != ''
        UNION ALL
        SELECT 'Website', website, 'Complaint'
        FROM complaints
        WHERE case_id = ? AND website IS NOT NULL AND website != ''
        UNION ALL
        SELECT CASE
                 WHEN entity_type IN ('Phone', 'UPI', 'Email', 'Telegram', 'Website') THEN entity_type
                 WHEN entity_type IN ('IP Address', 'IP') THEN 'IP'
                 WHEN entity_type IN ('Evidence Hash', 'Hash') THEN 'Hash'
                 ELSE 'Entity'
               END AS feature_type,
               entity_value,
               'Entity'
        FROM entities
        WHERE case_id = ? AND entity_value IS NOT NULL AND entity_value != ''
        UNION ALL
        SELECT 'IP', ip_address, 'IPDR'
        FROM ipdr_records
        WHERE case_id = ? AND ip_address IS NOT NULL AND ip_address != ''
        UNION ALL
        SELECT 'Phone', phone_number, 'IPDR'
        FROM ipdr_records
        WHERE case_id = ? AND phone_number IS NOT NULL AND phone_number != ''
        UNION ALL
        SELECT 'Evidence', evidence_id, 'Evidence'
        FROM evidence_items
        WHERE case_id = ? AND evidence_id IS NOT NULL AND evidence_id != ''
        UNION ALL
        SELECT 'Hash', sha256_hash, 'Evidence'
        FROM evidence_items
        WHERE case_id = ? AND sha256_hash IS NOT NULL AND sha256_hash != ''
    """, (case_id, case_id, case_id, case_id, case_id, case_id, case_id, case_id, case_id, case_id))

    for feature_type, value, source in cursor.fetchall():
        if value:
            features.append((feature_type, value, source))

    meta = _case_meta(cursor, case_id)
    return features, meta


def _parse_date(value):
    if not value:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(value, fmt)
        except Exception:
            pass
    return None


def _score_match(feature_type, count, same_case_type=False, same_investigator=False):
    score = INDICATOR_WEIGHTS.get(feature_type, 6)
    if count > 1:
        score += min(count - 1, 4) * 4
    if same_case_type:
        score += 5
    if same_investigator:
        score += 7
    return score


def compare_cases(case_a, case_b):
    conn = _connect()
    cursor = conn.cursor()
    try:
        features_a, meta_a = _collect_features(cursor, case_a)
        features_b, meta_b = _collect_features(cursor, case_b)
        if not meta_a or not meta_b:
            return None
    finally:
        conn.close()

    set_a = {}
    set_b = {}
    for feature_type, value, source in features_a:
        set_a.setdefault((feature_type, value), set()).add(source)
    for feature_type, value, source in features_b:
        set_b.setdefault((feature_type, value), set()).add(source)

    shared = []
    raw_score = 0

    for key, sources_a in set_a.items():
        if key not in set_b:
            continue
        feature_type, value = key
        shared_sources = sorted(sources_a | set_b[key])
        count = len(shared_sources)
        score = _score_match(
            feature_type,
            count,
            same_case_type=(meta_a["case_type"] == meta_b["case_type"] and meta_a["case_type"]),
            same_investigator=(meta_a["investigator"] == meta_b["investigator"] and meta_a["investigator"]),
        )
        raw_score += score
        shared.append({
            "type": feature_type,
            "value": value,
            "score": score,
            "sources": shared_sources,
        })

    if meta_a["case_type"] and meta_a["case_type"] == meta_b["case_type"]:
        raw_score += 8
    if meta_a["investigator"] and meta_a["investigator"] == meta_b["investigator"]:
        raw_score += 6

    date_a = _parse_date(meta_a["created_date"])
    date_b = _parse_date(meta_b["created_date"])
    if date_a and date_b:
        gap_days = abs((date_a - date_b).days)
        if gap_days <= 7:
            raw_score += 8
        elif gap_days <= 30:
            raw_score += 4
    else:
        gap_days = None

    overlap_types = sorted({item["type"] for item in shared})
    total_weight = sum(INDICATOR_WEIGHTS.get(t, 6) for t in overlap_types) or 1
    normalized = min(100, round((raw_score / (total_weight + 20)) * 100))

    explanation = []
    if shared:
        top = sorted(shared, key=lambda item: item["score"], reverse=True)[:3]
        for item in top:
            explanation.append(f"Shared {item['type']}: {item['value']}")
    if meta_a["case_type"] and meta_a["case_type"] == meta_b["case_type"]:
        explanation.append(f"Same case type: {meta_a['case_type']}")
    if meta_a["investigator"] and meta_a["investigator"] == meta_b["investigator"]:
        explanation.append(f"Same investigator: {meta_a['investigator']}")
    if gap_days is not None and gap_days <= 30:
        explanation.append(f"Case creation gap: {gap_days} day(s)")
    if not explanation:
        explanation.append("No direct indicator overlap found.")

    return {
        "case1": meta_a,
        "case2": meta_b,
        "strength": normalized,
        "shared_count": len(shared),
        "shared_indicators": sorted(shared, key=lambda item: item["score"], reverse=True),
        "explanation": explanation,
        "case_gap_days": gap_days,
    }


def get_case_similarity(case_id, limit=8):
    cache_key = (case_id, limit)
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    conn = _connect()
    cursor = conn.cursor()
    features, meta = _collect_features(cursor, case_id)
    if not meta:
        conn.close()
        result = {
            "case": None,
            "summary": "Case not found.",
            "results": [],
            "top_score": 0,
            "signal_count": 0,
        }
        _cache_put(cache_key, result)
        return result

    feature_map = {}
    for feature_type, value, source in features:
        feature_map.setdefault((feature_type, value), set()).add(source)

    candidates = {}
    query_specs = [
        ("Phone", "complaints", "phone_number"),
        ("UPI", "complaints", "upi_id"),
        ("Email", "complaints", "email"),
        ("Telegram", "complaints", "telegram"),
        ("Website", "complaints", "website"),
        ("Phone", "entities", "entity_value"),
        ("UPI", "entities", "entity_value"),
        ("Email", "entities", "entity_value"),
        ("Telegram", "entities", "entity_value"),
        ("Website", "entities", "entity_value"),
        ("IP", "ipdr_records", "ip_address"),
        ("Phone", "ipdr_records", "phone_number"),
        ("Evidence", "evidence_items", "evidence_id"),
        ("Hash", "evidence_items", "sha256_hash"),
    ]

    for feature_type, table, column in query_specs:
        values = sorted({value for t, value in feature_map if t == feature_type})
        if not values:
            continue
        placeholders = ",".join("?" * len(values))
        if table == "complaints":
            cursor.execute(
                f"SELECT DISTINCT case_id, {column} FROM {table} "
                f"WHERE {column} IN ({placeholders}) AND case_id IS NOT NULL AND case_id != ?",
                values + [case_id]
            )
        elif table == "entities":
            cursor.execute(
                f"SELECT DISTINCT case_id, {column}, entity_type FROM {table} "
                f"WHERE {column} IN ({placeholders}) AND case_id IS NOT NULL AND case_id != ?",
                values + [case_id]
            )
        elif table == "ipdr_records":
            cursor.execute(
                f"SELECT DISTINCT case_id, {column} FROM {table} "
                f"WHERE {column} IN ({placeholders}) AND case_id IS NOT NULL AND case_id != ?",
                values + [case_id]
            )
        else:
            cursor.execute(
                f"SELECT DISTINCT case_id, {column} FROM {table} "
                f"WHERE {column} IN ({placeholders}) AND case_id IS NOT NULL AND case_id != ?",
                values + [case_id]
            )

        rows = cursor.fetchall()
        for row in rows:
            other_case = row[0]
            value = row[1]
            other_type = feature_type
            if table == "entities" and len(row) > 2:
                raw_type = row[2] or "Entity"
                other_type = "IP" if raw_type in ("IP", "IP Address") else raw_type
                if raw_type not in ("Phone", "UPI", "Email", "Telegram", "Website", "IP", "Evidence", "Hash"):
                    other_type = "Entity"

            candidates.setdefault(other_case, []).append({
                "type": other_type,
                "value": value,
                "source": table,
            })

    conn.close()

    results = []
    for other_case, shared_items in candidates.items():
        comparison = compare_cases(case_id, other_case)
        if not comparison:
            continue
        comparison["shared_indicators"] = shared_items
        results.append(comparison)

    results.sort(
        key=lambda item: (item["strength"], item["shared_count"]),
        reverse=True
    )
    results = results[:limit]

    summary = (
        f"Found {len(results)} similar case(s) using {len(features)} local signal(s)."
        if results else
        "No meaningful similar cases were found."
    )

    payload = {
        "case": meta,
        "summary": summary,
        "results": results,
        "top_score": results[0]["strength"] if results else 0,
        "signal_count": len(features),
    }
    _cache_put(cache_key, payload)
    return payload


def clear_cache_for_case(case_id):
    keys_to_remove = [k for k in _CACHE if (k == case_id or (isinstance(k, tuple) and case_id in k))]
    for k in keys_to_remove:
        del _CACHE[k]
