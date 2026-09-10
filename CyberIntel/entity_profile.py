"""
Entity Intelligence Profiles (Module 4)
=======================================

A dedicated intelligence profile for every entity, for all current entity
types automatically. It does NOT duplicate risk / confidence / timeline /
graph logic - it reuses:

- fusion_engine.get_neighbors        -> relationship graph (with expansion)
- app.get_relationship_explanation   -> IP confidence (lazy import)
- timeline_reconstruction.get_case_timeline -> timeline (lazy import)

Design for scale:
- Every lookup is scoped to the selected entity value (indexed columns:
  entities.entity_value, complaints.<indicator>, ipdr_records.phone/ip).
- The summary is cheap and loads first; heavy sections (timeline, graph,
  history, related, ...) are lazy-loaded one endpoint at a time.
- Long lists are paginated. No N+1: linked cases are fetched in a single
  IN (...) query. A bounded in-memory cache fronts the summary.

Extensibility:
- A section registry (register_section) lets future modules (Evidence,
  Financial, Similarity, Alerts, MO Detection) add a profile section with a
  single call and no template/JS change - the generic renderer consumes a
  {kv} / {rows} / {message} shape.
"""

import sqlite3

from fusion_engine import get_neighbors, _norm_type, FUSION_ENTITY_TYPES

DB_PATH = "database/cyberintel.db"

PAGE_SIZE = 10

# Fixed column whitelists (safe for query building - never user input).
_COMPLAINT_COLUMN = {
    "Phone": "phone_number",
    "UPI": "upi_id",
    "Email": "email",
    "Telegram": "telegram",
    "Website": "website",
}

_IPDR_COLUMN = {
    "Phone": "phone_number",
    "IP": "ip_address",
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


# ============================================================
# Occurrence collection (scoped, indexed, no N+1)
# ============================================================

def _collect_occurrences(entity_type, value, cursor):
    """Every place this entity value appears -> (timestamp, case_id, source).

    Only indexed columns are queried, always filtered to this value."""
    rows = []

    cursor.execute(
        "SELECT date_added, case_id FROM entities WHERE entity_value = ?",
        (value,)
    )
    for ts, case_id in cursor.fetchall():
        rows.append((ts, case_id, "Intelligence"))

    column = _COMPLAINT_COLUMN.get(entity_type)
    if column:
        cursor.execute(
            "SELECT date_added, case_id FROM complaints "
            "WHERE {0} = ?".format(column), (value,)
        )
        for ts, case_id in cursor.fetchall():
            rows.append((ts, case_id, "Complaint"))

    ipdr_column = _IPDR_COLUMN.get(entity_type)
    if ipdr_column:
        cursor.execute(
            "SELECT timestamp, case_id FROM ipdr_records "
            "WHERE {0} = ?".format(ipdr_column), (value,)
        )
        for ts, case_id in cursor.fetchall():
            rows.append((ts, case_id, "IPDR"))

    if entity_type == "Case":
        cursor.execute(
            "SELECT created_date, case_id FROM cases WHERE case_id = ?",
            (value,)
        )
        for ts, case_id in cursor.fetchall():
            rows.append((ts, case_id, "Case"))

    if entity_type == "Investigator":
        cursor.execute(
            "SELECT created_date, case_id FROM cases WHERE investigator = ?",
            (value,)
        )
        for ts, case_id in cursor.fetchall():
            rows.append((ts, case_id, "Case"))

    if entity_type == "Evidence":
        cursor.execute(
            "SELECT uploaded_at, case_id FROM evidence_items "
            "WHERE evidence_id = ?", (value,)
        )
        for ts, case_id in cursor.fetchall():
            rows.append((ts, case_id, "Evidence"))

    return rows


def _linked_case_ids(entity_type, value, cursor):
    occurrences = _collect_occurrences(entity_type, value, cursor)
    return sorted({c for _, c, _ in occurrences if c})


# ============================================================
# Confidence + Risk (reuses existing calculations / thresholds)
# ============================================================

def _entity_confidence(entity_type, value, linked_cases, occurrences):
    if entity_type == "IP":
        # Reuse the platform IP confidence engine (no duplication).
        from app import get_relationship_explanation
        explanation = get_relationship_explanation(value)
        return explanation.get("confidence", "Unknown")

    if linked_cases >= 2:
        return "Strong"
    if occurrences >= 2 or linked_cases == 1:
        return "Moderate"
    if occurrences >= 1:
        return "Weak"
    return "Unknown"


def _entity_risk(linked_cases, occurrences, confidence):
    """Reuses the complaint risk bands: >= 4 HIGH, >= 1.5 MEDIUM, else LOW."""
    points = linked_cases * 2.0
    if occurrences > 1:
        points += min(occurrences - 1, 4) * 0.5
    if confidence == "Strong":
        points += 2.0
    elif confidence == "Moderate":
        points += 1.0

    if points >= 4:
        level = "HIGH"
    elif points >= 1.5:
        level = "MEDIUM"
    else:
        level = "LOW"
    return level, round(points, 1)


# ============================================================
# Summary (cheap, loads first)
# ============================================================

def get_entity_summary(entity_type, value):
    entity_type = _norm_type(entity_type)
    cache_key = ("summary", entity_type, value)
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    conn = _connect()
    cursor = conn.cursor()
    try:
        occurrences = _collect_occurrences(entity_type, value, cursor)
    finally:
        conn.close()

    timestamps = sorted(ts for ts, _, _ in occurrences if ts)
    linked_cases = sorted({c for _, c, _ in occurrences if c})
    occurrence_count = len(occurrences)

    confidence = _entity_confidence(
        entity_type, value, len(linked_cases), occurrence_count
    )
    risk_level, risk_points = _entity_risk(
        len(linked_cases), occurrence_count, confidence
    )

    source_counts = {}
    for _, _, source in occurrences:
        source_counts[source] = source_counts.get(source, 0) + 1

    summary = {
        "entity_type": entity_type,
        "value": value,
        "risk_level": risk_level,
        "risk_points": risk_points,
        "confidence": confidence,
        "occurrence_count": occurrence_count,
        "first_seen": timestamps[0] if timestamps else None,
        "last_seen": timestamps[-1] if timestamps else None,
        "linked_case_count": len(linked_cases),
        "linked_cases": linked_cases,
        "source_counts": source_counts,
    }
    _cache_put(cache_key, summary)
    return summary


# ============================================================
# Section registry (future modules plug in here)
# ============================================================

_SECTIONS = []
_SECTION_INDEX = {}


def register_section(slug, title, provider, render="epRenderGeneric",
                     hint="", lazy=True, span=False):
    """Register a profile section.

    provider(entity_type, value, page) -> dict consumed by the JS `render`
    function. Built-in renderers: epRenderGeneric ({kv}/{rows}/{message}),
    epRenderTimeline, epRenderGraph. Future modules can reuse epRenderGeneric
    and need no template or JS change."""
    if slug in _SECTION_INDEX:
        return
    section = {
        "slug": slug,
        "title": title,
        "provider": provider,
        "render": render,
        "hint": hint,
        "lazy": lazy,
        "span": span,
    }
    _SECTIONS.append(section)
    _SECTION_INDEX[slug] = section


def get_sections():
    """Section metadata for the template (no provider callables)."""
    return [
        {k: s[k] for k in ("slug", "title", "render", "hint", "lazy", "span")}
        for s in _SECTIONS
    ]


def get_section_data(slug, entity_type, value, page=1):
    section = _SECTION_INDEX.get(slug)
    if not section:
        return {"message": "Unknown section."}
    entity_type = _norm_type(entity_type)
    try:
        return section["provider"](entity_type, value, page)
    except Exception:
        return {"message": "This section could not be loaded."}


def _paginate(rows, page):
    total = len(rows)
    start = (page - 1) * PAGE_SIZE
    page_rows = rows[start:start + PAGE_SIZE]
    return {
        "rows": page_rows,
        "total": total,
        "page": page,
        "page_size": PAGE_SIZE,
        "has_more": start + PAGE_SIZE < total,
    }


# ============================================================
# Built-in section providers
# ============================================================

def _section_timeline(entity_type, value, page):
    """Reuses get_case_timeline for the entity's own cases (bounded)."""
    from timeline_reconstruction import get_case_timeline

    conn = _connect()
    cursor = conn.cursor()
    try:
        case_ids = _linked_case_ids(entity_type, value, cursor)
    finally:
        conn.close()

    events = []
    for case_id in case_ids[:3]:           # cap cases scanned for the preview
        for event in get_case_timeline(case_id):
            item = dict(event)
            item["case_id"] = case_id
            events.append(item)

    events.sort(key=lambda e: e.get("timestamp") or "", reverse=True)
    preview = events[:15]
    return {
        "events": preview,
        "shown": len(preview),
        "total": len(events),
    }


def _section_graph(entity_type, value, page):
    """Reuses the Fusion Engine; the client expands nodes via /fusion."""
    return get_neighbors(entity_type, value)


def _section_history(entity_type, value, page):
    conn = _connect()
    cursor = conn.cursor()
    try:
        case_ids = _linked_case_ids(entity_type, value, cursor)
        rows = []
        if case_ids:
            placeholders = ",".join("?" * len(case_ids))
            cursor.execute(
                "SELECT case_id, case_name, case_type, investigator, status, "
                "created_date FROM cases WHERE case_id IN ({0}) "
                "ORDER BY created_date DESC".format(placeholders),
                case_ids
            )
            for cid, name, ctype, investigator, status, created in cursor.fetchall():
                rows.append({
                    "label": "{0} - {1}".format(cid, name or ""),
                    "sub": "{0} · Investigator: {1} · {2}".format(
                        ctype or "—", investigator or "—", created or "—"),
                    "badge": status or "—",
                    "href": "/workspace/{0}".format(cid),
                })
    finally:
        conn.close()
    return _paginate(rows, page)


def _section_related(entity_type, value, page):
    """Co-occurring entities (share a case). Links open their profiles."""
    conn = _connect()
    cursor = conn.cursor()
    try:
        case_ids = _linked_case_ids(entity_type, value, cursor)
        rows = []
        if case_ids:
            placeholders = ",".join("?" * len(case_ids))
            cursor.execute(
                "SELECT DISTINCT entity_type, entity_value FROM entities "
                "WHERE case_id IN ({0}) AND entity_value != ? "
                "AND entity_value != '' "
                "ORDER BY entity_type".format(placeholders),
                case_ids + [value]
            )
            for etype, evalue in cursor.fetchall():
                canonical = _norm_type(etype)
                rows.append({
                    "label": evalue,
                    "sub": canonical,
                    "badge": canonical,
                    "href": "/entity?type={0}&value={1}".format(
                        canonical, evalue),
                })
    finally:
        conn.close()
    return _paginate(rows, page)


def _section_complaints(entity_type, value, page):
    conn = _connect()
    cursor = conn.cursor()
    try:
        seen = set()
        rows = []

        column = _COMPLAINT_COLUMN.get(entity_type)
        if column:
            cursor.execute(
                "SELECT id, complainant_name, complaint_details, case_id "
                "FROM complaints WHERE {0} = ? "
                "ORDER BY id DESC".format(column), (value,)
            )
            for cid, name, details, case_id in cursor.fetchall():
                seen.add(cid)
                rows.append(_complaint_row(cid, name, details, case_id))

        case_ids = _linked_case_ids(entity_type, value, cursor)
        if case_ids:
            placeholders = ",".join("?" * len(case_ids))
            cursor.execute(
                "SELECT id, complainant_name, complaint_details, case_id "
                "FROM complaints WHERE case_id IN ({0}) "
                "ORDER BY id DESC".format(placeholders), case_ids
            )
            for cid, name, details, case_id in cursor.fetchall():
                if cid not in seen:
                    seen.add(cid)
                    rows.append(_complaint_row(cid, name, details, case_id))
    finally:
        conn.close()
    return _paginate(rows, page)


def _complaint_row(cid, name, details, case_id):
    detail = (details or "").strip()
    if len(detail) > 90:
        detail = detail[:89] + "…"
    return {
        "label": "Complaint #{0} - {1}".format(cid, name or "Unknown"),
        "sub": detail or "No details recorded.",
        "badge": case_id or "—",
        "href": "/workspace/{0}".format(case_id) if case_id else "",
    }


def _section_infrastructure(entity_type, value, page):
    """IPs/phones tied to this entity. Links open their profiles."""
    conn = _connect()
    cursor = conn.cursor()
    rows = []
    try:
        if entity_type == "Phone":
            cursor.execute(
                "SELECT ip_address, COUNT(*) FROM ipdr_records "
                "WHERE phone_number = ? AND ip_address IS NOT NULL "
                "AND ip_address != '' GROUP BY ip_address "
                "ORDER BY COUNT(*) DESC", (value,)
            )
            rows = [_infra_row("IP", ip, hits) for ip, hits in cursor.fetchall()]

        elif entity_type == "IP":
            cursor.execute(
                "SELECT phone_number, COUNT(*) FROM ipdr_records "
                "WHERE ip_address = ? AND phone_number IS NOT NULL "
                "AND phone_number != '' GROUP BY phone_number "
                "ORDER BY COUNT(*) DESC", (value,)
            )
            rows = [_infra_row("Phone", ph, hits) for ph, hits in cursor.fetchall()]

        else:
            case_ids = _linked_case_ids(entity_type, value, cursor)
            if case_ids:
                placeholders = ",".join("?" * len(case_ids))
                cursor.execute(
                    "SELECT ip_address, COUNT(*) FROM ipdr_records "
                    "WHERE case_id IN ({0}) AND ip_address IS NOT NULL "
                    "AND ip_address != '' GROUP BY ip_address "
                    "ORDER BY COUNT(*) DESC".format(placeholders), case_ids
                )
                rows = [_infra_row("IP", ip, hits) for ip, hits in cursor.fetchall()]
    finally:
        conn.close()
    return _paginate(rows, page)


def _infra_row(node_type, node_value, hits):
    return {
        "label": node_value,
        "sub": "{0} hit(s) in IPDR".format(hits),
        "badge": node_type,
        "href": "/entity?type={0}&value={1}".format(node_type, node_value),
    }


def _section_activity(entity_type, value, page):
    conn = _connect()
    cursor = conn.cursor()
    try:
        occurrences = _collect_occurrences(entity_type, value, cursor)
    finally:
        conn.close()

    occurrences.sort(key=lambda o: o[0] or "", reverse=True)
    rows = []
    for ts, case_id, source in occurrences:
        rows.append({
            "label": "{0} record{1}".format(
                source, " in " + case_id if case_id else ""),
            "sub": ts or "—",
            "badge": source,
            "href": "/workspace/{0}".format(case_id) if case_id else "",
        })
    return _paginate(rows, page)



def _section_modus_operandi(entity_type, value, page):
    """Shows the detected Modus Operandi for cases associated with this entity."""
    from services.modus_operandi_service import detect_case_mo
    conn = _connect()
    cursor = conn.cursor()
    try:
        case_ids = _linked_case_ids(entity_type, value, cursor)
    finally:
        conn.close()

    rows = []
    for case_id in case_ids:
        mo_data = detect_case_mo(case_id)
        if mo_data:
            rows.append({
                "label": "{0} - {1}".format(case_id, mo_data.get("case_name") or ""),
                "sub": "M.O. detected: {0} ({1}% confidence). Signatures: {2}".format(
                    mo_data.get("detected_mo", "Generic/Unknown"),
                    mo_data.get("confidence", 0),
                    ", ".join(mo_data.get("signatures", [])[:3])
                ),
                "badge": mo_data.get("detected_mo", "Generic/Unknown"),
                "href": "/workspace/{0}".format(case_id)
            })

    return _paginate(rows, page)


# Built-in sections (order = display order). Future modules append more.
register_section("timeline", "Timeline Preview", _section_timeline,
                 render="epRenderTimeline",
                 hint="recent events · click to load", span=True)
register_section("graph", "Relationship Graph", _section_graph,
                 render="epRenderGraph",
                 hint="Fusion Engine · scroll to zoom · click to expand",
                 span=True)
register_section("history", "Investigation History", _section_history,
                 hint="linked cases")
register_section("related", "Linked Entities", _section_related,
                 hint="co-occurring · opens profile")
register_section("complaints", "Linked Complaints", _section_complaints,
                 hint="complaints referencing this entity")
register_section("infrastructure", "Related Infrastructure",
                 _section_infrastructure, hint="IPs / phones")
register_section("activity", "Recent Activity", _section_activity,
                 hint="latest occurrences")
register_section("modus_operandi", "Modus Operandi Detection",
                 _section_modus_operandi, hint="detected crime pattern profiles")
