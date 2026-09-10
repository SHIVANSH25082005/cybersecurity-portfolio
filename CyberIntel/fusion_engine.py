"""
Intelligence Fusion Engine (Module 3)
======================================

A unified relationship model over the existing tables. It does NOT duplicate
correlation logic or store a second copy of the graph: it reads the existing
entities / complaints / ipdr_records / cases / evidence_items tables through
indexed, set-based queries and returns a node/edge view of a single node's
DIRECT neighbours.

Key properties:
- One pluggable source registry (register_source) so future entity types
  (BankAccount, Wallet, IMEI, ...) are added with a single function + one
  register_source() call - pipeline/engine code is never edited.
- Only directly related nodes are fetched (1 hop). Expansion is lazy: the
  client calls get_neighbors() again for any node it wants to expand.
- Per-type clustering caps fan-out so the initial/visible graph stays small;
  overflow collapses into a single expandable cluster node.
- Bounded in-memory cache. No full graph is ever materialised.
"""

import sqlite3

DB_PATH = "database/cyberintel.db"

# Canonical node types exposed to the UI filters. Future types append here.
FUSION_ENTITY_TYPES = [
    "Case", "Complaint", "Phone", "Email", "UPI", "Telegram",
    "Website", "IP", "Evidence", "Investigator",
    "BankAccount", "Wallet", "IMEI",
]

# Edge/relationship confidence weights (reuses the case_correlation weighting
# idea: infrastructure > identifiers > soft indicators).
EDGE_CONFIDENCE = {
    "IP": 90, "IP Address": 90,
    "Case": 85, "Evidence": 85,
    "Complaint": 80, "Phone": 75, "UPI": 70,
    "Investigator": 60, "Email": 55, "Telegram": 55,
    "Website": 45, "Domain": 45, "Entity": 50,
    "BankAccount": 70, "Wallet": 70, "IMEI": 75,
}

CLUSTER_CAP = 8           # max nodes of one type before clustering
_CACHE = {}               # bounded neighbour cache
_CACHE_MAX = 256

# complaint indicator columns (fixed whitelist - safe for query building)
_COMPLAINT_COLUMN = {
    "Phone": "phone_number",
    "UPI": "upi_id",
    "Email": "email",
    "Telegram": "telegram",
    "Website": "website",
}


def _connect():
    return sqlite3.connect(DB_PATH)


def _norm_type(entity_type):
    if not entity_type:
        return "Entity"
    entity_type = entity_type.strip()
    if entity_type in ("IP Address", "IP"):
        return "IP"
    if entity_type == "Domain":
        return "Website"
    return entity_type


def _node(node_type, value, label=None, **extra):
    node = {
        "id": "{0}:{1}".format(node_type, value),
        "type": node_type,
        "value": value,
        "label": label or value,
    }
    node.update(extra)
    return node


# ============================================================
# Source registry (future entity types plug in here)
# ============================================================

_SOURCES = {}


def register_source(node_type, handler):
    """handler(value, cursor, limit) -> list of
    (neighbor_type, neighbor_value, relation, confidence, [label])."""
    _SOURCES[node_type] = handler
    return handler


def registered_types():
    return sorted(_SOURCES.keys())


# ============================================================
# Built-in neighbour sources (each is a small indexed query set)
# ============================================================

def _case_neighbors(value, cursor, limit):
    out = []

    cursor.execute(
        "SELECT investigator FROM cases WHERE case_id = ?", (value,)
    )
    row = cursor.fetchone()
    if row and row[0]:
        out.append(("Investigator", row[0], "investigator",
                    EDGE_CONFIDENCE["Investigator"], row[0]))

    cursor.execute(
        "SELECT id, complainant_name FROM complaints "
        "WHERE case_id = ? LIMIT ?", (value, limit)
    )
    for complaint_id, name in cursor.fetchall():
        out.append(("Complaint", str(complaint_id), "complaint",
                    EDGE_CONFIDENCE["Complaint"],
                    "Complaint {0}: {1}".format(complaint_id, name or "")))

    cursor.execute(
        "SELECT entity_type, entity_value FROM entities "
        "WHERE case_id = ? AND entity_value != '' LIMIT ?", (value, limit)
    )
    for entity_type, entity_value in cursor.fetchall():
        canonical = _norm_type(entity_type)
        out.append((canonical, entity_value, "entity",
                    EDGE_CONFIDENCE.get(canonical, 50), entity_value))

    cursor.execute(
        "SELECT DISTINCT ip_address FROM ipdr_records "
        "WHERE case_id = ? AND ip_address IS NOT NULL "
        "AND ip_address != '' LIMIT ?", (value, limit)
    )
    for (ip_address,) in cursor.fetchall():
        out.append(("IP", ip_address, "ipdr", EDGE_CONFIDENCE["IP"], ip_address))

    cursor.execute(
        "SELECT evidence_id FROM evidence_items "
        "WHERE case_id = ? LIMIT ?", (value, limit)
    )
    for (evidence_id,) in cursor.fetchall():
        out.append(("Evidence", evidence_id, "evidence",
                    EDGE_CONFIDENCE["Evidence"], evidence_id))

    return out


def _phone_neighbors(value, cursor, limit):
    out = []

    cursor.execute(
        "SELECT DISTINCT ip_address FROM ipdr_records "
        "WHERE phone_number = ? AND ip_address IS NOT NULL "
        "AND ip_address != '' LIMIT ?", (value, limit)
    )
    for (ip_address,) in cursor.fetchall():
        out.append(("IP", ip_address, "ipdr", EDGE_CONFIDENCE["IP"], ip_address))

    cursor.execute(
        "SELECT DISTINCT case_id FROM ipdr_records "
        "WHERE phone_number = ? AND case_id IS NOT NULL LIMIT ?",
        (value, limit)
    )
    for (case_id,) in cursor.fetchall():
        out.append(("Case", case_id, "ipdr", EDGE_CONFIDENCE["Case"], case_id))

    cursor.execute(
        "SELECT DISTINCT case_id FROM complaints "
        "WHERE phone_number = ? AND case_id IS NOT NULL LIMIT ?",
        (value, limit)
    )
    for (case_id,) in cursor.fetchall():
        out.append(("Case", case_id, "complaint",
                    EDGE_CONFIDENCE["Phone"], case_id))

    cursor.execute(
        "SELECT DISTINCT case_id FROM entities "
        "WHERE entity_value = ? AND case_id IS NOT NULL LIMIT ?",
        (value, limit)
    )
    for (case_id,) in cursor.fetchall():
        out.append(("Case", case_id, "entity",
                    EDGE_CONFIDENCE["Phone"], case_id))

    return out


def _ip_neighbors(value, cursor, limit):
    out = []

    cursor.execute(
        "SELECT DISTINCT phone_number FROM ipdr_records "
        "WHERE ip_address = ? AND phone_number IS NOT NULL "
        "AND phone_number != '' LIMIT ?", (value, limit)
    )
    for (phone,) in cursor.fetchall():
        out.append(("Phone", phone, "ipdr", EDGE_CONFIDENCE["Phone"], phone))

    cursor.execute(
        "SELECT DISTINCT case_id FROM ipdr_records "
        "WHERE ip_address = ? AND case_id IS NOT NULL LIMIT ?",
        (value, limit)
    )
    for (case_id,) in cursor.fetchall():
        out.append(("Case", case_id, "ipdr", EDGE_CONFIDENCE["Case"], case_id))

    return out


def _complaint_neighbors(value, cursor, limit):
    out = []
    cursor.execute(
        "SELECT case_id, phone_number, upi_id, email, telegram, website "
        "FROM complaints WHERE id = ?", (value,)
    )
    row = cursor.fetchone()
    if not row:
        return out

    case_id, phone, upi, email, telegram, website = row
    if case_id:
        out.append(("Case", case_id, "case", EDGE_CONFIDENCE["Case"], case_id))
    for indicator_type, indicator_value in (
        ("Phone", phone), ("UPI", upi), ("Email", email),
        ("Telegram", telegram), ("Website", website),
    ):
        if indicator_value:
            out.append((indicator_type, indicator_value, "indicator",
                        EDGE_CONFIDENCE.get(indicator_type, 50),
                        indicator_value))
    return out


def _evidence_neighbors(value, cursor, limit):
    out = []
    cursor.execute(
        "SELECT case_id FROM evidence_items WHERE evidence_id = ?", (value,)
    )
    row = cursor.fetchone()
    if row and row[0]:
        out.append(("Case", row[0], "evidence",
                    EDGE_CONFIDENCE["Case"], row[0]))
    return out


def _investigator_neighbors(value, cursor, limit):
    out = []
    cursor.execute(
        "SELECT case_id FROM cases WHERE investigator = ? LIMIT ?",
        (value, limit)
    )
    for (case_id,) in cursor.fetchall():
        out.append(("Case", case_id, "assigned",
                    EDGE_CONFIDENCE["Case"], case_id))
    return out


def _make_indicator_source(node_type):
    column = _COMPLAINT_COLUMN.get(node_type)

    def handler(value, cursor, limit):
        out = []
        if column:
            cursor.execute(
                "SELECT DISTINCT case_id FROM complaints "
                "WHERE {0} = ? AND case_id IS NOT NULL "
                "LIMIT ?".format(column), (value, limit)
            )
            for (case_id,) in cursor.fetchall():
                out.append(("Case", case_id, "complaint",
                            EDGE_CONFIDENCE.get(node_type, 50), case_id))
        cursor.execute(
            "SELECT DISTINCT case_id FROM entities "
            "WHERE entity_value = ? AND case_id IS NOT NULL LIMIT ?",
            (value, limit)
        )
        for (case_id,) in cursor.fetchall():
            out.append(("Case", case_id, "entity",
                        EDGE_CONFIDENCE.get(node_type, 50), case_id))
        return out

    return handler


register_source("Case", _case_neighbors)
register_source("Phone", _phone_neighbors)
register_source("IP", _ip_neighbors)
register_source("Complaint", _complaint_neighbors)
register_source("Evidence", _evidence_neighbors)
register_source("Investigator", _investigator_neighbors)
for _indicator in ("Email", "UPI", "Telegram", "Website"):
    register_source(_indicator, _make_indicator_source(_indicator))


# ============================================================
# Public API
# ============================================================

def _cache_get(key):
    return _CACHE.get(key)


def _cache_put(key, value):
    if len(_CACHE) >= _CACHE_MAX:
        _CACHE.clear()
    _CACHE[key] = value


def get_neighbors(node_type, value, limit=40, confidence_min=0, types=None):
    """Return the center node plus its direct neighbours (1 hop), filtered by
    confidence and node type, with per-type clustering."""
    center = _node(node_type, value)
    handler = _SOURCES.get(node_type)
    if not handler or not value:
        return {"center": center["id"], "nodes": [center], "edges": []}

    types_key = ",".join(sorted(types)) if types else ""
    cache_key = (node_type, value, limit, confidence_min, types_key)
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    conn = _connect()
    cursor = conn.cursor()
    try:
        raw = handler(value, cursor, limit)
    finally:
        conn.close()

    filtered = []
    for item in raw:
        neighbor_type, neighbor_value = item[0], item[1]
        relation, confidence = item[2], item[3]
        label = item[4] if len(item) > 4 else neighbor_value
        if confidence < confidence_min:
            continue
        if types and neighbor_type not in types:
            continue
        filtered.append(
            (neighbor_type, neighbor_value, relation, confidence, label)
        )

    groups = {}
    for entry in filtered:
        groups.setdefault(entry[0], []).append(entry)

    nodes = [center]
    edges = []
    seen = {center["id"]}

    for neighbor_type, entries in groups.items():
        shown = entries[:CLUSTER_CAP]
        for n_type, n_value, relation, confidence, label in shown:
            node_id = "{0}:{1}".format(n_type, n_value)
            if node_id not in seen:
                seen.add(node_id)
                nodes.append(_node(n_type, n_value, label, expandable=True))
            edges.append({
                "source": center["id"],
                "target": node_id,
                "relation": relation,
                "confidence": confidence,
            })

        extra = len(entries) - len(shown)
        if extra > 0:
            cluster_id = "cluster:{0}:{1}:{2}".format(
                node_type, value, neighbor_type
            )
            nodes.append({
                "id": cluster_id,
                "type": neighbor_type,
                "value": cluster_id,
                "label": "+{0} more {1}".format(extra, neighbor_type),
                "cluster": True,
                "cluster_type": neighbor_type,
                "parent_type": node_type,
                "parent_value": value,
            })
            edges.append({
                "source": center["id"],
                "target": cluster_id,
                "relation": "cluster",
                "confidence": entries[0][3],
            })

    result = {"center": center["id"], "nodes": nodes, "edges": edges}
    _cache_put(cache_key, result)
    return result


def search_nodes(query, limit=20):
    """Indexed LIKE search across all entity sources -> seed candidates."""
    pattern = "%{0}%".format(query)
    conn = _connect()
    cursor = conn.cursor()
    results = []
    seen = set()

    def add(node_type, value, label=None):
        node_id = "{0}:{1}".format(node_type, value)
        if value and node_id not in seen:
            seen.add(node_id)
            results.append(_node(node_type, value, label))

    cursor.execute(
        "SELECT case_id, case_name FROM cases "
        "WHERE case_id LIKE ? OR case_name LIKE ? LIMIT ?",
        (pattern, pattern, limit)
    )
    for case_id, case_name in cursor.fetchall():
        add("Case", case_id, "{0} - {1}".format(case_id, case_name or ""))

    cursor.execute(
        "SELECT DISTINCT entity_type, entity_value FROM entities "
        "WHERE entity_value LIKE ? LIMIT ?", (pattern, limit)
    )
    for entity_type, entity_value in cursor.fetchall():
        add(_norm_type(entity_type), entity_value)

    cursor.execute(
        "SELECT DISTINCT ip_address FROM ipdr_records "
        "WHERE ip_address LIKE ? LIMIT ?", (pattern, limit)
    )
    for (ip_address,) in cursor.fetchall():
        add("IP", ip_address)

    cursor.execute(
        "SELECT DISTINCT phone_number FROM ipdr_records "
        "WHERE phone_number LIKE ? LIMIT ?", (pattern, limit)
    )
    for (phone,) in cursor.fetchall():
        add("Phone", phone)

    cursor.execute(
        "SELECT evidence_id FROM evidence_items "
        "WHERE evidence_id LIKE ? LIMIT ?", (pattern, limit)
    )
    for (evidence_id,) in cursor.fetchall():
        add("Evidence", evidence_id)

    conn.close()
    return results[:limit]


def clear_cache_for_case(case_id):
    keys_to_remove = [k for k in _CACHE if (k == case_id or (isinstance(k, tuple) and case_id in k))]
    for k in keys_to_remove:
        del _CACHE[k]
