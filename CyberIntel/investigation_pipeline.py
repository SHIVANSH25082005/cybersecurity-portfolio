"""
Automated Investigation Pipeline (Module 2)
============================================

Central orchestration layer that runs automatically whenever a complaint,
case, entity or IPDR record is created or updated.

Design goals:
- Reuse existing engines only (no duplicated analysis logic).
- A single ordered stage registry so future modules (Financial Intelligence,
  Evidence, Alerts, Similarity, ...) plug in via register_stage() WITHOUT
  editing pipeline logic.
- Prevent repeated execution: a cheap per-case data signature skips re-runs
  when nothing changed.
- Avoid duplicate queries: the expensive intelligence assessment is computed
  once per run and shared across stages through the run context.
- Never raises into the caller: a failing stage is recorded, not propagated,
  so case/complaint creation never breaks.
"""

import sqlite3
import hashlib
from datetime import datetime

DB_PATH = "database/cyberintel.db"


# ============================================================
# Stage registry (future modules register here)
# ============================================================

_STAGES = []


def register_stage(name, func, order=100):
    """Register a pipeline stage. func(ctx) -> dict (merged into results).

    Future modules call this at import time to plug in without touching
    pipeline logic. Lower `order` runs earlier.
    """
    _STAGES[:] = [s for s in _STAGES if s["name"] != name]
    _STAGES.append({"name": name, "func": func, "order": order})
    _STAGES.sort(key=lambda s: s["order"])
    return func


def registered_stages():
    return [s["name"] for s in _STAGES]


# ============================================================
# Cache (in-memory; no database change required)
# ============================================================

_CACHE = {}  # case_id -> {"signature", "result", "ran_at"}


def _connect():
    return sqlite3.connect(DB_PATH)


def compute_case_signature(case_id):
    """Cheap change-detector: counts + max(id) across the case's analytic
    tables. Detects inserts without loading any row data."""
    conn = _connect()
    cursor = conn.cursor()
    parts = []
    for table in ("complaints", "entities", "ipdr_records", "evidence_items"):
        cursor.execute(
            "SELECT COUNT(*), COALESCE(MAX(id), 0) "
            "FROM {0} WHERE case_id = ?".format(table),
            (case_id,)
        )
        count, max_id = cursor.fetchone()
        parts.append("{0}:{1}:{2}".format(table, count, max_id))
    conn.close()
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def get_cached_pipeline(case_id):
    return _CACHE.get(case_id)


# ============================================================
# Shared, memoized intelligence assessment (computed once per run)
# ============================================================

def _ensure_report(ctx):
    """Reuse the existing assessment engine exactly once per run."""
    if "report" not in ctx:
        from app import generate_intelligence_assessment
        ctx["report"] = generate_intelligence_assessment(ctx["case_id"])
    return ctx["report"]


# ============================================================
# Built-in stages (each reuses an existing engine)
# ============================================================

def stage_extract_entities(ctx):
    """Promote complaint indicators into the entities table (batched, deduped).
    Only inserts indicators not already present for the case."""
    case_id = ctx["case_id"]
    conn = _connect()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT phone_number, upi_id, email, telegram, website "
        "FROM complaints WHERE case_id = ?",
        (case_id,)
    )
    complaints = cursor.fetchall()

    cursor.execute(
        "SELECT entity_value FROM entities WHERE case_id = ?",
        (case_id,)
    )
    existing = {row[0] for row in cursor.fetchall()}

    type_map = ["Phone", "UPI", "Email", "Telegram", "Website"]
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    to_insert = []
    for complaint in complaints:
        for index, value in enumerate(complaint):
            if value and value not in existing:
                existing.add(value)
                to_insert.append(
                    (type_map[index], value, "Pipeline", now, case_id)
                )

    if to_insert:
        cursor.executemany(
            "INSERT INTO entities "
            "(entity_type, entity_value, source, date_added, case_id) "
            "VALUES (?, ?, ?, ?, ?)",
            to_insert
        )
        conn.commit()

    conn.close()
    return {"entities_added": len(to_insert)}


def stage_correlate_intelligence(ctx):
    report = _ensure_report(ctx)
    correlations = report.get("correlations", [])
    shared = [
        line for line in correlations
        if "No cross-case" not in line
    ]
    return {"correlations": len(shared)}


def stage_ip_analysis(ctx):
    """Scoped IP analysis: shared IPs for this case only (indexed, bounded)."""
    case_id = ctx["case_id"]
    conn = _connect()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT ip_address, COUNT(DISTINCT phone_number) AS fanout "
        "FROM ipdr_records "
        "WHERE case_id = ? AND ip_address IS NOT NULL AND ip_address != '' "
        "GROUP BY ip_address "
        "HAVING COUNT(DISTINCT phone_number) > 1 "
        "ORDER BY fanout DESC "
        "LIMIT 50",
        (case_id,)
    )
    shared_ips = cursor.fetchall()
    conn.close()
    ctx["shared_ips"] = [row[0] for row in shared_ips]
    return {"shared_ips": len(shared_ips)}


def stage_confidence_analysis(ctx):
    """Reuse the existing confidence engine (cached per run via context)."""
    from app import get_workspace_confidence
    confidence = get_workspace_confidence(ctx["case_id"])
    return {"confidence": confidence.get("overall", "Unknown")}


def stage_risk_score(ctx):
    report = _ensure_report(ctx)
    return {"risk_level": report.get("risk_level", "LOW")}


def stage_timeline(ctx):
    from timeline_reconstruction import get_case_timeline
    timeline = get_case_timeline(ctx["case_id"])
    return {"timeline_events": len(timeline)}


def stage_recommendations(ctx):
    report = _ensure_report(ctx)
    return {"recommendations": len(report.get("recommendations", []))}


def stage_financial_intelligence(ctx):
    from services.financial_service import analyze_case_financials
    financial = analyze_case_financials(ctx["case_id"])
    ctx["financial"] = financial
    return {
        "financial_indicators": financial.get("unique_instrument_count", 0),
        "financial_reuse": len(financial.get("reused", [])),
    }


def stage_alerts(ctx):
    from services.alert_service import alert_summary
    alerts = alert_summary(ctx["case_id"])
    ctx["alerts"] = alerts
    return {
        "alerts": alerts.get("total", 0),
        "high_alerts": alerts.get("counts", {}).get("HIGH", 0),
    }


def stage_similarity(ctx):
    from services.similarity_service import get_case_similarity
    similarity = get_case_similarity(ctx["case_id"], limit=5)
    ctx["similarity"] = similarity
    return {
        "similar_cases": len(similarity.get("results", [])),
        "top_similarity": similarity.get("top_score", 0),
    }


def stage_modus_operandi(ctx):
    from services.modus_operandi_service import detect_case_mo
    mo_data = detect_case_mo(ctx["case_id"])
    ctx["modus_operandi"] = mo_data
    return {
        "detected_mo": mo_data.get("detected_mo", "Generic/Unknown"),
        "mo_confidence": mo_data.get("confidence", 0),
    }


def stage_refresh_workspace(ctx):
    return {"workspace_refreshed_at": ctx["ran_at"]}


# Register built-in stages in pipeline order.
register_stage("extract_entities", stage_extract_entities, order=10)
register_stage("correlate_intelligence", stage_correlate_intelligence, order=20)
register_stage("ip_analysis", stage_ip_analysis, order=30)
register_stage("confidence_analysis", stage_confidence_analysis, order=40)
register_stage("risk_score", stage_risk_score, order=50)
register_stage("timeline", stage_timeline, order=60)
register_stage("recommendations", stage_recommendations, order=70)
register_stage("financial_intelligence", stage_financial_intelligence, order=75)
register_stage("alerts", stage_alerts, order=80)
register_stage("similarity", stage_similarity, order=85)
register_stage("modus_operandi", stage_modus_operandi, order=90)
register_stage("refresh_workspace", stage_refresh_workspace, order=99)


# ============================================================
# Orchestrator
# ============================================================

def run_pipeline(case_id, force=False):
    """Run all registered stages for a case.

    Skips execution when the case data signature is unchanged (prevents
    repeated execution). Never raises into the caller.
    """
    if not case_id:
        return {"status": "skipped", "reason": "no case_id"}

    try:
        signature = compute_case_signature(case_id)
    except Exception as error:
        return {"status": "error", "reason": str(error)}

    cached = _CACHE.get(case_id)
    if cached and cached["signature"] == signature and not force:
        return {
            "status": "cached",
            "case_id": case_id,
            "ran_at": cached["ran_at"],
            "results": cached["result"],
        }

    ctx = {
        "case_id": case_id,
        "ran_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    results = {}
    errors = {}

    for stage in _STAGES:
        try:
            output = stage["func"](ctx)
            if output:
                results.update(output)
        except Exception as error:
            errors[stage["name"]] = str(error)

    # Re-read signature: extract_entities may have inserted rows this run.
    try:
        signature = compute_case_signature(case_id)
    except Exception:
        pass

    _CACHE[case_id] = {
        "signature": signature,
        "result": results,
        "ran_at": ctx["ran_at"],
    }

    return {
        "status": "ran",
        "case_id": case_id,
        "ran_at": ctx["ran_at"],
        "stages": registered_stages(),
        "results": results,
        "errors": errors,
    }


def clear_cache_for_case(case_id):
    keys_to_remove = [k for k in _CACHE if (k == case_id or (isinstance(k, tuple) and case_id in k))]
    for k in keys_to_remove:
        del _CACHE[k]
