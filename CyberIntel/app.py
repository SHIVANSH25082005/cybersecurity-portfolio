from osint_enrichment import get_osint_data

from flask import send_file

from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    PageBreak,
    Image
)

from reportlab.lib import utils

from reportlab.lib.styles import getSampleStyleSheet

from time_analysis import calculate_time_proximity

from confidence_analysis import calculate_ip_confidence

from timeline_reconstruction import get_case_timeline, generate_investigation_summary

print("APP FILE LOADED")

from ip_relationships import find_ip_relationships

from relationship_discovery import discover_relationships
from network_summary import get_network_summary

from investigation_pipeline import run_pipeline, get_cached_pipeline, clear_cache_for_case as clear_pipeline_cache

from fusion_engine import (
    search_nodes,
    get_neighbors,
    FUSION_ENTITY_TYPES,
    clear_cache_for_case as clear_fusion_cache
)

from entity_profile import (
    get_entity_summary,
    get_sections,
    get_section_data
)
from services.search_service import global_search
from services.financial_service import analyze_case_financials
from services.alert_service import alert_summary
from services.recommendation_service import build_case_recommendations
from services.risk_service import priority_from_signals
from services.activity_service import get_recent_activity as service_recent_activity
from services.similarity_service import get_case_similarity, compare_cases, clear_cache_for_case as clear_similarity_cache
from services.modus_operandi_service import detect_case_mo, get_mo_stats, MO_PROFILES
from services.sop_service import get_all_sops, get_relevant_sops_for_case

def invalidate_analytical_caches(case_id):
    if not case_id:
        return
    try:
        clear_pipeline_cache(case_id)
    except Exception:
        pass
    try:
        clear_fusion_cache(case_id)
    except Exception:
        pass
    try:
        clear_similarity_cache(case_id)
    except Exception:
        pass

import matplotlib
matplotlib.use('Agg')

import matplotlib.pyplot as plt
import networkx as nx

from flask import Flask, render_template, request, redirect, jsonify, url_for
from services.evidence_service import log_custody_event, get_audit_trail, verify_file_integrity
from werkzeug.utils import secure_filename
import pandas as pd

import sqlite3
import hashlib
from datetime import datetime
import networkx as nx
import matplotlib.pyplot as plt
import os

def get_relationship_explanation(shared_ip, case_id=None, enable_cross_case=False):

    confidence_results = calculate_ip_confidence(
        shared_ip, case_id=case_id, enable_cross_case=enable_cross_case
    )

    if not confidence_results:

        return {
            "fanout": 0,
            "time_gap": "N/A",
            "confidence": "Unknown",
            "narrative": (
                f"No confidence analysis data "
                f"was available for IP "
                f"{shared_ip}."
            )
        }

    best_result = confidence_results[0]

    for result in confidence_results:

        if result["minutes"] < best_result["minutes"]:
            best_result = result

    fanout = best_result["fanout"]
    time_gap = best_result["minutes"]
    confidence = best_result["final_confidence"]
    reasoning = best_result.get("reasoning", "")
    dims = best_result.get("dimensions", {})
    contradictions = best_result.get("contradictions", [])

    narrative_parts = [
        f"The cases share IP address {shared_ip}.",
        f"Confidence Level: {confidence}. {reasoning}",
        f"Uniqueness: {dims.get('uniqueness', {}).get('category', 'N/A')} (Exclusive association: {dims.get('uniqueness', {}).get('score', 0.0)}).",
        f"Infrastructure Significance: {dims.get('infrastructure', {}).get('category', 'N/A')} ({dims.get('infrastructure', {}).get('explanation', '')}).",
        f"Temporal Proximity: {dims.get('temporal', {}).get('category', 'N/A')} ({dims.get('temporal', {}).get('explanation', '')}).",
        f"Persistence: {dims.get('persistence', {}).get('category', 'N/A')} ({dims.get('persistence', {}).get('explanation', '')}).",
        f"Cross-Source Corroboration: {dims.get('corroboration', {}).get('category', 'N/A')} ({dims.get('corroboration', {}).get('explanation', '')})."
    ]

    if enable_cross_case and dims.get('recurrence', {}).get('score', 0.0) > 0:
        narrative_parts.append(f"[Historical Intelligence] {dims.get('recurrence', {}).get('explanation', '')}")

    if contradictions:
        narrative_parts.append(f"[Logical Contradictions] Detected {len(contradictions)} inconsistency/inconsistencies: " + 
                               "; ".join(f"{c['description']} ({c['explanation']})" for c in contradictions))

    return {
        "fanout": fanout,
        "time_gap": time_gap,
        "confidence": confidence,
        "narrative": " ".join(narrative_parts),
        "dimensions": dims,
        "contradictions": contradictions
    }
def generate_graph(search_value, intelligence_results, complaint_results):

    G = nx.Graph()

    G.add_node(search_value)

    for record in intelligence_results:

        entity_type = record[1]
        entity_value = record[2]

        G.add_node(entity_value)
        G.add_edge(search_value, entity_value)

    for complaint in complaint_results:

        for item in complaint[1:6]:

            if item:

                G.add_node(item)
                G.add_edge(search_value, item)

    plt.figure(figsize=(8, 6))

    nx.draw(
        G,
        with_labels=True,
        node_size=3000,
        font_size=8
    )

    graph_path = os.path.join("static", "graph.png")

    plt.savefig(graph_path)
    plt.close()
app = Flask(__name__)

SEARCHABLE_MODULES = [
    "cases",
    "complaints",
    "entities",
    "ipdr_records",
    "evidence_items",
    "investigation_notes",
    "investigation_tasks"
]


def geocode_location(address_parts):
    import urllib.request
    import urllib.parse
    import json
    query = ", ".join([p for p in address_parts if p])
    if not query:
        return None, None
    try:
        url = "https://nominatim.openstreetmap.org/search?q=" + urllib.parse.quote(query) + "&format=json&limit=1"
        req = urllib.request.Request(
            url,
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AntigravityGeoIP/1.0'}
        )
        with urllib.request.urlopen(req, timeout=3) as response:
            data = json.loads(response.read().decode())
            if data:
                return float(data[0]['lat']), float(data[0]['lon'])
    except Exception as e:
        print("Geocoding failed for query:", query, e)
    return None, None


def upgrade_database_schema():
    conn = sqlite3.connect("database/cyberintel.db")
    cursor = conn.cursor()
    
    def add_col(table, col, col_type):
        cursor.execute(f"PRAGMA table_info({table})")
        cols = [c[1] for c in cursor.fetchall()]
        if col not in cols:
            cursor.execute(f"ALTER TABLE {table} ADD COLUMN {col} {col_type}")
            print(f"Added column {col} to {table}")

    for col in ["country", "state", "district", "city", "locality", "address"]:
        add_col("complaints", col, "TEXT")
    for col in ["latitude", "longitude"]:
        add_col("complaints", col, "REAL")

    for col in ["country", "state", "district", "city", "locality", "address"]:
        add_col("entities", col, "TEXT")
    for col in ["latitude", "longitude"]:
        add_col("entities", col, "REAL")

    for col in ["cell_tower_id", "tower_name", "country", "state", "district", "city"]:
        add_col("ipdr_records", col, "TEXT")
    for col in ["latitude", "longitude"]:
        add_col("ipdr_records", col, "REAL")
        
    conn.commit()
    conn.close()


def ensure_enterprise_tables():

    upgrade_database_schema()

    conn = sqlite3.connect("database/cyberintel.db")
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS evidence_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        evidence_id TEXT UNIQUE,
        case_id TEXT,
        file_name TEXT,
        file_type TEXT,
        description TEXT,
        uploaded_by TEXT,
        uploaded_at TEXT,
        sha256_hash TEXT,
        status TEXT DEFAULT 'Stored'
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS evidence_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        evidence_id TEXT,
        case_id TEXT,
        actor TEXT,
        action TEXT,
        event_time TEXT,
        notes TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS investigation_notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id TEXT,
        note TEXT,
        officer TEXT,
        created_at TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS investigation_tasks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id TEXT,
        task TEXT,
        status TEXT DEFAULT 'Open',
        owner TEXT,
        due_date TEXT,
        created_at TEXT
    )
    """)

    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_entities_case ON entities(case_id)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_entities_value ON entities(entity_value)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_complaints_case ON complaints(case_id)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_ipdr_case ON ipdr_records(case_id)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_ipdr_ip ON ipdr_records(ip_address)"
    )

    # Intelligence Fusion Engine indexes (Module 3)
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_ipdr_phone ON ipdr_records(phone_number)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_complaints_phone ON complaints(phone_number)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_complaints_upi ON complaints(upi_id)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_complaints_email ON complaints(email)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_complaints_telegram ON complaints(telegram)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_complaints_website ON complaints(website)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_cases_investigator ON cases(investigator)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_evidence_case ON evidence_items(case_id)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_evidence_id ON evidence_items(evidence_id)"
    )

    # Module 5: Chain of Custody — extend evidence_events with diff columns
    for col in ("prev_value", "new_value"):
        try:
            cursor.execute(
                f"ALTER TABLE evidence_events ADD COLUMN {col} TEXT"
            )
        except Exception:
            pass

    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_ev_events_eid "
        "ON evidence_events(evidence_id)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_ev_events_time "
        "ON evidence_events(event_time)"
    )

    conn.commit()
    conn.close()


ensure_enterprise_tables()


def get_case_workspace(case_id):

    report = generate_intelligence_assessment(case_id)
    financial = analyze_case_financials(case_id)
    alerts = alert_summary(case_id)
    similarity = get_case_similarity(case_id, limit=6)
    modus_operandi = detect_case_mo(case_id)
    relevant_sops = get_relevant_sops_for_case(
        case_id,
        case_type=report["case"][3] if report.get("case") else None,
        detected_mo=modus_operandi.get("detected_mo")
    )

    conn = sqlite3.connect("database/cyberintel.db")
    cursor = conn.cursor()

    cursor.execute("""
    SELECT
        e.entity_type,
        e.entity_value,
        COUNT(DISTINCT e2.case_id) AS linked_cases
    FROM entities e
    LEFT JOIN entities e2
        ON e.entity_value = e2.entity_value
        AND e2.case_id != e.case_id
    WHERE e.case_id = ?
    GROUP BY e.entity_type, e.entity_value
    ORDER BY linked_cases DESC, e.entity_type
    LIMIT 25
    """, (case_id,))
    entity_profiles = cursor.fetchall()

    cursor.execute("""
    SELECT
        ip_address,
        COUNT(*) AS observations,
        COUNT(DISTINCT phone_number) AS phones
    FROM ipdr_records
    WHERE case_id = ?
    GROUP BY ip_address
    ORDER BY observations DESC
    LIMIT 20
    """, (case_id,))
    infrastructure = cursor.fetchall()

    cursor.execute("""
    SELECT DISTINCT other.case_id, current.entity_type, current.entity_value
    FROM entities current
    JOIN entities other
        ON current.entity_value = other.entity_value
        AND current.case_id != other.case_id
    WHERE current.case_id = ?
    ORDER BY other.case_id
    LIMIT 30
    """, (case_id,))
    linked_cases = cursor.fetchall()

    cursor.execute("""
    SELECT id, evidence_id, case_id, file_name, file_type, description, uploaded_by, uploaded_at, sha256_hash, status
    FROM evidence_items
    WHERE case_id = ?
    ORDER BY id DESC
    LIMIT 20
    """, (case_id,))
    raw_ev = cursor.fetchall()

    from services.provenance_service import get_record_provenance
    evidence_items = []
    for row in raw_ev:
        prov = get_record_provenance("evidence_items", row[0])
        row_list = list(row)
        row_list.append(prov)
        evidence_items.append(row_list)

    cursor.execute("""
    SELECT *
    FROM investigation_notes
    WHERE case_id = ?
    ORDER BY id DESC
    LIMIT 10
    """, (case_id,))
    notes = cursor.fetchall()

    cursor.execute("""
    SELECT *
    FROM investigation_tasks
    WHERE case_id = ?
    ORDER BY
        CASE status WHEN 'Open' THEN 0 ELSE 1 END,
        id DESC
    LIMIT 20
    """, (case_id,))
    tasks = cursor.fetchall()

    conn.close()

    unique_ips = {
        record[2]
        for record in report["ipdr_records"]
        if record[2]
    }

    shared_upi = any(
        entity[0] == "UPI" and entity[2] > 0
        for entity in entity_profiles
    )

    shared_phone = any(
        entity[0] == "Phone" and entity[2] > 0
        for entity in entity_profiles
    )

    shared_ip = len(linked_cases) > 0

    priority = priority_from_signals(
        report["risk_level"],
        linked_case_count=len(linked_cases),
        unique_ip_count=len(unique_ips),
        rapid_switch_count=len(report["rapid_switching"]),
        complaint_count=report["complaint_count"],
        financial_reuse_count=len(financial.get("reused", [])),
        high_alert_count=alerts["counts"].get("HIGH", 0),
        similarity_top_score=similarity.get("top_score", 0),
    )
    priority_points = priority["points"]
    priority_level = priority["level"]

    priority_breakdown = {
        "linked_cases": {"count": len(linked_cases), "points": len(linked_cases) * 8},
        "unique_ips": {"count": len(unique_ips), "points": len(unique_ips) * 3},
        "rapid_switching": {"count": len(report["rapid_switching"]), "points": len(report["rapid_switching"]) * 20},
        "complaints": {"count": report["complaint_count"], "points": report["complaint_count"] * 10},
        "financial_reuse": {"count": len(financial.get("reused", [])), "points": len(financial.get("reused", [])) * 18},
        "high_alerts": {"count": alerts["counts"].get("HIGH", 0), "points": alerts["counts"].get("HIGH", 0) * 12},
        "similarity": {
            "score": similarity.get("top_score", 0),
            "points": 10 if similarity.get("top_score", 0) >= 70 else (5 if similarity.get("top_score", 0) >= 50 else 0)
        },
        "risk": {
            "level": report["risk_level"],
            "points": 30 if report["risk_level"] == "HIGH" else (15 if report["risk_level"] == "MEDIUM" else 0)
        }
    }

    recommendations = build_case_recommendations(
        report,
        {
            "shared_upi": shared_upi,
            "shared_phone": shared_phone,
            "shared_ip": shared_ip,
            "rapid_switching": bool(report["rapid_switching"]),
            "financial_reuse": bool(financial.get("reused")),
            "similar_cases": bool(similarity.get("results")),
            "missing_evidence": not evidence_items,
            "open_tasks": any(task[3] == "Open" for task in tasks),
        },
        limit=10,
        case_id=case_id
    )

    if similarity.get("results") and similarity["results"][0]["strength"] >= 70:
        recommendations.insert(
            0,
            "Review the strongest similar case first and compare shared indicators, chronology, and investigator notes."
        )

    graph_summary = {
        "visible_nodes": min(
            75,
            1 + len(entity_profiles) + len(linked_cases)
        ),
        "visible_edges": min(
            150,
            len(entity_profiles) + len(linked_cases)
        ),
        "hidden_nodes": max(
            0,
            report["entity_count"] + len(linked_cases) - 74
        ),
        "confidence_threshold": 70,
        "hop_depth": 1,
        "render_cap": 500
    }

    entity_type_counts = {}
    for entity_row in report["entities"]:
        entity_type_counts[entity_row[1]] = (
            entity_type_counts.get(entity_row[1], 0) + 1
        )

    unique_ip_count = len(unique_ips)

    return {
        "report": report,
        "entity_profiles": entity_profiles,
        "infrastructure": infrastructure,
        "linked_cases": linked_cases,
        "evidence_items": evidence_items,
        "notes": notes,
        "tasks": tasks,
        "priority_level": priority_level,
        "priority_points": priority_points,
        "shared_upi": shared_upi,
        "shared_phone": shared_phone,
        "shared_ip": shared_ip,
        "graph_summary": graph_summary,
        "entity_type_counts": entity_type_counts,
        "unique_ip_count": unique_ip_count,
        "recommendations": recommendations,
        "financial": financial,
        "alerts": alerts,
        "similarity": similarity,
        "modus_operandi": modus_operandi,
        "relevant_sops": relevant_sops,
        "priority_breakdown": priority_breakdown
    }


def get_db_connection():
    
    conn = sqlite3.connect("database/cyberintel.db")
    conn.row_factory = sqlite3.Row
    return conn

@app.route("/search")
def search():

    query = request.args.get("q", "").strip()

    results = {}

    if query:
        results = global_search(query)

    return render_template(
    "global_search.html",
        query=query,
        results=results
    )

@app.route("/")
def home():
    

    connection = sqlite3.connect("database/cyberintel.db")
    cursor = connection.cursor()

    cursor.execute("SELECT COUNT(*) FROM entities")
    total_records = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM entities WHERE entity_type='Phone'")
    phone_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM entities WHERE entity_type='UPI'")
    upi_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM entities WHERE entity_type='Website'")
    website_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM entities WHERE entity_type='Email'")
    email_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM entities WHERE entity_type='Telegram'")
    telegram_count = cursor.fetchone()[0]

    # Fetch recent active cases
    cursor.execute("""
        SELECT case_id, case_name, case_type, investigator, status, created_date
        FROM cases
        ORDER BY id DESC
        LIMIT 5
    """)
    recent_cases = cursor.fetchall()

    connection.close()

    return render_template(
        "index.html",
        total_records=total_records,
        phone_count=phone_count,
        upi_count=upi_count,
        website_count=website_count,
        email_count=email_count,
        telegram_count=telegram_count,
        recent_cases=recent_cases
    )

@app.route("/add_intelligence")
def add_intelligence_page():
    return render_template("add_intelligence.html")

@app.route("/add_profile", methods=["POST"])
def add_profile():

    case_id = request.form["case_id"]

    phone = request.form["phone"]
    upi = request.form["upi"]
    email = request.form["email"]
    telegram = request.form["telegram"]
    website = request.form["website"]

    country = request.form.get("country", "")
    state = request.form.get("state", "")
    district = request.form.get("district", "")
    city = request.form.get("city", "")
    locality = request.form.get("locality", "")
    address = request.form.get("address", "")
    
    latitude_str = request.form.get("latitude", "")
    longitude_str = request.form.get("longitude", "")
    
    latitude = None
    longitude = None
    if latitude_str:
        try: latitude = float(latitude_str)
        except: pass
    if longitude_str:
        try: longitude = float(longitude_str)
        except: pass
        
    has_location = any([country, state, district, city, locality, address, latitude is not None, longitude is not None])
    if has_location and (latitude is None or longitude is None):
        lat, lon = geocode_location([address, locality, city, district, state, country])
        if lat is not None and lon is not None:
            latitude = lat
            longitude = lon

    connection = sqlite3.connect("database/cyberintel.db")
    cursor = connection.cursor()

    current_time = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    if phone:

        cursor.execute("""
        INSERT INTO entities
        (
            entity_type,
            entity_value,
            date_added,
            case_id,
            country,
            state,
            district,
            city,
            locality,
            address,
            latitude,
            longitude
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "Phone",
            phone,
            current_time,
            case_id,
            country,
            state,
            district,
            city,
            locality,
            address,
            latitude,
            longitude
        ))

    if upi:

        cursor.execute("""
        INSERT INTO entities
        (
            entity_type,
            entity_value,
            date_added,
            case_id,
            country,
            state,
            district,
            city,
            locality,
            address,
            latitude,
            longitude
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "UPI",
            upi,
            current_time,
            case_id,
            country,
            state,
            district,
            city,
            locality,
            address,
            latitude,
            longitude
        ))

    if email:

        cursor.execute("""
        INSERT INTO entities
        (
            entity_type,
            entity_value,
            date_added,
            case_id,
            country,
            state,
            district,
            city,
            locality,
            address,
            latitude,
            longitude
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "Email",
            email,
            current_time,
            case_id,
            country,
            state,
            district,
            city,
            locality,
            address,
            latitude,
            longitude
        ))

    if telegram:

        cursor.execute("""
        INSERT INTO entities
        (
            entity_type,
            entity_value,
            date_added,
            case_id,
            country,
            state,
            district,
            city,
            locality,
            address,
            latitude,
            longitude
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "Telegram",
            telegram,
            current_time,
            case_id,
            country,
            state,
            district,
            city,
            locality,
            address,
            latitude,
            longitude
        ))

    if website:

        cursor.execute("""
        INSERT INTO entities
        (
            entity_type,
            entity_value,
            date_added,
            case_id,
            country,
            state,
            district,
            city,
            locality,
            address,
            latitude,
            longitude
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "Website",
            website,
            current_time,
            case_id,
            country,
            state,
            district,
            city,
            locality,
            address,
            latitude,
            longitude
        ))

    connection.commit()
    connection.close()

    run_pipeline(case_id)
    invalidate_analytical_caches(case_id)

    return redirect("/")

def add():
    entity_type = request.form["entity_type"]
    entity_value = request.form["entity_value"]

    connection = sqlite3.connect("database/cyberintel.db")
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO entities
(
    entity_type,
    entity_value,
    date_added,
    case_id
)
VALUES (?, ?, ?, ?)
    """,
    (
        entity_type,
        entity_value,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    connection.commit()
    connection.close()

    return home()

@app.route("/complaint", methods=["GET", "POST"])
def complaint():

    if request.method == "POST":

        complainant_name = request.form["complainant_name"]
        phone_number = request.form["phone_number"]
        upi_id = request.form["upi_id"]
        email = request.form["email"]
        telegram = request.form["telegram"]
        website = request.form["website"]
        complaint_details = request.form["complaint_details"]
        case_id = request.form["case_id"]

        country = request.form.get("country", "")
        state = request.form.get("state", "")
        district = request.form.get("district", "")
        city = request.form.get("city", "")
        locality = request.form.get("locality", "")
        address = request.form.get("address", "")
        
        latitude_str = request.form.get("latitude", "")
        longitude_str = request.form.get("longitude", "")
        
        latitude = None
        longitude = None
        if latitude_str:
            try: latitude = float(latitude_str)
            except: pass
        if longitude_str:
            try: longitude = float(longitude_str)
            except: pass
            
        if latitude is None or longitude is None:
            lat, lon = geocode_location([address, locality, city, district, state, country])
            if lat is not None and lon is not None:
                latitude = lat
                longitude = lon

        connection = sqlite3.connect("database/cyberintel.db")
        cursor = connection.cursor()

        cursor.execute("""
        INSERT INTO complaints
        (
            complainant_name,
            phone_number,
            upi_id,
            email,
            telegram,
            website,
            complaint_details,
            date_added,
            case_id,
            country,
            state,
            district,
            city,
            locality,
            address,
            latitude,
            longitude
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            complainant_name,
            phone_number,
            upi_id,
            email,
            telegram,
            website,
            complaint_details,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            case_id,
            country,
            state,
            district,
            city,
            locality,
            address,
            latitude,
            longitude
        ))

        connection.commit()

        matches = []
        risk_points = 0

        cursor.execute(
            "SELECT COUNT(*) FROM entities WHERE entity_value=?",
            (phone_number,)
        )
        if cursor.fetchone()[0] > 0:
            matches.append(
                "Phone Number found in Intelligence Database"
            )
            risk_points += 2.0

        cursor.execute(
            "SELECT COUNT(*) FROM entities WHERE entity_value=?",
            (upi_id,)
        )
        if cursor.fetchone()[0] > 0:
            matches.append(
                "UPI ID found in Intelligence Database"
            )
            risk_points += 2.0

        cursor.execute(
            "SELECT COUNT(*) FROM entities WHERE entity_value=?",
            (email,)
        )
        if cursor.fetchone()[0] > 0:
            matches.append(
                "Email found in Intelligence Database"
            )
            risk_points += 1.5

        cursor.execute(
            "SELECT COUNT(*) FROM entities WHERE entity_value=?",
            (telegram,)
        )
        if cursor.fetchone()[0] > 0:
            matches.append(
                "Telegram ID found in Intelligence Database"
            )
            risk_points += 1.5

        cursor.execute(
            "SELECT COUNT(*) FROM entities WHERE entity_value=?",
            (website,)
        )
        if cursor.fetchone()[0] > 0:
            matches.append(
                "Website found in Intelligence Database"
            )
            risk_points += 0.5

        connection.close()

        run_pipeline(case_id)
        invalidate_analytical_caches(case_id)

        if risk_points >= 4:
            risk_score = "HIGH"

        elif risk_points >= 1.5:
            risk_score = "MEDIUM"

        else:
            risk_score = "LOW"

        return render_template(
            "correlation_result.html",
            matches=matches,
            risk_score=risk_score
        )

    return render_template("complaints.html")


@app.route("/records")
def records():

    search_query = request.args.get("q", "").strip()

    connection = sqlite3.connect("database/cyberintel.db")
    cursor = connection.cursor()

    if search_query:
        like_query = f"%{search_query}%"
        # Search suspect coordinates
        cursor.execute("""
            SELECT id, entity_type, entity_value, date_added, case_id
            FROM entities
            WHERE entity_value LIKE ? OR entity_type LIKE ? OR case_id LIKE ? OR date_added LIKE ?
            ORDER BY id DESC
        """, (like_query, like_query, like_query, like_query))
        records = cursor.fetchall()

        # Search complaints
        cursor.execute("""
            SELECT id, complainant_name, phone_number, upi_id, email, telegram, website, complaint_details, date_added, case_id
            FROM complaints
            WHERE complainant_name LIKE ? OR phone_number LIKE ? OR upi_id LIKE ? OR email LIKE ? OR telegram LIKE ? OR website LIKE ? OR complaint_details LIKE ? OR case_id LIKE ?
            ORDER BY id DESC
        """, (like_query, like_query, like_query, like_query, like_query, like_query, like_query, like_query))
        complaints = cursor.fetchall()
    else:
        # Default load
        cursor.execute("""
            SELECT id, entity_type, entity_value, date_added, case_id
            FROM entities
            ORDER BY id DESC
        """)
        records = cursor.fetchall()

        cursor.execute("""
            SELECT id, complainant_name, phone_number, upi_id, email, telegram, website, complaint_details, date_added, case_id
            FROM complaints
            ORDER BY id DESC
        """)
        complaints = cursor.fetchall()

    connection.close()

    return render_template(
        "records.html",
        records=records,
        complaints=complaints,
        search_query=search_query
    )

def build_advanced_graph():

    import sqlite3
    import networkx as nx

    conn = sqlite3.connect("database/cyberintel.db")
    cursor = conn.cursor()

    G = nx.Graph()

    cursor.execute("SELECT * FROM complaints")
    complaints = cursor.fetchall()

    for complaint in complaints:

        complaint_id = f"Complaint_{complaint[0]}"

        phone = complaint[2]
        upi = complaint[3]
        email = complaint[4]
        telegram = complaint[5]
        website = complaint[6]

        G.add_node(complaint_id)

        if phone:
            G.add_node(phone)
            G.add_edge(complaint_id, phone)

        if upi:
            G.add_node(upi)
            G.add_edge(complaint_id, upi)

        if email:
            G.add_node(email)
            G.add_edge(complaint_id, email)

        if telegram:
            G.add_node(telegram)
            G.add_edge(complaint_id, telegram)

        if website:
            G.add_node(website)
            G.add_edge(complaint_id, website)

        cursor.execute("""
        SELECT DISTINCT ip_address
        FROM ipdr_records
        WHERE phone_number = ?
        """, (phone,))

        ip_records = cursor.fetchall()

        for ip in ip_records:

            ip_address = ip[0]

            if ip_address:
                G.add_node(ip_address)
                G.add_edge(phone, ip_address)

    conn.close()

    return G

def calculate_risk_level(records):

    complaint_count = len(records)

    if complaint_count >= 5:
        return "HIGH"

    elif complaint_count >= 2:
        return "MEDIUM"

    else:
        return "LOW"
    
def find_connections(search_value):
    
    
    
    graph = build_advanced_graph()

    if search_value not in graph:
        return []

    connected_nodes = nx.node_connected_component(
        graph,
        search_value
    )

    return list(connected_nodes)

def generate_link_graph(search_value):

    graph = build_advanced_graph()

    if search_value not in graph:
        return None

    connected_nodes = nx.node_connected_component(
        graph,
        search_value
    )

    subgraph = graph.subgraph(connected_nodes)

    node_colors = []

    for node in subgraph.nodes():

        node = str(node)

        if node.startswith("Complaint_"):
            node_colors.append("red")

        elif node.startswith("@"):
            node_colors.append("purple")

        elif ".com" in node:
            node_colors.append("gray")

        elif node.isdigit():
            node_colors.append("blue")

        elif "@" in node:
            node_colors.append("green")

        else:
            node_colors.append("orange")

    # ==========================
    # SPRING GRAPH
    # ==========================

    plt.figure(figsize=(20, 18))

    pos = nx.spring_layout(
        subgraph,
        k=2.0,
        iterations=100,
        seed=42
    )

    nx.draw(
        subgraph,
        pos,
        with_labels=True,
        node_color=node_colors,
        node_size=3500,
        font_size=15,
        font_weight="bold"
    )

    plt.savefig("static/link_graph.png")

    plt.close()

    # ==========================
    # CONCENTRIC GRAPH
    # ==========================

    plt.figure(figsize=(20, 18))

    shells = [[search_value]]

    remaining_nodes = [
        node
        for node in subgraph.nodes()
        if node != search_value
    ]

    shells.append(remaining_nodes)

    shell_pos = nx.shell_layout(
        subgraph,
        nlist=shells
    )

    nx.draw(
        subgraph,
        shell_pos,
        with_labels=True,
        node_color=node_colors,
        node_size=3500,
        font_size=15,
        font_weight="bold"
    )

    plt.savefig(
        "static/link_graph_concentric.png"
    )

    plt.close()

    return "link_graph.png"


def get_case_primary_indicator(case_id):

    conn = sqlite3.connect(
        "database/cyberintel.db"
    )
    cursor = conn.cursor()

    cursor.execute("""
    SELECT
        phone_number,
        upi_id,
        email,
        telegram,
        website
    FROM complaints
    WHERE case_id = ?
    LIMIT 1
    """, (case_id,))

    complaint = cursor.fetchone()

    conn.close()

    if not complaint:
        return None

    phone = complaint[0]
    upi = complaint[1]
    email = complaint[2]
    telegram = complaint[3]
    website = complaint[4]

    if phone:
        return phone

    if upi:
        return upi

    if email:
        return email

    if telegram:
        return telegram

    if website:
        return website

    return None


def generate_case_report_graphs(case_id):

    conn = sqlite3.connect(
        "database/cyberintel.db"
    )
    cursor = conn.cursor()

    G = nx.Graph()

    cursor.execute("""
    SELECT
        phone_number,
        upi_id,
        email,
        telegram,
        website
    FROM complaints
    WHERE case_id = ?
    """, (case_id,))

    complaints = cursor.fetchall()

    for complaint in complaints:

        phone = complaint[0]
        upi = complaint[1]
        email = complaint[2]
        telegram = complaint[3]
        website = complaint[4]

        complaint_node = case_id

        G.add_node(complaint_node)

        for value in [
            phone,
            upi,
            email,
            telegram,
            website
        ]:

            if value:

                G.add_node(value)
                G.add_edge(
                    complaint_node,
                    value
                )

    cursor.execute("""
    SELECT
        phone_number,
        ip_address
    FROM ipdr_records
    WHERE case_id = ?
    """, (case_id,))

    ip_records = cursor.fetchall()

    for phone, ip in ip_records:

        if phone and ip:

            G.add_node(phone)
            G.add_node(ip)

            G.add_edge(
                phone,
                ip
            )

    # Ingest entities registered to this case
    cursor.execute("""
    SELECT entity_value
    FROM entities
    WHERE case_id = ? AND entity_value IS NOT NULL AND entity_value != ''
    """, (case_id,))
    entity_records = cursor.fetchall()
    for entity in entity_records:
        val = entity[0]
        if val:
            G.add_node(val)

    # Link any disconnected indicator nodes directly to the case node
    if case_id in G:
        for node in list(G.nodes()):
            if node != case_id:
                try:
                    if not nx.has_path(G, case_id, node):
                        G.add_edge(case_id, node)
                except Exception:
                    G.add_edge(case_id, node)

    conn.close()

    if len(G.nodes()) == 0:
        return False

    node_colors = []

    for node in G.nodes():

        node = str(node)

        if node == case_id:
            node_colors.append("red")

        elif node.isdigit():
            node_colors.append("blue")

        elif "@" in node:
            node_colors.append("green")

        elif "." in node:
            node_colors.append("orange")

        else:
            node_colors.append("gray")

    # SPRING GRAPH

    plt.figure(figsize=(14, 10))

    pos = nx.spring_layout(
        G,
        seed=42
    )

    nx.draw(
        G,
        pos,
        with_labels=True,
        node_color=node_colors,
        node_size=3000,
        font_size=10
    )

    plt.savefig(
        "static/link_graph.png"
    )

    plt.close()

    # CONCENTRIC GRAPH

    plt.figure(figsize=(14, 10))

    shells = [[case_id]]

    outer_nodes = [
        node
        for node in G.nodes()
        if node != case_id
    ]

    shells.append(
        outer_nodes
    )

    pos = nx.shell_layout(
        G,
        nlist=shells
    )

    nx.draw(
        G,
        pos,
        with_labels=True,
        node_color=node_colors,
        node_size=3000,
        font_size=10
    )

    plt.savefig(
        "static/link_graph_concentric.png"
    )

    plt.close()

    return True

@app.route("/test_case_graphs/<case_id>")
def test_case_graphs(case_id):

    result = generate_case_report_graphs(
        case_id
    )

    return str(result)

    

@app.route("/link_analysis")
def link_analysis():
    return render_template("link_analysis.html")

@app.route("/link_analysis_result", methods=["POST"])
def link_analysis_result():

    search_value = request.form["search_value"]

    discovered_records = discover_relationships(search_value)

    print("DISCOVERED RECORDS: count =", len(discovered_records))

    summary = get_network_summary(discovered_records)

    risk_level = calculate_risk_level(discovered_records)

    graph_file = generate_link_graph(search_value)

    print("SEARCHED:", search_value)
    print("GRAPH FILE:", graph_file)

    return render_template(
        "link_analysis_result.html",
        search_value=search_value,
        connections=discovered_records,
        graph_file=graph_file,
        risk_level=risk_level,
        summary=summary
    )

@app.route("/ipdr_upload", methods=["GET", "POST"])
def ipdr_upload():

    if request.method == "POST":

        case_id = request.form["case_id"]

        uploaded_file = request.files["ipdr_file"]

        if uploaded_file:

            os.makedirs("uploads", exist_ok=True)

            file_path = os.path.join(
                "uploads",
                uploaded_file.filename
            )

            uploaded_file.save(file_path)

            file_ext = os.path.splitext(uploaded_file.filename)[1].lower()
            if file_ext not in ('.xlsx', '.xls', '.csv'):
                return "IPDR Data Ingestion Failed: Invalid file extension. Only .xlsx, .xls, and .csv files are allowed."

            try:
                if file_ext == '.csv':
                    df = pd.read_csv(file_path)
                else:
                    df = pd.read_excel(file_path)
            except Exception as e:
                return f"IPDR Data Ingestion Failed: The file is empty or corrupted. Error: {e}"

            if df.empty:
                return "IPDR Data Ingestion Failed: The uploaded spreadsheet contains no data."

            df.columns = (
                df.columns
                .str.strip()
                .str.lower()
            )

            required_cols = ['msisdn', 'source_ip', 'date', 'time', 'location']
            missing_cols = [col for col in required_cols if col not in df.columns]
            if missing_cols:
                return f"IPDR Data Ingestion Failed: Missing required columns: {', '.join(missing_cols)}"

            conn = sqlite3.connect(
                "database/cyberintel.db"
            )
            cursor = conn.cursor()

            def get_col_val(r, possible_names):
                for name in possible_names:
                    if name in r:
                        val = r[name]
                        if pd.notna(val) and val != "":
                            return val
                return None

            for index, row in df.iterrows():

                date_value = pd.to_datetime(
                    row["date"]
                ).strftime("%Y-%m-%d")

                time_value = str(
                    row["time"]
                )

                timestamp = (
                    f"{date_value} {time_value}"
                )

                cell_tower_id = get_col_val(row, ["cell tower id", "cell_tower_id", "tower_id", "tower id", "cellid", "cell_id"])
                tower_name = get_col_val(row, ["tower name", "tower_name", "cell name", "cell_name", "location_name", "location name"])
                country = get_col_val(row, ["country"])
                state = get_col_val(row, ["state"])
                district = get_col_val(row, ["district"])
                city = get_col_val(row, ["city"])
                
                latitude = get_col_val(row, ["latitude", "lat"])
                longitude = get_col_val(row, ["longitude", "lon", "lng", "long"])
                
                if cell_tower_id is not None: cell_tower_id = str(cell_tower_id).strip()
                if tower_name is not None: tower_name = str(tower_name).strip()
                if country is not None: country = str(country).strip()
                if state is not None: state = str(state).strip()
                if district is not None: district = str(district).strip()
                if city is not None: city = str(city).strip()
                
                if latitude is not None:
                    try: latitude = float(latitude)
                    except: latitude = None
                if longitude is not None:
                    try: longitude = float(longitude)
                    except: longitude = None

                cursor.execute("""
INSERT INTO ipdr_records
(phone_number, ip_address, timestamp, location, case_id, cell_tower_id, tower_name, country, state, district, city, latitude, longitude)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
""",
                (
                    str(row["msisdn"]),
                    str(row["source_ip"]),
                    timestamp,
                    str(row["location"]),
                    case_id,
                    cell_tower_id,
                    tower_name,
                    country,
                    state,
                    district,
                    city,
                    latitude,
                    longitude
                ))

            conn.commit()
            conn.close()

            run_pipeline(case_id)

            return "IPDR Data Imported Successfully"

    return render_template(
        "ipdr_upload.html"
    )

@app.route("/ipdr_records")
def ipdr_records():

    conn = sqlite3.connect("database/cyberintel.db")
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM ipdr_records")

    records = cursor.fetchall()

    conn.close()

    return render_template(
        "ipdr_records.html",
        records=records
    )

@app.route("/common_ip", methods=["GET", "POST"])
def common_ip():

    conn = sqlite3.connect("database/cyberintel.db")
    cursor = conn.cursor()

    cursor.execute("""
SELECT
    ip_address,
    GROUP_CONCAT(DISTINCT phone_number),
    COUNT(DISTINCT phone_number) AS fanout
FROM ipdr_records
GROUP BY ip_address
HAVING COUNT(DISTINCT phone_number) > 1
ORDER BY fanout DESC
""")

    results = cursor.fetchall()

    conn.close()

    return render_template(
        "common_ip.html",
        results=results
    )

@app.route("/confidence_analysis")
def confidence_analysis_page():

    conn = sqlite3.connect("database/cyberintel.db")
    cursor = conn.cursor()

    cursor.execute("""
    SELECT DISTINCT ip_address
    FROM ipdr_records
    GROUP BY ip_address
    HAVING COUNT(DISTINCT phone_number) > 1
    """)

    ips = cursor.fetchall()

    conn.close()

    results = []

    for ip in ips:

        ip_address = ip[0]

        confidence_data = calculate_ip_confidence(
            ip_address
        )

        results.extend(confidence_data)

    return render_template(
        "confidence_analysis.html",
        results=results
    )

@app.route(
    "/timeline_reconstruction",
    methods=["GET", "POST"]
)
def timeline_reconstruction_page():

    conn = sqlite3.connect("database/cyberintel.db")
    conn.row_factory = sqlite3.Row

    cases = conn.execute(
        """
        SELECT case_id, case_name
        FROM cases
        ORDER BY case_id
        """
    ).fetchall()

    conn.close()

    timeline = None
    selected_case = None
    summary = None
    summary_data = None

    if request.method == "POST":

        selected_case = request.form.get(
            "case_id"
        )

        timeline = get_case_timeline(
            selected_case
        )

        workspace = get_case_workspace(
            selected_case
        )

        summary_data = generate_investigation_summary(
            selected_case,
            workspace
        )

        unique_ips = set()
        unique_locations = set()
        transition_count = 0
        entity_count = 0

        for event in timeline:

            if event["event_type"] == "IPDR_ACTIVITY":

                details = event["details"]

                parts = details.split("|")

                for part in parts:

                    part = part.strip()

                    if part.startswith("IP:"):
                        unique_ips.add(
                            part.replace("IP:", "").strip()
                        )

                    if part.startswith("Location:"):
                        unique_locations.add(
                            part.replace(
                                "Location:",
                                ""
                            ).strip()
                        )

            elif (
                event["event_type"]
                == "INFRASTRUCTURE_TRANSITION"
            ):
                transition_count += 1

            elif event["event_type"] == "ENTITY":
                entity_count += 1

        summary = {
            "total_events": len(timeline),
            "unique_ips": len(unique_ips),
            "unique_locations": len(unique_locations),
            "transitions": transition_count,
            "entities": entity_count
        }

    return render_template(
        "timeline_reconstruction.html",
        cases=cases,
        timeline=timeline,
        selected_case=selected_case,
        summary=summary,
        summary_data=summary_data
    )

@app.route("/ip_relationships")
def ip_relationships():

    results = find_ip_relationships()

    return render_template(
        "ip_relationships.html",
        results=results
    )


@app.route("/add_case", methods=["GET", "POST"])
def add_case():

    if request.method == "POST":

        case_name = request.form["case_name"]
        case_type = request.form["case_type"]
        investigator = request.form["investigator"]
        status = request.form["status"]

        created_date = datetime.now().strftime("%Y-%m-%d")

        conn = sqlite3.connect("database/cyberintel.db")
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT case_id FROM cases")
            existing_ids = cursor.fetchall()
            max_num = 0
            for row in existing_ids:
                cid = row[0]
                if cid and cid.startswith("CASE"):
                    try:
                        num = int(cid[4:])
                        if num > max_num:
                            max_num = num
                    except ValueError:
                        pass
            count = max_num + 1
            generated_case_id = f"CASE{count:03d}"

            cursor.execute("""
INSERT INTO cases
(case_id, case_name, case_type, investigator, status, created_date)
VALUES (?, ?, ?, ?, ?, ?)
""", (
    generated_case_id,
    case_name,
    case_type,
    investigator,
    status,
    created_date
))

            conn.commit()
        finally:
            conn.close()

        run_pipeline(generated_case_id)
        invalidate_analytical_caches(generated_case_id)

        return redirect(url_for('investigation_workspace', case_id=generated_case_id))

    return render_template("add_case.html")




@app.route("/ipdr_case_correlation")
def ipdr_case_correlation():

    conn = sqlite3.connect("database/cyberintel.db")
    cursor = conn.cursor()

    cursor.execute("""
    SELECT
        ip_address,
        GROUP_CONCAT(DISTINCT case_id),
        COUNT(DISTINCT case_id)
    FROM ipdr_records
    GROUP BY ip_address
    HAVING COUNT(DISTINCT case_id) > 1
    ORDER BY COUNT(DISTINCT case_id) DESC
    """)

    results = cursor.fetchall()

    conn.close()

    return render_template(
        "ipdr_case_correlation.html",
        results=results
    )

@app.route("/case_correlation")
def case_correlation():

    conn = sqlite3.connect("database/cyberintel.db")
    cursor = conn.cursor()

    cursor.execute("""
    SELECT
        e1.case_id,
        e2.case_id,
        e1.entity_type,
        e1.entity_value
    FROM entities e1
    JOIN entities e2
        ON e1.entity_value = e2.entity_value
    WHERE e1.case_id < e2.case_id

    UNION

    SELECT
        c1.case_id,
        c2.case_id,
        'Phone',
        c1.phone_number
    FROM complaints c1
    JOIN complaints c2
        ON c1.phone_number = c2.phone_number
    WHERE c1.case_id < c2.case_id
    AND c1.phone_number IS NOT NULL
    AND c1.phone_number != ''

    UNION

    SELECT
        i1.case_id,
        i2.case_id,
        'IP Address',
        i1.ip_address
    FROM ipdr_records i1
    JOIN ipdr_records i2
        ON i1.ip_address = i2.ip_address
    WHERE i1.case_id < i2.case_id
    AND i1.ip_address IS NOT NULL
    AND i1.ip_address != ''
    """)

    raw_results = cursor.fetchall()

    correlations = {}

    for row in raw_results:

        case1 = row[0]
        case2 = row[1]
        entity_type = row[2]
        entity_value = row[3]

        key = (case1, case2)

        if key not in correlations:

            correlations[key] = {
                "case1": case1,
                "case2": case2,
                "indicators": [],
                "strength": 0,
                "explanation": [],
                "best_strength": 0,
                "shared_count": 0
            }

        correlations[key]["shared_count"] += 1

        correlations[key]["indicators"].append({
            "type": entity_type,
            "value": entity_value
        })

        if entity_type == "IP Address":

            explanation = get_relationship_explanation(
                entity_value
            )

            if explanation["confidence"] == "Strong":
                base_score = 90

            elif explanation["confidence"] == "Moderate":
                base_score = 60

            else:
                base_score = 30

            if base_score > correlations[key]["best_strength"]:

                correlations[key]["best_strength"] = base_score

                correlations[key]["explanation"] = [
                    explanation["narrative"]
                ]

    for correlation in correlations.values():

        if (
            not correlation["explanation"]
            and
            len(correlation["indicators"]) > 0
        ):

            first_indicator = correlation["indicators"][0]

            correlation["explanation"] = [
                f"Shared {first_indicator['type']}: {first_indicator['value']}"
            ]

        indicator_weights = {
            "IP Address": 40,
            "Phone": 25,
            "UPI": 20,
            "Email": 10,
            "Telegram": 10,
            "Website": 5
        }

        raw_score = 0

        for indicator in correlation["indicators"]:

            raw_score += indicator_weights.get(
                indicator["type"],
                5
            )

        ip_score = correlation["best_strength"]

        final_score = (
            raw_score * 0.4
        ) + (
            ip_score * 0.6
        )

        if final_score == 0:
            final_score = 10

        if final_score > 100:
            final_score = 100

        correlation["strength"] = round(
            final_score
        )

    results = sorted(
        correlations.values(),
        key=lambda x: x["strength"],
        reverse=True
    )

    conn.close()

    return render_template(
        "case_correlation.html",
        results=results
    )


@app.route("/case_similarity", methods=["GET", "POST"])
def case_similarity():
    case_id = ""
    other_case = ""
    similarity = None
    comparison = None

    if request.method == "POST":
        case_id = request.form.get("case_id", "").strip()
        other_case = request.form.get("other_case", "").strip()
    else:
        case_id = request.args.get("case_id", "").strip()
        other_case = request.args.get("other_case", "").strip()

    if case_id:
        similarity = get_case_similarity(case_id, limit=10)
        if other_case:
            comparison = compare_cases(case_id, other_case)

    return render_template(
        "case_similarity.html",
        case_id=case_id,
        other_case=other_case,
        similarity=similarity,
        comparison=comparison
    )


def generate_case_graph(results):

    G = nx.Graph()

    edge_labels = {}

    for case1, case2, indicator, indicator_type in results:

        G.add_node(case1)
        G.add_node(case2)

        G.add_edge(case1, case2)

        key = (case1, case2)

        if key not in edge_labels:
            edge_labels[key] = []

        edge_labels[key].append(
            f"{indicator_type}: {indicator}"
        )

    if len(G.nodes()) == 0:
        plt.figure(figsize=(16, 10))
        plt.text(0.5, 0.5, "No shared indicators found between these cases.",
                 ha="center", va="center", fontsize=12)
        plt.savefig("static/case_graph.png")
        plt.close()
        return

    plt.figure(figsize=(16, 10))

    pos = nx.spring_layout(
        G,
        seed=42,
        k=3
    )

    nx.draw(
        G,
        pos,
        with_labels=True,
        node_size=5000,
        font_size=10
    )

    formatted_labels = {}

    for edge, indicators in edge_labels.items():

        formatted_labels[edge] = (
            f"Shared Indicators ({len(indicators)})\n\n"
            + "\n".join(indicators)
        )

    nx.draw_networkx_edge_labels(
        G,
        pos,
        edge_labels=formatted_labels,
        font_size=10
    )

    plt.savefig("static/case_graph.png")

    plt.close()

@app.route("/case_correlation_graph", methods=["GET", "POST"])
def case_correlation_graph():

    selected_case1 = None
    selected_case2 = None

    if request.method == "POST":

        selected_case1 = request.form["case1"]
        selected_case2 = request.form["case2"]

        print("CASE 1:", selected_case1)
        print("CASE 2:", selected_case2)

    conn = sqlite3.connect("database/cyberintel.db")
    cursor = conn.cursor()

    cursor.execute("""
SELECT
    e1.case_id,
    e2.case_id,
    e1.entity_value,
    'Entity'
FROM entities e1
JOIN entities e2
    ON e1.entity_value = e2.entity_value
WHERE
(
    (e1.case_id = ? AND e2.case_id = ?)
    OR
    (e1.case_id = ? AND e2.case_id = ?)
)

UNION

SELECT
    c1.case_id,
    c2.case_id,
    c1.phone_number,
    'Phone'
FROM complaints c1
JOIN complaints c2
    ON c1.phone_number = c2.phone_number
WHERE
(
    (c1.case_id = ? AND c2.case_id = ?)
    OR
    (c1.case_id = ? AND c2.case_id = ?)
)
AND c1.phone_number IS NOT NULL
AND c1.phone_number != ''

UNION

SELECT
    i1.case_id,
    i2.case_id,
    i1.ip_address,
    'IP'
FROM ipdr_records i1
JOIN ipdr_records i2
    ON i1.ip_address = i2.ip_address
WHERE
(
    (i1.case_id = ? AND i2.case_id = ?)
    OR
    (i1.case_id = ? AND i2.case_id = ?)
)
AND i1.ip_address IS NOT NULL
AND i1.ip_address != ''
""",
(
    selected_case1, selected_case2,
    selected_case2, selected_case1,

    selected_case1, selected_case2,
    selected_case2, selected_case1,

    selected_case1, selected_case2,
    selected_case2, selected_case1
))

    results = cursor.fetchall()

    conn.close()

    generate_case_graph(results)

    return render_template(
        "case_correlation_graph.html",
        case1=selected_case1,
        case2=selected_case2
    )

@app.route("/debug_ipdr")
def debug_ipdr():

    conn = sqlite3.connect("database/cyberintel.db")
    cursor = conn.cursor()

    cursor.execute("""
SELECT phone_number, ip_address, timestamp, case_id
FROM ipdr_records
LIMIT 50
""")

    rows = cursor.fetchall()

    conn.close()

    return str(rows)

from services.cache_service import request_cached

@request_cached("intelligence_assessment")
def generate_intelligence_assessment(case_id):

    conn = sqlite3.connect("database/cyberintel.db")
    cursor = conn.cursor()

    # Case Information
    cursor.execute(
        "SELECT * FROM cases WHERE case_id=?",
        (case_id,)
    )
    case = cursor.fetchone()

    # Complaints
    cursor.execute(
        "SELECT * FROM complaints WHERE case_id=?",
        (case_id,)
    )
    complaints = cursor.fetchall()

    # Intelligence Entities
    cursor.execute(
        "SELECT * FROM entities WHERE case_id=?",
        (case_id,)
    )
    entities = cursor.fetchall()

    # IPDR Records
    cursor.execute(
        "SELECT * FROM ipdr_records WHERE case_id=?",
        (case_id,)
    )
    ipdr_records = cursor.fetchall()

    conn.close()

    report = {}

    report["rapid_switching"] = []

    report["case"] = case
    report["complaints"] = complaints
    report["entities"] = entities
    report["ipdr_records"] = ipdr_records

    report["complaint_count"] = len(complaints)
    report["entity_count"] = len(entities)
    report["ipdr_count"] = len(ipdr_records)
    financial = analyze_case_financials(case_id)
    alerts = alert_summary(case_id)
    similarity = get_case_similarity(case_id, limit=6)
    report["financial"] = financial
    report["alerts"] = alerts
    report["similarity"] = similarity

    findings = []

    findings.append(
        f"The case contains {len(entities)} intelligence indicators."
    )

    findings.append(
        f"The case contains {len(complaints)} linked complaint record(s)."
    )

    findings.append(
        f"The case contains {len(ipdr_records)} IPDR record(s)."
    )

    unique_ips = set()

    for record in ipdr_records:
        if record[2]:
            unique_ips.add(record[2])

    findings.append(
        f"{len(unique_ips)} unique IP address(es) were observed during analysis."
    )

    findings.append(
        financial["summary"]
    )

    if similarity.get("results"):
        top = similarity["results"][0]
        findings.append(
            f"Strongest similar case is {top['case2']['case_id']} with similarity score {top['strength']}."
        )

    if alerts["total"]:
        findings.append(
            f"{alerts['total']} active intelligence alert(s) were generated for this case."
        )

    # ==========================================
    # RAPID INFRASTRUCTURE SWITCHING DETECTION
    # ==========================================

    phone_activity = {}

    for record in ipdr_records:

        phone_number = record[1]
        ip_address = record[2]
        timestamp = record[3]

        try:

            dt = datetime.strptime(
                timestamp,
                "%Y-%m-%d %H:%M:%S"
            )

        except:

            continue

        if phone_number not in phone_activity:

            phone_activity[phone_number] = []

        phone_activity[phone_number].append(
            (dt, ip_address)
        )

    for phone_number, activities in phone_activity.items():

        activities.sort()

        unique_ip_window = set()

        start_time = activities[0][0]

        for activity in activities:

            current_time = activity[0]
            current_ip = activity[1]

            minutes = (
                current_time - start_time
            ).total_seconds() / 60

            if minutes <= 60:

                unique_ip_window.add(
                    current_ip
                )

            else:

                break

        if len(unique_ip_window) >= 3:

          report["rapid_switching"].append(
        {
            "phone": phone_number,
            "ip_count": len(unique_ip_window)
        }
    )

    entity_types = []

    for entity in entities:
        entity_types.append(entity[1])

    if entity_types:

        findings.append(
            "Available intelligence indicators include: "
            + ", ".join(entity_types) + "."
        )

    report["findings"] = findings

    conn = sqlite3.connect("database/cyberintel.db")
    cursor = conn.cursor()

    correlations = []
    seen_correlations = set()

    for record in ipdr_records:

        ip_address = record[2]
        if not ip_address:
            continue

        cursor.execute("""
        SELECT DISTINCT case_id
        FROM ipdr_records
        WHERE ip_address = ?
        AND case_id != ?
        """,
        (
            ip_address,
            case_id
        ))

        related_cases = cursor.fetchall()

        for related_case in related_cases:
            rel_case_id = related_case[0]
            corr_key = (ip_address, rel_case_id)
            if corr_key not in seen_correlations:
                seen_correlations.add(corr_key)
                correlations.append(
                    f"IP address {ip_address} is also associated with case {rel_case_id}."
                )

    conn.close()

    if not correlations:

        correlations.append(
            "No cross-case infrastructure sharing was identified."
        )

    report["correlations"] = correlations

    risk_score = 0

    risk_score += len(entities) * 5
    risk_score += len(ipdr_records) * 2
    risk_score += len(correlations) * 15

    if risk_score >= 60:

        risk_level = "HIGH"

    elif risk_score >= 30:

        risk_level = "MEDIUM"

    else:

        risk_level = "LOW"

    risk_reasons = []

    if len(entities) >= 5:

        risk_reasons.append(
            "Multiple intelligence indicators were identified."
        )

    if len(ipdr_records) >= 5:

        risk_reasons.append(
            "Multiple IPDR records are linked to the case."
        )

    if correlations and \
       "No cross-case infrastructure sharing was identified." \
       not in correlations:

        risk_reasons.append(
            "Cross-case infrastructure sharing was detected."
        )

    if len(complaints) >= 1:

        risk_reasons.append(
            "Complaint records are associated with the case."
        )

    if financial.get("reused"):
        risk_reasons.append(
            "Financial indicators are reused across other cases."
        )

    if alerts["counts"].get("HIGH", 0):
        risk_reasons.append(
            "High-severity intelligence alerts are active."
        )

    if similarity.get("results") and similarity["results"][0]["strength"] >= 70:
        risk_reasons.append(
            "A high-similarity case match was identified."
        )

    report["risk_level"] = risk_level
    report["risk_reasons"] = risk_reasons
    report["risk_score"] = risk_score
    report["entity_risk_points"] = len(entities) * 5
    report["ipdr_risk_points"] = len(ipdr_records) * 2
    report["correlation_risk_points"] = len(correlations) * 15

    unique_ips = set()

    for record in ipdr_records:

        if record[2]:
            unique_ips.add(record[2])

    executive_summary = (
        f"Case {case_id} involves "
        f"{len(entities)} intelligence indicator(s), "
        f"{len(complaints)} complaint record(s), and "
        f"{len(ipdr_records)} IPDR record(s). "
        f"Analysis identified {len(unique_ips)} unique IP address(es). "
        f"The case has been assessed as {risk_level} risk."
    )

    if correlations and \
       "No cross-case infrastructure sharing was identified." \
       not in correlations:

        executive_summary += (
            " Cross-case infrastructure sharing was detected "
            "during analysis."
        )

    if financial.get("available"):
        executive_summary += " " + financial["summary"]

    if similarity.get("results"):
        top = similarity["results"][0]
        executive_summary += (
            f" Strongest similar case: {top['case2']['case_id']} "
            f"({top['strength']} similarity)."
        )

    report["executive_summary"] = executive_summary

    recommendations = []

    if correlations and \
       "No cross-case infrastructure sharing was identified." \
       not in correlations:

        recommendations.append(
            "Prioritize investigation of shared infrastructure indicators identified across multiple cases."
        )

    if len(unique_ips) >= 3:

        recommendations.append(
            "Conduct deeper analysis of identified IP addresses to determine infrastructure reuse patterns."
        )

    if len(entities) >= 5:

        recommendations.append(
            "Expand intelligence collection around known communication identifiers including phone numbers, email accounts, UPI IDs, websites, and messaging platforms."
        )

    if len(ipdr_records) >= 5:

        recommendations.append(
            "Perform detailed IPDR timeline review to identify recurring network activity and infrastructure usage."
        )

    if len(complaints) >= 1:

        recommendations.append(
            "Cross-reference complaint details with other active investigations for additional investigative leads."
        )

    if financial.get("reused"):
        recommendations.append(
            "Obtain KYC and transaction logs for reused financial indicators and initiate freeze workflow where legally appropriate."
        )

    if alerts["counts"].get("HIGH", 0):
        recommendations.append(
            "Resolve high-severity alerts before closing the investigation."
        )

    if similarity.get("results"):
        recommendations.append(
            "Open the closest matching case and compare shared indicators, timeline, and evidence before closing leads."
        )

    recommendations.append(
        "Perform advanced graph-based relationship analysis to identify hidden connections between indicators."
    )

    report["recommendations"] = recommendations

    return report

@app.route("/intelligence_assessment", methods=["GET", "POST"])
def intelligence_assessment_form():

    if request.method == "POST":

        case_id = request.form["case_id"]

        return redirect(
            f"/assessment/{case_id}"
        )

    return render_template(
        "intelligence_assessment_form.html"
    )

@app.route("/assessment/<case_id>")
def intelligence_assessment(case_id):
    from services.hypothesis_service import generate_hypothesis
    from services.contradiction_service import detect_case_contradictions

    report = generate_intelligence_assessment(case_id)
    hypothesis = generate_hypothesis(case_id, report)
    contradictions = detect_case_contradictions(case_id)
    timeline = get_case_timeline(case_id)

    # CONSISTENCY PATCH: The executive_summary is built inside
    # generate_intelligence_assessment() before the hypothesis is known.
    # Append the authoritative investigative conclusion here so every
    # section of the report references the same result.
    report["executive_summary"] = (
        report["executive_summary"]
        + f" The primary investigative hypothesis is '{hypothesis['likely_scenario']}'"
        + f" with {hypothesis['confidence_level']} confidence."
    )

    return render_template(
        "intelligence_assessment.html",
        report=report,
        hypothesis=hypothesis,
        contradictions=contradictions,
        timeline=timeline,
        case_id=case_id
    )

@app.route("/show_tables")
def show_tables():

    conn = sqlite3.connect("database/cyberintel.db")
    cursor = conn.cursor()

    cursor.execute("""
    SELECT name
    FROM sqlite_master
    WHERE type='table'
    """)

    tables = cursor.fetchall()

    conn.close()

    return str(tables)

@app.route("/show_cases_schema")
def show_cases_schema():

    conn = sqlite3.connect("database/cyberintel.db")
    cursor = conn.cursor()

    cursor.execute("PRAGMA table_info(cases)")

    rows = cursor.fetchall()

    conn.close()

    return str(rows)

@app.route("/show_entities")
def show_entities():

    conn = sqlite3.connect("database/cyberintel.db")
    cursor = conn.cursor()

    cursor.execute("PRAGMA table_info(entities)")
    entities = cursor.fetchall()

    cursor.execute("PRAGMA table_info(complaints)")
    complaints = cursor.fetchall()

    cursor.execute("PRAGMA table_info(ipdr_records)")
    ipdr = cursor.fetchall()

    conn.close()

    return f"""
    ENTITIES:<br>{entities}<br><br>
    COMPLAINTS:<br>{complaints}<br><br>
    IPDR:<br>{ipdr}
    """

@app.route("/cases")
def view_cases():

    conn = sqlite3.connect("database/cyberintel.db")
    cursor = conn.cursor()

    cursor.execute("""
    SELECT *
    FROM cases
    ORDER BY id DESC
    """)

    cases = cursor.fetchall()

    conn.close()

    return render_template(
        "cases.html",
        cases=cases
    )


@app.route("/workspace/<case_id>")
def investigation_workspace(case_id):

    workspace = get_case_workspace(case_id)

    if not workspace["report"]["case"]:
        return "Case not found", 404

    from services.hypothesis_service import generate_hypothesis
    workspace["hypothesis"] = generate_hypothesis(case_id, workspace)

    from services.blindspot_service import detect_blind_spots
    workspace["blindspot"] = detect_blind_spots(case_id, workspace)

    return render_template(
        "investigation_workspace.html",
        workspace=workspace
    )


@app.route("/workspace/<case_id>/toggle_status", methods=["POST"])
def toggle_case_status(case_id):
    connection = sqlite3.connect("database/cyberintel.db")
    cursor = connection.cursor()
    cursor.execute("SELECT status FROM cases WHERE case_id = ?", (case_id,))
    row = cursor.fetchone()
    if row:
        current_status = row[0]
        new_status = "Open" if current_status == "Closed" else "Closed"
        cursor.execute("UPDATE cases SET status = ? WHERE case_id = ?", (new_status, case_id))
        connection.commit()
    connection.close()
    return redirect(f"/workspace/{case_id}")


@app.route("/workspace/<case_id>/note", methods=["POST"])
def add_investigation_note(case_id):

    note = request.form.get("note", "").strip()
    officer = request.form.get("officer", "Investigator").strip()

    if note:
        conn = sqlite3.connect("database/cyberintel.db")
        cursor = conn.cursor()
        try:
            cursor.execute("""
            INSERT INTO investigation_notes
            (case_id, note, officer, created_at)
            VALUES (?, ?, ?, ?)
            """, (
                case_id,
                note,
                officer or "Investigator",
                datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ))
            conn.commit()
        finally:
            conn.close()

    invalidate_analytical_caches(case_id)
    return redirect(f"/workspace/{case_id}")


@app.route("/workspace/<case_id>/task", methods=["POST"])
def add_investigation_task(case_id):

    task = request.form.get("task", "").strip()
    owner = request.form.get("owner", "").strip()
    due_date = request.form.get("due_date", "").strip()

    if task:
        conn = sqlite3.connect("database/cyberintel.db")
        cursor = conn.cursor()
        try:
            cursor.execute("""
            INSERT INTO investigation_tasks
            (case_id, task, owner, due_date, created_at)
            VALUES (?, ?, ?, ?, ?)
            """, (
                case_id,
                task,
                owner,
                due_date,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ))
            conn.commit()
        finally:
            conn.close()

    invalidate_analytical_caches(case_id)
    return redirect(f"/workspace/{case_id}")


@app.route("/workspace/<case_id>/task/<int:task_id>/toggle", methods=["POST"])
def toggle_investigation_task(case_id, task_id):

    conn = sqlite3.connect("database/cyberintel.db")
    cursor = conn.cursor()

    cursor.execute("""
    SELECT status
    FROM investigation_tasks
    WHERE id = ? AND case_id = ?
    """, (task_id, case_id))
    row = cursor.fetchone()

    if row:
        new_status = "Completed" if row[0] == "Open" else "Open"
        cursor.execute("""
        UPDATE investigation_tasks
        SET status = ?
        WHERE id = ? AND case_id = ?
        """, (new_status, task_id, case_id))
        conn.commit()

    conn.close()
    invalidate_analytical_caches(case_id)

    return redirect(f"/workspace/{case_id}")


@app.route("/workspace/<case_id>/evidence", methods=["POST"])
def upload_case_evidence(case_id):

    evidence_file = request.files.get("evidence_file")

    if not evidence_file or not evidence_file.filename:
        return redirect(f"/workspace/{case_id}")

    original_name = secure_filename(evidence_file.filename)
    uploaded_by = request.form.get("uploaded_by", "Investigator").strip()
    description = request.form.get("description", "").strip()
    file_bytes = evidence_file.read()
    sha256_hash = hashlib.sha256(file_bytes).hexdigest()

    conn = sqlite3.connect("database/cyberintel.db")
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT evidence_id FROM evidence_items WHERE case_id = ?",
            (case_id,)
        )
        existing_ids = cursor.fetchall()
        max_number = 0
        for (eid,) in existing_ids:
            try:
                num = int(eid.split("EV")[-1])
                max_number = max(max_number, num)
            except (ValueError, IndexError):
                continue
        evidence_number = max_number + 1
        evidence_id = f"{case_id}-EV{evidence_number:03d}"

        evidence_dir = os.path.join("uploads", "evidence", case_id)
        os.makedirs(evidence_dir, exist_ok=True)
        saved_name = f"{evidence_id}_{original_name}"
        saved_path = os.path.join(evidence_dir, saved_name)

        with open(saved_path, "wb") as saved_file:
            saved_file.write(file_bytes)

        uploaded_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        file_type = os.path.splitext(original_name)[1].lower().replace(".", "")

        cursor.execute("""
        INSERT INTO evidence_items
        (
            evidence_id,
            case_id,
            file_name,
            file_type,
            description,
            uploaded_by,
            uploaded_at,
            sha256_hash,
            status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            evidence_id,
            case_id,
            saved_name,
            file_type,
            description,
            uploaded_by or "Investigator",
            uploaded_at,
            sha256_hash,
            "Stored"
        ))

        cursor.execute("""
        INSERT INTO evidence_events
        (evidence_id, case_id, actor, action, event_time, notes)
        VALUES (?, ?, ?, ?, ?, ?)
        """, (
            evidence_id,
            case_id,
            uploaded_by or "Investigator",
            "Uploaded",
            uploaded_at,
            "SHA256 hash generated and evidence stored."
        ))

        conn.commit()
    finally:
        conn.close()
    invalidate_analytical_caches(case_id)

    return redirect(f"/workspace/{case_id}")


@app.route("/workspace/<case_id>/evidence/<evidence_id>/view")
def view_evidence(case_id, evidence_id):
    conn = sqlite3.connect("database/cyberintel.db")
    cursor = conn.cursor()
    cursor.execute(
        "SELECT file_name, case_id FROM evidence_items WHERE evidence_id = ?",
        (evidence_id,)
    )
    row = cursor.fetchone()
    conn.close()
    if not row:
        return "Evidence not found", 404
    file_name, ev_case_id = row
    actor = request.args.get("actor", "Investigator")
    log_custody_event(evidence_id, ev_case_id, actor, "Viewed",
                      f"File viewed: {file_name}")
    file_path = os.path.abspath(os.path.join("uploads", "evidence", ev_case_id, file_name))
    return send_file(file_path, as_attachment=False)


@app.route("/workspace/<case_id>/evidence/<evidence_id>/download")
def download_evidence(case_id, evidence_id):
    conn = sqlite3.connect("database/cyberintel.db")
    cursor = conn.cursor()
    cursor.execute(
        "SELECT file_name, case_id FROM evidence_items WHERE evidence_id = ?",
        (evidence_id,)
    )
    row = cursor.fetchone()
    conn.close()
    if not row:
        return "Evidence not found", 404
    file_name, ev_case_id = row
    actor = request.args.get("actor", "Investigator")
    log_custody_event(evidence_id, ev_case_id, actor, "Downloaded",
                      f"File downloaded: {file_name}")
    file_path = os.path.abspath(os.path.join("uploads", "evidence", ev_case_id, file_name))
    return send_file(file_path, as_attachment=True, download_name=file_name)


@app.route("/workspace/<case_id>/evidence/<evidence_id>/edit", methods=["POST"])
def edit_evidence_metadata(case_id, evidence_id):
    conn = sqlite3.connect("database/cyberintel.db")
    cursor = conn.cursor()
    cursor.execute(
        "SELECT case_id, description, status FROM evidence_items WHERE evidence_id = ?",
        (evidence_id,)
    )
    row = cursor.fetchone()
    if not row:
        conn.close()
        return redirect(f"/workspace/{case_id}")
    ev_case_id, prev_description, prev_status = row
    actor = request.form.get("actor", "Investigator").strip() or "Investigator"
    new_description = request.form.get("description", prev_description or "").strip()
    new_status = request.form.get("status", prev_status or "Stored").strip()
    cursor.execute(
        "UPDATE evidence_items SET description = ?, status = ? WHERE evidence_id = ?",
        (new_description, new_status, evidence_id)
    )
    conn.commit()
    conn.close()
    if new_description != (prev_description or ""):
        log_custody_event(evidence_id, ev_case_id, actor, "MetadataEdited",
                          "Description updated.",
                          prev_value=prev_description, new_value=new_description)
    if new_status != prev_status:
        log_custody_event(evidence_id, ev_case_id, actor, "StatusChanged",
                          "Status updated.",
                           prev_value=prev_status, new_value=new_status)
    invalidate_analytical_caches(case_id)
    return redirect(f"/workspace/{case_id}")


@app.route("/workspace/<case_id>/evidence/<evidence_id>/delete", methods=["POST"])
def delete_evidence(case_id, evidence_id):
    actor = request.form.get("actor", "Investigator").strip() or "Investigator"
    conn = sqlite3.connect("database/cyberintel.db")
    cursor = conn.cursor()
    cursor.execute(
        "SELECT case_id, file_name FROM evidence_items WHERE evidence_id = ?",
        (evidence_id,)
    )
    row = cursor.fetchone()
    if not row:
        conn.close()
        return redirect(f"/workspace/{case_id}")
    ev_case_id, file_name = row
    try:
        log_custody_event(evidence_id, ev_case_id, actor, "Deleted",
                          f"Evidence record deleted: {file_name}")
        cursor.execute("DELETE FROM evidence_items WHERE evidence_id = ?", (evidence_id,))
        conn.commit()
    finally:
        conn.close()
    file_path = os.path.join("uploads", "evidence", ev_case_id, file_name)
    if os.path.exists(file_path):
        os.remove(file_path)
    invalidate_analytical_caches(case_id)
    return redirect(f"/workspace/{case_id}")


@app.route("/workspace/<case_id>/evidence/<evidence_id>/verify")
def verify_evidence_integrity(case_id, evidence_id):
    result = verify_file_integrity(evidence_id)
    conn = sqlite3.connect("database/cyberintel.db")
    cursor = conn.cursor()
    cursor.execute(
        "SELECT case_id FROM evidence_items WHERE evidence_id = ?",
        (evidence_id,)
    )
    row = cursor.fetchone()
    conn.close()
    ev_case_id = row[0] if row else case_id
    actor = request.args.get("actor", "Investigator")
    action = "IntegrityVerified" if result["verified"] else "IntegrityFailed"
    log_custody_event(evidence_id, ev_case_id, actor, action, result["reason"])
    return jsonify(result)


@app.route("/workspace/<case_id>/evidence/<evidence_id>/audit")
def evidence_audit_trail(case_id, evidence_id):
    page = int(request.args.get("page", 1))
    return jsonify(get_audit_trail(evidence_id, page=page))


@app.route("/debug_entities")
def debug_entities():

    conn = sqlite3.connect("database/cyberintel.db")
    cursor = conn.cursor()

    cursor.execute("""
    SELECT
        entity_type,
        entity_value,
        COUNT(DISTINCT case_id) as cases
    FROM entities
    GROUP BY entity_type, entity_value
    ORDER BY cases DESC
    LIMIT 20
    """)

    results = cursor.fetchall()

    conn.close()

    return str(results)

@app.route("/debug/tables")
def debug_tables():

    conn = sqlite3.connect("database/cyberintel.db")
    conn.row_factory = sqlite3.Row

    tables = conn.execute(
        """
        SELECT name
        FROM sqlite_master
        WHERE type='table'
        ORDER BY name
        """
    ).fetchall()

    conn.close()

    return "<pre>" + str([dict(row) for row in tables]) + "</pre>"

@app.route("/debug/complaints-schema")
def debug_complaints_schema():

    conn = sqlite3.connect("database/cyberintel.db")
    conn.row_factory = sqlite3.Row

    columns = conn.execute(
        "PRAGMA table_info(complaints)"
    ).fetchall()

    conn.close()

    return "<pre>" + str([dict(col) for col in columns]) + "</pre>"

@app.route("/debug/timeline/<case_id>")
def debug_timeline(case_id):

    timeline = get_case_timeline(case_id)

    return "<pre>" + str(timeline) + "</pre>"

@app.route("/debug/cases")
def debug_cases():

    conn = sqlite3.connect("database/cyberintel.db")
    conn.row_factory = sqlite3.Row

    cases = conn.execute(
        """
        SELECT case_id, case_name
        FROM cases
        """
    ).fetchall()

    conn.close()

    return "<pre>" + str([dict(row) for row in cases]) + "</pre>"

@app.route("/debug/routes")
def debug_routes():

    routes = []

    for rule in app.url_map.iter_rules():
        routes.append(str(rule))

    return "<pre>" + "\n".join(sorted(routes)) + "</pre>"

@app.route("/debug/entities-schema")
def debug_entities_schema():

    conn = sqlite3.connect("database/cyberintel.db")
    conn.row_factory = sqlite3.Row

    columns = conn.execute(
        "PRAGMA table_info(entities)"
    ).fetchall()

    conn.close()

    return "<pre>" + str([dict(col) for col in columns]) + "</pre>"

@app.route("/debug/ipdr-schema")
def debug_ipdr_schema():

    conn = sqlite3.connect("database/cyberintel.db")
    conn.row_factory = sqlite3.Row

    columns = conn.execute(
        "PRAGMA table_info(ipdr_records)"
    ).fetchall()

    conn.close()

    return "<pre>" + str([dict(col) for col in columns]) + "</pre>"

@app.route("/debug/timeline/<case_id>/raw")
def debug_timeline_raw(case_id):

    timeline = get_case_timeline(case_id)

    return {
        "event_count": len(timeline),
        "timeline": timeline
    }



@app.route("/test_pdf")
def test_pdf():
    pdf_path = "static/test_report.pdf"
    doc = SimpleDocTemplate(pdf_path)
    styles = getSampleStyleSheet()
    elements = []

    elements.append(
        Paragraph(
            "Cybercrime Intelligence Investigation Report",
            styles["Title"]
        )
    )
    elements.append(Spacer(1, 20))
    elements.append(
        Paragraph(
            "PDF generation working successfully.",
            styles["BodyText"]
        )
    )

    doc.build(elements)
    return send_file(pdf_path, as_attachment=True)

from reportlab.platypus import Image
from reportlab.lib import utils


def get_image(path, width=500):

    img = utils.ImageReader(path)

    img_width, img_height = img.getSize()

    aspect = img_height / float(img_width)

    return Image(
        path,
        width=width,
        height=(width * aspect)
    )


@app.route("/download_report/<case_id>")
def download_report(case_id):
    from services.hypothesis_service import generate_hypothesis
    from services.provenance_service import get_record_provenance
    from services.contradiction_service import detect_case_contradictions
    from reportlab.platypus import Table, TableStyle
    from reportlab.lib import colors

    report = generate_intelligence_assessment(case_id)
    timeline = get_case_timeline(case_id)
    generate_case_report_graphs(case_id)

    hyp_res = generate_hypothesis(case_id, report)
    primary_hyp = hyp_res["primary_hypothesis"]
    ranked_hyps = hyp_res["ranked_hypotheses"]
    contradictions = detect_case_contradictions(case_id)

    # CONSISTENCY PATCH: The executive_summary is built inside
    # generate_intelligence_assessment() before the hypothesis is known.
    # Append the authoritative investigative conclusion here so every
    # section of the PDF report references the same result.
    executive_summary_full = (
        report["executive_summary"]
        + f" The primary investigative hypothesis is '{hyp_res['likely_scenario']}'"
        + f" with {hyp_res['confidence_level']} confidence."
    )

    pdf_path = f"static/{case_id}_investigation_report.pdf"
    doc = SimpleDocTemplate(pdf_path)
    styles = getSampleStyleSheet()
    elements = []

    # ==========================
    # PAGE 1: TITLE & EXECUTIVE SUMMARY
    # ==========================
    elements.append(Paragraph("Cybercrime Intelligence Investigation Report", styles["Title"]))
    elements.append(Spacer(1, 10))
    elements.append(Paragraph(f"Case ID: {case_id}", styles["Heading2"]))
    elements.append(Paragraph(f"Primary Threat Scenario: {hyp_res['likely_scenario']}", styles["BodyText"]))
    elements.append(Paragraph(f"Confidence Level: {hyp_res['confidence_level']}", styles["BodyText"]))
    elements.append(Spacer(1, 15))

    elements.append(Paragraph("Executive Summary", styles["Heading1"]))
    elements.append(Paragraph(executive_summary_full, styles["BodyText"]))
    elements.append(Spacer(1, 10))

    elements.append(Paragraph("Intelligence Assessment Summary", styles["Heading2"]))
    for finding in report["findings"]:
        elements.append(Paragraph("• " + finding, styles["BodyText"]))

    elements.append(PageBreak())

    # ==========================
    # PAGE 2: EVIDENCE SUMMARY (provenance & classifications)
    # ==========================
    elements.append(Paragraph("1. Evidence Summary", styles["Heading1"]))
    elements.append(Paragraph("List of physical and digital indicators registered in the case with their record-level provenance and quality classifications.", styles["BodyText"]))
    elements.append(Spacer(1, 15))

    evidence_table_data = [["Indicator Value", "Type", "Origin Module", "Classification"]]

    conn = sqlite3.connect("database/cyberintel.db")
    cursor = conn.cursor()
    
    # Get entities
    cursor.execute("SELECT id, entity_type, entity_value FROM entities WHERE case_id = ?", (case_id,))
    entities_list = cursor.fetchall()
    for row in entities_list:
        prov = get_record_provenance("entities", row[0])
        evidence_table_data.append([row[2], row[1], prov["origin_module"], prov["classification"]])

    # Get complaints indicators
    cursor.execute("SELECT id, phone_number, upi_id FROM complaints WHERE case_id = ?", (case_id,))
    complaints_list = cursor.fetchall()
    for row in complaints_list:
        if row[1]:
            prov = get_record_provenance("complaints", row[0])
            evidence_table_data.append([row[1], "Complainant Phone", prov["origin_module"], prov["classification"]])
        if row[2]:
            prov = get_record_provenance("complaints", row[0])
            evidence_table_data.append([row[2], "Complainant UPI", prov["origin_module"], prov["classification"]])

    conn.close()

    if len(evidence_table_data) > 1:
        t = Table(evidence_table_data, colWidths=[120, 100, 150, 130])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
        ]))
        elements.append(t)
    else:
        elements.append(Paragraph("No physical indicators registered in database.", styles["BodyText"]))

    elements.append(PageBreak())

    # ==========================
    # PAGE 3: ANALYTICAL ASSESSMENT
    # ==========================
    elements.append(Paragraph("2. Analytical Assessment", styles["Heading1"]))
    elements.append(Spacer(1, 10))
    elements.append(Paragraph("Relationship Graph (Spring Layout)", styles["Heading2"]))
    elements.append(get_image("static/link_graph.png", width=400))
    elements.append(Spacer(1, 15))
    elements.append(Paragraph("Relationship Graph (Concentric Layout)", styles["Heading2"]))
    elements.append(get_image("static/link_graph_concentric.png", width=400))

    elements.append(PageBreak())

    # ==========================
    # PAGE 4: SUPPORTING EVIDENCE
    # ==========================
    elements.append(Paragraph("3. Supporting Evidence & Confidence Details", styles["Heading1"]))
    elements.append(Spacer(1, 10))

    conf_assessments = get_workspace_confidence(case_id)["assessments"]
    for a in conf_assessments:
        elements.append(Paragraph(f"<b>IP Address:</b> {a['ip']} (Confidence: {a['confidence']})", styles["Heading3"]))
        elements.append(Paragraph(f"<b>Assessment:</b> {a['narrative']}", styles["BodyText"]))
        
        if a.get("dimensions"):
            elements.append(Spacer(1, 5))
            elements.append(Paragraph("<b>8-Dimension Breakdown:</b>", styles["BodyText"]))
            for dim_name, d_val in a["dimensions"].items():
                elements.append(Paragraph(f"• {dim_name.capitalize()}: {d_val['category']} (Score: {d_val['score']})", styles["BodyText"]))
        elements.append(Spacer(1, 15))

    elements.append(PageBreak())

    # ==========================
    # PAGE 5: CONTRADICTING EVIDENCE & ALTERNATIVE HYPOTHESES
    # ==========================
    elements.append(Paragraph("4. Contradicting Evidence & Conflicts", styles["Heading1"]))
    elements.append(Spacer(1, 10))

    if contradictions:
        elements.append(Paragraph("The contradiction engine flagged the following logical inconsistencies:", styles["BodyText"]))
        elements.append(Spacer(1, 5))
        for c in contradictions:
            elements.append(Paragraph(f"• <b>[{c['severity']} Severity] {c['type']}</b>: {c['description']}", styles["BodyText"]))
            elements.append(Paragraph(f"  <i>Possible Explanation:</i> {c['explanation']}", styles["BodyText"]))
            elements.append(Spacer(1, 8))
    else:
        elements.append(Paragraph("No logical contradictions or chronology conflicts were detected in the case evidence.", styles["BodyText"]))

    elements.append(Spacer(1, 20))
    elements.append(Paragraph("5. Alternative Explanations Considered", styles["Heading1"]))
    elements.append(Spacer(1, 10))

    for hyp in ranked_hyps:
        elements.append(Paragraph(f"<b>Hypothesis Model: {hyp['name']}</b> (Score: {hyp['score']}, Strength: {hyp['strength']})", styles["Heading3"]))
        elements.append(Paragraph(f"Supporting: {', '.join(hyp['supporting_evidence']) if hyp['supporting_evidence'] else 'None'}", styles["BodyText"]))
        elements.append(Paragraph(f"Contradicting: {', '.join(hyp['contradicting_evidence']) if hyp['contradicting_evidence'] else 'None'}", styles["BodyText"]))
        elements.append(Paragraph(f"Gaps/Missing: {', '.join(hyp['missing_evidence']) if hyp['missing_evidence'] else 'None'}", styles["BodyText"]))
        elements.append(Spacer(1, 10))

    elements.append(PageBreak())

    # ==========================
    # PAGE 6: REASON LOWER & FINAL ASSESSMENT
    # ==========================
    elements.append(Paragraph("6. Reason Alternatives Were Ranked Lower", styles["Heading1"]))
    elements.append(Spacer(1, 10))

    for hyp in ranked_hyps:
        if hyp["name"] != hyp_res["likely_scenario"]:
            elements.append(Paragraph(f"• <b>{hyp['name']}:</b> {hyp['reason_ranked_above_alternatives']}", styles["BodyText"]))

    elements.append(Spacer(1, 20))
    elements.append(Paragraph("7. Final Investigative Assessment", styles["Heading1"]))
    elements.append(Spacer(1, 10))

    elements.append(Paragraph(f"Based on the logical confidence gates and sufficiency analysis, the case is officially categorized as:", styles["BodyText"]))
    elements.append(Spacer(1, 5))
    elements.append(Paragraph(f"<b>Primary Threat Scenario:</b> {hyp_res['likely_scenario']}", styles["Heading2"]))
    elements.append(Paragraph(f"<b>Confidence Level:</b> {hyp_res['confidence_level']}", styles["Heading3"]))
    elements.append(Spacer(1, 10))
    elements.append(Paragraph(f"<b>Investigative Summary:</b> {hyp_res['overall_assessment']}", styles["BodyText"]))

    elements.append(Spacer(1, 15))
    elements.append(Paragraph("Case Correlation Findings (Historical Cross-Case Linkages)", styles["Heading3"]))
    for finding in report["correlations"]:
        elements.append(Paragraph("• " + finding, styles["BodyText"]))

    elements.append(Spacer(1, 15))
    elements.append(Paragraph("Investigator Action Recommendations", styles["Heading3"]))
    for action in hyp_res["next_actions"]:
        elements.append(Paragraph("• " + action, styles["BodyText"]))

    doc.build(elements)
    return send_file(pdf_path, as_attachment=True)


# ============================================================
# UNIFIED INVESTIGATION WORKSPACE - ASYNC DATA ENDPOINTS
# Heavy / expensive sections are loaded on demand so the
# initial dashboard stays lightweight for large datasets.
# Each helper reuses existing calculations; no logic is
# duplicated and no existing route is modified.
# ============================================================


def get_workspace_timeline_preview(case_id, limit=15):

    timeline = get_case_timeline(case_id)

    total = len(timeline)

    preview = list(reversed(timeline[-limit:]))

    return {
        "total": total,
        "shown": len(preview),
        "events": preview
    }


def get_workspace_confidence(case_id, ip_limit=8):

    enable_cross_case = False
    try:
        from flask import request
        enable_cross_case = request.args.get("cross_case") == "1"
    except Exception:
        pass

    conn = sqlite3.connect("database/cyberintel.db")
    cursor = conn.cursor()

    cursor.execute("""
        SELECT DISTINCT ip_address
        FROM ipdr_records
        WHERE case_id = ?
        AND ip_address IS NOT NULL
        AND ip_address != ''
    """, (case_id,))

    case_ips = [row[0] for row in cursor.fetchall()]

    conn.close()

    rank = {"Strong": 4, "Moderate": 3, "Limited": 2, "Insufficient Evidence": 1, "Unknown": 0}

    assessments = []

    for ip_address in case_ips[:ip_limit]:

        explanation = get_relationship_explanation(ip_address, case_id=case_id, enable_cross_case=enable_cross_case)

        assessments.append({
            "ip": ip_address,
            "confidence": explanation["confidence"],
            "fanout": explanation["fanout"],
            "time_gap": explanation["time_gap"],
            "narrative": explanation["narrative"],
            "dimensions": explanation.get("dimensions", {}),
            "contradictions": explanation.get("contradictions", [])
        })

    assessments.sort(
        key=lambda item: rank.get(item["confidence"], 0),
        reverse=True
    )

    overall = assessments[0]["confidence"] if assessments else "Insufficient Evidence"

    return {
        "overall": overall,
        "assessed": len(assessments),
        "total_ips": len(case_ips),
        "assessments": assessments
    }


def get_workspace_graph_preview(case_id, node_cap=40):

    conn = sqlite3.connect("database/cyberintel.db")
    cursor = conn.cursor()

    nodes = [{"id": case_id, "label": case_id, "group": "case"}]
    edges = []
    seen = {case_id}

    cursor.execute("""
        SELECT entity_type, entity_value
        FROM entities
        WHERE case_id = ?
        AND entity_value IS NOT NULL
        AND entity_value != ''
        LIMIT ?
    """, (case_id, node_cap))

    for entity_type, entity_value in cursor.fetchall():

        if entity_value in seen or len(nodes) >= node_cap:
            continue

        seen.add(entity_value)
        nodes.append({
            "id": entity_value,
            "label": entity_value,
            "group": entity_type or "Entity"
        })
        edges.append({"source": case_id, "target": entity_value})

    cursor.execute("""
        SELECT DISTINCT other.case_id
        FROM entities current
        JOIN entities other
            ON current.entity_value = other.entity_value
            AND current.case_id != other.case_id
        WHERE current.case_id = ?
        LIMIT 15
    """, (case_id,))

    for (other_case,) in cursor.fetchall():

        if other_case in seen or len(nodes) >= node_cap:
            continue

        seen.add(other_case)
        nodes.append({
            "id": other_case,
            "label": other_case,
            "group": "Linked Case"
        })
        edges.append({"source": case_id, "target": other_case})

    cursor.execute(
        "SELECT COUNT(*) FROM entities WHERE case_id = ?",
        (case_id,)
    )
    total_entities = cursor.fetchone()[0]

    conn.close()

    return {
        "nodes": nodes,
        "edges": edges,
        "node_cap": node_cap,
        "hidden": max(0, total_entities - (len(nodes) - 1))
    }


def get_recent_activity(case_id, limit=20):

    conn = sqlite3.connect("database/cyberintel.db")
    cursor = conn.cursor()

    cursor.execute("""
        SELECT ts, kind, label, actor FROM (
            SELECT created_at AS ts, 'Note' AS kind,
                   note AS label, officer AS actor
            FROM investigation_notes WHERE case_id = ?
            UNION ALL
            SELECT created_at, 'Task', task, owner
            FROM investigation_tasks WHERE case_id = ?
            UNION ALL
            SELECT event_time, 'Evidence',
                   action || ' - ' || evidence_id, actor
            FROM evidence_events WHERE case_id = ?
            UNION ALL
            SELECT date_added, 'Entity',
                   entity_type || ': ' || entity_value, source
            FROM entities WHERE case_id = ?
            UNION ALL
            SELECT date_added, 'Complaint',
                   'Complaint by ' || complainant_name, complainant_name
            FROM complaints WHERE case_id = ?
        )
        ORDER BY ts DESC
        LIMIT ?
    """, (case_id, case_id, case_id, case_id, case_id, limit))

    rows = cursor.fetchall()

    conn.close()

    activity = []

    for ts, kind, label, actor in rows:
        activity.append({
            "time": ts,
            "kind": kind,
            "label": label,
            "actor": actor or "—"
        })

    return {"activity": activity}


@app.route("/workspace/<case_id>/api/timeline_preview")
def workspace_timeline_preview(case_id):
    return jsonify(get_workspace_timeline_preview(case_id))


@app.route("/workspace/<case_id>/api/confidence")
def workspace_confidence(case_id):
    return jsonify(get_workspace_confidence(case_id))


@app.route("/workspace/<case_id>/api/graph_preview")
def workspace_graph_preview(case_id):
    return jsonify(get_workspace_graph_preview(case_id))


@app.route("/workspace/<case_id>/api/activity")
def workspace_activity(case_id):
    return jsonify(get_recent_activity(case_id))


@app.route("/workspace/<case_id>/api/pipeline")
def workspace_pipeline_status(case_id):
    cached = get_cached_pipeline(case_id)
    if not cached:
        return jsonify({"status": "not_run"})
    return jsonify({
        "status": "ready",
        "ran_at": cached["ran_at"],
        "results": cached["result"]
    })


@app.route("/workspace/<case_id>/api/pipeline/run", methods=["POST"])
def workspace_pipeline_run(case_id):
    return jsonify(run_pipeline(case_id, force=True))


# ============================================================
# INTELLIGENCE FUSION ENGINE (Module 3)
# ============================================================

@app.route("/fusion")
def fusion_graph_page():
    return render_template(
        "fusion_graph.html",
        entity_types=FUSION_ENTITY_TYPES
    )


@app.route("/fusion/api/search")
def fusion_search():
    query = request.args.get("q", "").strip()
    if not query:
        return jsonify([])
    return jsonify(search_nodes(query))


@app.route("/fusion/api/neighbors")
def fusion_neighbors():
    node_type = request.args.get("type", "")
    value = request.args.get("value", "")
    limit = request.args.get("limit", 40, type=int)
    confidence_min = request.args.get("confidence_min", 0, type=int)
    types_param = request.args.get("types", "").strip()
    types = [t for t in types_param.split(",") if t] or None
    return jsonify(
        get_neighbors(
            node_type,
            value,
            limit=limit,
            confidence_min=confidence_min,
            types=types
        )
    )


# ============================================================
# ENTITY INTELLIGENCE PROFILES (Module 4)
# ============================================================

@app.route("/entity")
def entity_profile_page():
    entity_type = request.args.get("type", "").strip()
    value = request.args.get("value", "").strip()
    if not entity_type or not value:
        return redirect("/records")
    summary = get_entity_summary(entity_type, value)
    return render_template(
        "entity_profile.html",
        summary=summary,
        sections=get_sections()
    )


@app.route("/entity/api/summary")
def entity_summary_api():
    entity_type = request.args.get("type", "").strip()
    value = request.args.get("value", "").strip()
    if not entity_type or not value:
        return jsonify({})
    return jsonify(get_entity_summary(entity_type, value))


@app.route("/entity/api/section/<slug>")
def entity_section_api(slug):
    entity_type = request.args.get("type", "").strip()
    value = request.args.get("value", "").strip()
    page = request.args.get("page", 1, type=int)
    if not entity_type or not value:
        return jsonify({"message": "Missing entity."})
    return jsonify(get_section_data(slug, entity_type, value, page))


@app.route("/modus_operandi", methods=["GET", "POST"])
def modus_operandi():
    case_id = ""
    if request.method == "POST":
        case_id = request.form.get("case_id", "").strip()
    else:
        case_id = request.args.get("case_id", "").strip()

    mo_data = None
    if case_id:
        mo_data = detect_case_mo(case_id)

    stats = get_mo_stats()

    return render_template(
        "modus_operandi.html",
        case_id=case_id,
        mo_data=mo_data,
        stats=stats
    )


@app.route("/sop")
def sop_kb():
    query = request.args.get("q", "").strip()
    category = request.args.get("category", "").strip()

    sops = get_all_sops(query=query, category=category)

    return render_template(
        "sop_knowledge_base.html",
        sops=sops,
        query=query,
        current_category=category
    )


def get_geo_data(filters):
    conn = sqlite3.connect("database/cyberintel.db")
    cursor = conn.cursor()
    
    # 1. Fetch complaints
    cursor.execute("""
        SELECT id, complainant_name, phone_number, upi_id, email, telegram, website, 
               complaint_details, date_added, case_id, country, state, district, city, 
               locality, address, latitude, longitude 
        FROM complaints
    """)
    raw_complaints = cursor.fetchall()
    
    # 2. Fetch entities
    cursor.execute("""
        SELECT id, entity_type, entity_value, date_added, case_id, country, state, 
               district, city, locality, address, latitude, longitude 
        FROM entities
    """)
    raw_entities = cursor.fetchall()
    
    # 3. Fetch IPDR records
    cursor.execute("""
        SELECT id, phone_number, ip_address, timestamp, location, case_id, cell_tower_id, 
               tower_name, country, state, district, city, latitude, longitude 
        FROM ipdr_records
    """)
    raw_ipdr = cursor.fetchall()
    
    # Fetch cases details for case filters (status, MO, risk)
    cursor.execute("SELECT case_id, case_type, status FROM cases")
    cases_dict = {row[0]: {"type": row[1], "status": row[2]} for row in cursor.fetchall()}
    conn.close()
    
    # Pre-compute case MOs and risk levels using the imported services
    case_mos = {}
    case_risks = {}
    for cid in cases_dict.keys():
        mo_res = detect_case_mo(cid)
        case_mos[cid] = mo_res.get("detected_mo", "Generic/Unknown")
        
        # Risk level based on authoritative assessment implementation
        report = generate_intelligence_assessment(cid)
        case_risks[cid] = report["risk_level"]
    
    markers = []
    stats = {
        "total_complaints": 0,
        "total_intelligence": 0,
        "total_ipdr": 0,
        "missing_coords": 0,
        "countries": set(),
        "states": set(),
        "cities": set()
    }
    
    # Process complaints
    for row in raw_complaints:
        cid = row[9]
        c_case = cases_dict.get(cid, {"type": "", "status": "Unknown"})
        c_mo = case_mos.get(cid, "Generic/Unknown")
        c_risk = case_risks.get(cid, "LOW")
        
        # Check coordinates
        has_coords = row[16] is not None and row[17] is not None
        
        if row[10]: stats["countries"].add(row[10].strip().title())
        if row[11]: stats["states"].add(row[11].strip().title())
        if row[13]: stats["cities"].add(row[13].strip().title())
        elif row[12]: stats["cities"].add(row[12].strip().title())
        
        if not has_coords:
            stats["missing_coords"] += 1
            continue
            
        stats["total_complaints"] += 1
        
        marker = {
            "id": f"complaint_{row[0]}",
            "type": "Complaint",
            "entity_type": "Complaint",
            "lat": row[16],
            "lng": row[17],
            "label": f"Complaint: {row[1] or 'Anonymous'}",
            "details": f"<b>Details:</b> {row[7] or '—'}<br><b>Phone:</b> {row[2] or '—'}<br><b>Address:</b> {row[14] or ''} {row[15] or ''} {row[13] or ''} {row[11] or ''}",
            "link": f"/search?q={row[2]}" if row[2] else "/records",
            "color": "blue",
            "case_id": cid,
            "date": row[8],
            "risk_level": c_risk,
            "modus_operandi": c_mo,
            "status": c_case["status"],
            "country": row[10],
            "state": row[11],
            "district": row[12],
            "city": row[13]
        }
        markers.append(marker)
        
    # Process entities
    for row in raw_entities:
        cid = row[4]
        c_case = cases_dict.get(cid, {"type": "", "status": "Unknown"})
        c_mo = case_mos.get(cid, "Generic/Unknown")
        c_risk = case_risks.get(cid, "LOW")
        
        has_coords = row[11] is not None and row[12] is not None
        
        if row[5]: stats["countries"].add(row[5].strip().title())
        if row[6]: stats["states"].add(row[6].strip().title())
        if row[8]: stats["cities"].add(row[8].strip().title())
        elif row[7]: stats["cities"].add(row[7].strip().title())
        
        if not has_coords:
            stats["missing_coords"] += 1
            continue
            
        stats["total_intelligence"] += 1
        
        marker = {
            "id": f"entity_{row[0]}",
            "type": "Intelligence",
            "entity_type": row[1],
            "lat": row[11],
            "lng": row[12],
            "label": f"{row[1]} Intelligence: {row[2]}",
            "details": f"<b>Case ID:</b> {cid or '—'}<br><b>Entity:</b> {row[1]} ({row[2]})<br><b>Address:</b> {row[9] or ''} {row[10] or ''} {row[8] or ''}",
            "link": f"/workspace/{cid}" if cid else "/records",
            "color": "green",
            "case_id": cid,
            "date": row[3],
            "risk_level": c_risk,
            "modus_operandi": c_mo,
            "status": c_case["status"],
            "country": row[5],
            "state": row[6],
            "district": row[7],
            "city": row[8]
        }
        markers.append(marker)

    # Process IPDR
    for row in raw_ipdr:
        cid = row[5]
        c_case = cases_dict.get(cid, {"type": "", "status": "Unknown"})
        c_mo = case_mos.get(cid, "Generic/Unknown")
        c_risk = case_risks.get(cid, "LOW")
        
        has_coords = row[12] is not None and row[13] is not None
        
        if row[8]: stats["countries"].add(row[8].strip().title())
        if row[9]: stats["states"].add(row[9].strip().title())
        if row[11]: stats["cities"].add(row[11].strip().title())
        elif row[10]: stats["cities"].add(row[10].strip().title())
        
        if not has_coords:
            stats["missing_coords"] += 1
            continue
            
        stats["total_ipdr"] += 1
        
        marker = {
            "id": f"ipdr_{row[0]}",
            "type": "IPDR",
            "entity_type": "IPDR",
            "lat": row[12],
            "lng": row[13],
            "label": f"IPDR Tower: {row[7] or row[6] or 'Unknown'}",
            "details": f"<b>Phone:</b> {row[1]}<br><b>IP:</b> {row[2]}<br><b>Tower Name:</b> {row[7] or '—'}<br><b>Tower ID:</b> {row[6] or '—'}<br><b>Timestamp:</b> {row[3]}",
            "link": f"/workspace/{cid}" if cid else "/records",
            "color": "red",
            "case_id": cid,
            "date": row[3],
            "risk_level": c_risk,
            "modus_operandi": c_mo,
            "status": c_case["status"],
            "country": row[8],
            "state": row[9],
            "district": row[10],
            "city": row[11]
        }
        markers.append(marker)

    # Filter markers list
    filtered_markers = []
    for m in markers:
        if filters.get("case_id") and filters["case_id"].lower() not in (m["case_id"] or "").lower():
            continue
        if filters.get("entity_type") and filters["entity_type"].lower() != (m["entity_type"] or "").lower():
            continue
        if filters.get("date_start"):
            m_date = (m["date"] or "")[:10]
            if m_date < filters["date_start"]:
                continue
        if filters.get("date_end"):
            m_date = (m["date"] or "")[:10]
            if m_date > filters["date_end"]:
                continue
        if filters.get("risk_level") and filters["risk_level"].upper() != (m["risk_level"] or "").upper():
            continue
        if filters.get("modus_operandi") and filters["modus_operandi"].lower() not in (m["modus_operandi"] or "").lower():
            continue
        if filters.get("status") and filters["status"].lower() not in (m["status"] or "").lower():
            continue
        if filters.get("country") and filters["country"].lower() not in (m["country"] or "").lower():
            continue
        if filters.get("state") and filters["state"].lower() not in (m["state"] or "").lower():
            continue
        if filters.get("district") and filters["district"].lower() not in (m["district"] or "").lower():
            continue
        if filters.get("city") and filters["city"].lower() not in (m["city"] or "").lower():
            continue
            
        filtered_markers.append(m)
        
    stats["countries"] = len(stats["countries"])
    stats["states"] = len(stats["states"])
    stats["cities"] = len(stats["cities"])
    
    return filtered_markers, stats


def get_filter_options():
    conn = sqlite3.connect("database/cyberintel.db")
    cursor = conn.cursor()
    
    cursor.execute("SELECT DISTINCT case_id FROM cases WHERE case_id IS NOT NULL AND case_id != ''")
    cases = [r[0] for r in cursor.fetchall()]
    
    countries = set()
    states = set()
    cities = set()
    
    for table in ["complaints", "entities", "ipdr_records"]:
        cursor.execute(f"SELECT DISTINCT country, state, city FROM {table}")
        for country, state, city in cursor.fetchall():
            if country: countries.add(country.strip().title())
            if state: states.add(state.strip().title())
            if city: cities.add(city.strip().title())
            
    conn.close()
    return {
        "cases": sorted(cases),
        "countries": sorted(list(countries)),
        "states": sorted(list(states)),
        "cities": sorted(list(cities))
    }


@app.route("/geo_spatial")
def geo_spatial():
    filters = {
        "case_id": request.args.get("case_id", ""),
        "entity_type": request.args.get("entity_type", ""),
        "date_start": request.args.get("date_start", ""),
        "date_end": request.args.get("date_end", ""),
        "risk_level": request.args.get("risk_level", ""),
        "modus_operandi": request.args.get("modus_operandi", ""),
        "country": request.args.get("country", ""),
        "state": request.args.get("state", ""),
        "district": request.args.get("district", ""),
        "city": request.args.get("city", "")
    }
    
    markers, stats = get_geo_data(filters)
    options = get_filter_options()
    mo_list = list(MO_PROFILES.keys())
    entity_types = ["Complaint", "IPDR", "Phone", "UPI", "Email", "Telegram", "Website"]

    return render_template(
        "geo_spatial.html",
        markers=markers,
        stats=stats,
        options=options,
        mo_list=mo_list,
        entity_types=entity_types,
        filters=filters
    )# ==========================================
# Legal Correspondence Routes
# ==========================================

@app.route("/workspace/<case_id>/legal")
def legal_correspondence(case_id):
    workspace = get_case_workspace(case_id)
    if not workspace["report"]["case"]:
        return "Case not found", 404
        
    import services.notice_service as notice_service
    import json
    
    notices = notice_service.get_case_notices(case_id)
    orgs = list(notice_service.ORGANIZATION_NOTICE_TYPES.keys())
    notice_types_json = json.dumps(notice_service.ORGANIZATION_NOTICE_TYPES)
    
    return render_template(
        "legal_correspondence.html",
        workspace=workspace,
        notices=notices,
        orgs=orgs,
        notice_types_json=notice_types_json
    )

@app.route("/workspace/<case_id>/api/notice_template")
def get_notice_template_api(case_id):
    org = request.args.get("org", "").strip()
    ntype = request.args.get("type", "").strip()
    entity_type = request.args.get("entity_type", "").strip()
    entity_value = request.args.get("entity_value", "").strip()
    
    if not org or not ntype:
        return {"error": "Missing parameters"}, 400
        
    workspace = get_case_workspace(case_id)
    case = workspace["report"]["case"]
    
    import services.notice_service as notice_service
    template_raw = notice_service.get_notice_template(org, ntype)
    
    # Populate template
    current_date = datetime.now().strftime("%Y-%m-%d")
    police_station = "Cyber Crime Police Station" # Default placeholder
    
    populated = template_raw.format(
        investigator=case[4] or "Investigating Officer",
        police_station=police_station,
        current_date=current_date,
        organization=org,
        notice_type=ntype,
        entity_type=entity_type,
        entity_value=entity_value,
        case_id=case_id,
        case_title=case[2] or "Case Title"
    )
    
    return {"template": populated}

@app.route("/workspace/<case_id>/notice/generate", methods=["POST"])
def generate_notice(case_id):
    org = request.form.get("organization", "").strip()
    ntype = request.form.get("notice_type", "").strip()
    related_entity = request.form.get("related_entity", "").strip()
    content = request.form.get("content", "").strip()
    status = request.form.get("status", "Draft").strip()
    
    if not org or not ntype or not related_entity or not content:
        return "Missing required notice parameters", 400
        
    entity_type, entity_value = related_entity.split("|", 1)
    
    import services.notice_service as notice_service
    notice_id = notice_service.save_notice(
        case_id=case_id,
        organization=org,
        notice_type=ntype,
        related_entity_type=entity_type,
        related_entity_value=entity_value,
        content=content,
        status=status
    )
    
    invalidate_analytical_caches(case_id)
    return redirect(f"/workspace/{case_id}/legal")

@app.route("/workspace/<case_id>/notice/<notice_id>")
def notice_details(case_id, notice_id):
    workspace = get_case_workspace(case_id)
    if not workspace["report"]["case"]:
        return "Case not found", 404
        
    import services.notice_service as notice_service
    notice = notice_service.get_notice_by_id(notice_id)
    if not notice:
        return "Notice not found", 404
        
    logs = notice_service.get_notice_activity_log(notice_id)
    
    return render_template(
        "notice_details.html",
        workspace=workspace,
        notice=notice,
        logs=logs
    )

@app.route("/workspace/<case_id>/notice/<notice_id>/update", methods=["POST"])
def update_notice_details(case_id, notice_id):
    status = request.form.get("status", "").strip()
    notes = request.form.get("notes", "").strip()
    
    if not status:
        return "Missing status", 400
        
    import services.notice_service as notice_service
    notice_service.update_notice(notice_id, status, notes)
    
    invalidate_analytical_caches(case_id)
    return redirect(f"/workspace/{case_id}/notice/{notice_id}")

@app.route("/workspace/<case_id>/notice/<notice_id>/view")
def view_notice_pdf(case_id, notice_id):
    import services.notice_service as notice_service
    notice = notice_service.get_notice_by_id(notice_id)
    if not notice or not notice["pdf_path"]:
        return "PDF not found", 404
        
    file_path = os.path.abspath(notice["pdf_path"])
    return send_file(file_path, as_attachment=False)

@app.route("/workspace/<case_id>/notice/<notice_id>/download")
def download_notice_pdf(case_id, notice_id):
    import services.notice_service as notice_service
    notice = notice_service.get_notice_by_id(notice_id)
    if not notice or not notice["pdf_path"]:
        return "PDF not found", 404
        
    file_path = os.path.abspath(notice["pdf_path"])
    return send_file(file_path, as_attachment=True, download_name=f"{notice_id}.pdf")


if __name__ == "__main__":
    app.run(debug=True)
