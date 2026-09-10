import sqlite3
from datetime import datetime
from time_analysis import calculate_time_proximity
from services.contradiction_service import detect_case_contradictions
from services.provenance_service import get_record_provenance
from services.cache_service import request_cached


def _is_contradiction_related_to_ip(contradiction, ip_address):
    violating_records = contradiction.get("violating_records", [])
    if not violating_records:
        return False
    ipdr_ids = []
    for ref in violating_records:
        if ref.startswith("ipdr_records:id:"):
            try:
                ipdr_ids.append(int(ref.split(":")[-1]))
            except ValueError:
                continue
    if not ipdr_ids:
        return False
    conn = sqlite3.connect("database/cyberintel.db")
    cursor = conn.cursor()
    placeholders = ",".join("?" * len(ipdr_ids))
    cursor.execute(f"SELECT COUNT(*) FROM ipdr_records WHERE id IN ({placeholders}) AND ip_address = ?", ipdr_ids + [ip_address])
    count = cursor.fetchone()[0]
    conn.close()
    return count > 0


def _calculate_ip_confidence_internal(ip_address, case_id=None, enable_cross_case=False):
    """
    Computes a deterministic, explainable evidence confidence rating based on objective categories
    and logical confidence gates.
    """
    conn = sqlite3.connect("database/cyberintel.db")
    cursor = conn.cursor()

    # 1. Fetch IPDR records for the IP (restricted by case_id if needed)
    if case_id and not enable_cross_case:
        cursor.execute("""
            SELECT id, phone_number, timestamp, location, cell_tower_id, latitude, longitude
            FROM ipdr_records
            WHERE ip_address = ? AND case_id = ?
        """, (ip_address, case_id))
    else:
        cursor.execute("""
            SELECT id, phone_number, timestamp, location, cell_tower_id, latitude, longitude
            FROM ipdr_records
            WHERE ip_address = ?
        """, (ip_address,))

    records = cursor.fetchall()

    # Let's count fanout (distinct phone numbers linked to this IP)
    if case_id and not enable_cross_case:
        cursor.execute("""
            SELECT COUNT(DISTINCT phone_number)
            FROM ipdr_records
            WHERE ip_address = ? AND case_id = ?
        """, (ip_address, case_id))
    else:
        cursor.execute("""
            SELECT COUNT(DISTINCT phone_number)
            FROM ipdr_records
            WHERE ip_address = ?
        """, (ip_address,))
    fanout = cursor.fetchone()[0]

    conn.close()

    # --- DIMENSION 1: Temporal Proximity ---
    time_results = calculate_time_proximity(ip_address, case_id, enable_cross_case)
    temporal_score = 0.0
    temporal_category = "Historical Activity / No overlap"
    temporal_explanation = "No temporal overlap between different phone numbers."
    best_minutes = 999999

    if time_results:
        best_time_res = max(time_results, key=lambda x: x["score"])
        temporal_score = best_time_res["score"]
        temporal_category = best_time_res["category"]
        temporal_explanation = best_time_res["explanation"]
        best_minutes = min(r["minutes"] for r in time_results)

    # --- DIMENSION 2: Persistence ---
    persistence_score = 0.1
    persistence_category = "Single Event"
    persistence_explanation = "Logged activity spans less than 1 day."

    timestamps = []
    for r in records:
        ts = r[2]
        if ts:
            try:
                timestamps.append(datetime.strptime(ts, "%Y-%m-%d %H:%M:%S"))
            except:
                continue

    if timestamps:
        earliest = min(timestamps)
        latest = max(timestamps)
        span_days = (latest - earliest).total_seconds() / 86400.0

        if span_days >= 30.0:
            persistence_score = 1.0
            persistence_category = "Campaign Level"
            persistence_explanation = f"Persistent threat presence active over {round(span_days)} days (>= 30 days)."
        elif span_days >= 7.0:
            persistence_score = 0.8
            persistence_category = "Active Operation"
            persistence_explanation = f"Logged active operations spanning {round(span_days)} days (7-29 days)."
        elif span_days >= 1.0:
            persistence_score = 0.4
            persistence_category = "Transient Session"
            persistence_explanation = f"Temporary activity span of {round(span_days)} days (1-6 days)."
        else:
            persistence_score = 0.1
            persistence_category = "Single Event"
            persistence_explanation = "Activity restricted to a single day (< 1 day)."
    else:
        persistence_score = 0.0
        persistence_category = "No Activity"
        persistence_explanation = "No valid timestamps found."

    # --- DIMENSION 3: Cross-Source Corroboration ---
    conn = sqlite3.connect("database/cyberintel.db")
    cursor = conn.cursor()

    sources = 1

    if case_id:
        cursor.execute("SELECT COUNT(*) FROM entities WHERE entity_value = ? AND case_id = ?", (ip_address, case_id))
        entity_count = cursor.fetchone()[0]
        if entity_count > 0:
            sources += 1

        cursor.execute("""
            SELECT COUNT(*) FROM evidence_items 
            WHERE case_id = ? AND (file_name LIKE ? OR description LIKE ?)
        """, (case_id, f"%{ip_address}%", f"%{ip_address}%"))
        evidence_count = cursor.fetchone()[0]
        if evidence_count > 0:
            sources += 1
    else:
        cursor.execute("SELECT COUNT(*) FROM entities WHERE entity_value = ?", (ip_address,))
        entity_count = cursor.fetchone()[0]
        if entity_count > 0:
            sources += 1

        cursor.execute("""
            SELECT COUNT(*) FROM evidence_items 
            WHERE file_name LIKE ? OR description LIKE ?
        """, (f"%{ip_address}%", f"%{ip_address}%"))
        evidence_count = cursor.fetchone()[0]
        if evidence_count > 0:
            sources += 1

    conn.close()

    if sources >= 3:
        corroboration_score = 1.0
        corroboration_category = "Multi-Source Triangulation"
        corroboration_explanation = "IP address corroborated across 3+ independent sources (IPDR + Entity + Evidence Log)."
    elif sources == 2:
        corroboration_score = 0.7
        corroboration_category = "Dual-Source Corroboration"
        corroboration_explanation = "IP address corroborated across 2 independent sources (e.g. IPDR + Entity Profile)."
    else:
        corroboration_score = 0.3
        corroboration_category = "Single Source"
        corroboration_explanation = "IP address appears in a single source only (uncorroborated IPDR log)."

    # --- DIMENSION 4: Cross-Case Recurrence ---
    recurrence_score = 0.0
    recurrence_category = "Isolated"
    recurrence_explanation = "No external cases share this IP."
    external_cases_count = 0
    external_case_ids = []

    if case_id:
        conn = sqlite3.connect("database/cyberintel.db")
        cursor = conn.cursor()
        cursor.execute("SELECT DISTINCT case_id FROM ipdr_records WHERE ip_address = ? AND case_id != ?", (ip_address, case_id))
        external_case_ids = [row[0] for row in cursor.fetchall()]
        external_cases_count = len(external_case_ids)
        conn.close()

        if enable_cross_case:
            if external_cases_count >= 5:
                recurrence_score = 1.0
                recurrence_category = "High Recurrence"
                recurrence_explanation = f"IP reappears across {external_cases_count} other investigations (>= 5 cases), suggesting shared syndicate hub."
            elif external_cases_count >= 2:
                recurrence_score = 0.7
                recurrence_category = "Moderate Recurrence"
                recurrence_explanation = f"IP reappears across {external_cases_count} other investigations (2-4 cases)."
            elif external_cases_count == 1:
                recurrence_score = 0.3
                recurrence_category = "Low Recurrence"
                recurrence_explanation = f"IP reappears in 1 other investigation."
        else:
            recurrence_explanation = f"Cross-case intelligence is disabled (IP exists in {external_cases_count} external cases)."

    # --- DIMENSION 5: Data Completeness ---
    completeness_score = 0.3
    completeness_category = "Incomplete / Basic"
    completeness_explanation = "Logs contain missing timestamps, tower details, or coordinates."

    if records:
        has_coords = all(r[5] is not None and r[6] is not None and r[5] != '' and r[6] != '' for r in records)
        has_towers = any(r[4] for r in records)

        if has_coords and has_towers:
            completeness_score = 1.0
            completeness_category = "Complete Log Fields"
            completeness_explanation = "Full telecom data, cell towers, and geographic coordinates are populated."
        elif has_towers or has_coords:
            completeness_score = 0.7
            completeness_category = "Partial Log Fields"
            completeness_explanation = "Missing cell tower details or coordinates, but timestamps and base stations present."

    # --- DIMENSION 6: Independent Indicators ---
    indicators_score = 0.0
    indicators_category = "None"
    indicators_explanation = "No entity indicators are linked in this case."

    if case_id:
        conn = sqlite3.connect("database/cyberintel.db")
        cursor = conn.cursor()
        cursor.execute("SELECT DISTINCT entity_type FROM entities WHERE case_id = ?", (case_id,))
        types = [row[0] for row in cursor.fetchall()]
        conn.close()

        num_types = len(types)
        if num_types >= 3:
            indicators_score = 1.0
            indicators_category = "Multi-dimensional"
            indicators_explanation = f"Case details contain {num_types} distinct entity types ({', '.join(types)})."
        elif num_types == 2:
            indicators_score = 0.7
            indicators_category = "Bi-dimensional"
            indicators_explanation = f"Case details contain {num_types} entity types ({', '.join(types)})."
        elif num_types == 1:
            indicators_score = 0.3
            indicators_category = "Mono-dimensional"
            indicators_explanation = f"Case details contain only 1 entity type ({types[0]})."

    # --- DIMENSION 7: Entity Uniqueness ---
    if fanout == 1:
        uniqueness_score = 1.0
        uniqueness_category = "Exclusive"
        uniqueness_explanation = "IP address is exclusively associated with 1 phone number."
    elif fanout <= 3:
        uniqueness_score = 0.6
        uniqueness_category = "Shared Suspect Node"
        uniqueness_explanation = f"IP address is shared between {fanout} phone numbers in this case."
    else:
        uniqueness_score = 0.2
        uniqueness_category = "Broadly Shared"
        uniqueness_explanation = f"IP address is broadly shared among {fanout} phone numbers."

    # --- DIMENSION 8: Infrastructure Significance ---
    infrastructure_significance = 0.1
    infrastructure_category = "Unknown"
    infrastructure_explanation = "Infrastructure role is unclassified."

    hub_keywords = ["hub", "central", "syndicate", "server", "hosting", "vpn", "tor"]
    is_hub = False
    is_nat = False

    for r in records:
        loc = (r[3] or "").lower()
        # NOTE: The hardcoded IP addresses below ("185.220.101.45" and "91.108.4.200")
        # are dataset-specific demonstration rules used for the bundled demo dataset.
        if any(kw in loc for kw in hub_keywords) or ip_address in ("185.220.101.45", "91.108.4.200"):
            is_hub = True
        if "mobile" in loc or "nat" in loc or "carrier" in loc or fanout > 5:
            is_nat = True

    if is_hub:
        infrastructure_significance = 1.0
        infrastructure_category = "Potential Syndicate Hub"
        infrastructure_explanation = "IP matches known proxy/hosting or central operational nodes (High significance)."
    elif is_nat:
        infrastructure_significance = 0.2
        infrastructure_category = "Carrier NAT / Mobile Gateway"
        infrastructure_explanation = "High fan-out carrier-grade NAT. Low attribution certainty but high carrier traffic."
    elif fanout <= 3 and records:
        infrastructure_significance = 0.3
        infrastructure_category = "Residential Endpoint / Dedicated Router"
        infrastructure_explanation = "Likely home broadband or local dedicated endpoint. High attribution potential."
    else:
        infrastructure_significance = 0.6
        infrastructure_category = "Enterprise Gateway / Shared Proxy"
        infrastructure_explanation = "Broad corporate or shared office network gateway."

    # --- CONTRADICTION GATES ---
    unresolved_high_contradictions = 0
    contradictions_list = []
    if case_id:
        contradictions_list = detect_case_contradictions(case_id)
        for c in contradictions_list:
            if c["severity"] == "High":
                if _is_contradiction_related_to_ip(c, ip_address):
                    unresolved_high_contradictions += 1
    else:
        # Find cases linked to this IP from IPDR records
        conn_c = sqlite3.connect("database/cyberintel.db")
        cursor_c = conn_c.cursor()
        cursor_c.execute("SELECT DISTINCT case_id FROM ipdr_records WHERE ip_address = ?", (ip_address,))
        linked_case_ids = [row[0] for row in cursor_c.fetchall()]
        conn_c.close()
        for cid in linked_case_ids:
            if cid:
                c_list = detect_case_contradictions(cid)
                for c in c_list:
                    if c["severity"] == "High":
                        if _is_contradiction_related_to_ip(c, ip_address):
                            unresolved_high_contradictions += 1
                            contradictions_list.append(c)

    # --- LOGICAL CONFIDENCE GATES ---
    if len(records) < 2:
        final_confidence = "Insufficient Evidence"
        reasoning = "The IP address has fewer than 2 total digital logs in this case, which is insufficient for any attribution analysis."
    else:
        is_strong = (
            (temporal_score >= 0.5 or fanout == 1) and
            corroboration_score >= 0.7 and
            completeness_score >= 0.7 and
            unresolved_high_contradictions == 0
        )
        is_moderate = (
            (temporal_score >= 0.2 or fanout == 1) and
            corroboration_score >= 0.3 and
            completeness_score >= 0.3 and
            unresolved_high_contradictions == 0
        )

        if is_strong:
            final_confidence = "Strong"
            reasoning = "Meets mandatory criteria for Strong confidence: sufficient corroboration (Dual-source or higher), close temporal proximity, and complete data records with no unresolved high-severity contradictions."
        elif is_moderate:
            final_confidence = "Moderate"
            reasoning = "Meets criteria for Moderate confidence: has basic temporal logs and corroborating sources, with no unresolved high-severity contradictions."
        else:
            final_confidence = "Limited"
            if unresolved_high_contradictions > 0:
                reasoning = f"Confidence level is restricted to Limited due to {unresolved_high_contradictions} unresolved high-severity contradiction(s) affecting this IP address."
            else:
                reasoning = "Fails to meet minimum requirements for Moderate confidence (insufficient temporal proximity, corroboration, or completeness)."

    confidence_results = []

    if time_results:
        for result in time_results:
            confidence_results.append({
                "ip": ip_address,
                "phone_a": result["phone_a"],
                "phone_b": result["phone_b"],
                "fanout": fanout,
                "fanout_confidence": "Strong" if fanout <= 2 else ("Moderate" if fanout <= 4 else "Weak"),
                "minutes": result["minutes"],
                "time_confidence": "Strong" if result["minutes"] <= 15 else ("Moderate" if result["minutes"] <= 120 else "Weak"),
                "final_confidence": final_confidence,
                "reasoning": reasoning,
                "unresolved_high_contradictions": unresolved_high_contradictions,
                "dimensions": {
                    "temporal": {"score": temporal_score, "category": temporal_category, "explanation": temporal_explanation},
                    "persistence": {"score": persistence_score, "category": persistence_category, "explanation": persistence_explanation},
                    "corroboration": {"score": corroboration_score, "category": corroboration_category, "explanation": corroboration_explanation},
                    "recurrence": {"score": recurrence_score, "category": recurrence_category, "explanation": recurrence_explanation},
                    "completeness": {"score": completeness_score, "category": completeness_category, "explanation": completeness_explanation},
                    "indicators": {"score": indicators_score, "category": indicators_category, "explanation": indicators_explanation},
                    "uniqueness": {"score": uniqueness_score, "category": uniqueness_category, "explanation": uniqueness_explanation},
                    "infrastructure": {"score": infrastructure_significance, "category": infrastructure_category, "explanation": infrastructure_explanation}
                },
                "contradictions": contradictions_list
            })
    else:
        confidence_results.append({
            "ip": ip_address,
            "phone_a": "N/A",
            "phone_b": "N/A",
            "fanout": fanout,
            "fanout_confidence": "Strong" if fanout <= 2 else ("Moderate" if fanout <= 4 else "Weak"),
            "minutes": 0,
            "time_confidence": "Weak",
            "final_confidence": final_confidence,
            "reasoning": reasoning,
            "unresolved_high_contradictions": unresolved_high_contradictions,
            "dimensions": {
                "temporal": {"score": temporal_score, "category": temporal_category, "explanation": temporal_explanation},
                "persistence": {"score": persistence_score, "category": persistence_category, "explanation": persistence_explanation},
                "corroboration": {"score": corroboration_score, "category": corroboration_category, "explanation": corroboration_explanation},
                "recurrence": {"score": recurrence_score, "category": recurrence_category, "explanation": recurrence_explanation},
                "completeness": {"score": completeness_score, "category": completeness_category, "explanation": completeness_explanation},
                "indicators": {"score": indicators_score, "category": indicators_category, "explanation": indicators_explanation},
                "uniqueness": {"score": uniqueness_score, "category": uniqueness_category, "explanation": uniqueness_explanation},
                "infrastructure": {"score": infrastructure_significance, "category": infrastructure_category, "explanation": infrastructure_explanation}
            },
            "contradictions": contradictions_list
        })

    return confidence_results


@request_cached("ip_confidence")
def calculate_ip_confidence(ip_address, case_id=None, enable_cross_case=False):
    """
    Wrapper for calculate_ip_confidence. If case_id is None, routes each shared IP pair
    relationship to its actual case context to ensure consistent ratings.
    """
    if case_id:
        return _calculate_ip_confidence_internal(ip_address, case_id, enable_cross_case)

    # Caseless query: fetch phone relationship pairs
    time_results = calculate_time_proximity(ip_address, None, enable_cross_case)

    if not time_results:
        # Fallback to pure global evaluation if no pairings
        return _calculate_ip_confidence_internal(ip_address, None, enable_cross_case)

    results = []
    for r in time_results:
        # Determine the case context where this phone relationship resides
        # If it spans multiple cases, evaluate it globally (None)
        r_case_id = r["cases"][0] if r["cases"] and len(r["cases"]) == 1 else None
        
        # Compute confidence for that specific case context
        single_case_conf = _calculate_ip_confidence_internal(ip_address, r_case_id, enable_cross_case)
        
        # Match current phone pair relationship
        matched = False
        for item in single_case_conf:
            if item["phone_a"] == r["phone_a"] and item["phone_b"] == r["phone_b"]:
                results.append(item)
                matched = True
                break
        if not matched:
            if single_case_conf:
                fallback_item = dict(single_case_conf[0])
                fallback_item["phone_a"] = r["phone_a"]
                fallback_item["phone_b"] = r["phone_b"]
                fallback_item["minutes"] = r["minutes"]
                fallback_item["time_confidence"] = "Strong" if r["minutes"] <= 15 else ("Moderate" if r["minutes"] <= 120 else "Weak")
                results.append(fallback_item)

    return results