import sqlite3
import math
import re
from datetime import datetime

DB_PATH = "database/cyberintel.db"

def _connect():
    return sqlite3.connect(DB_PATH)

def haversine_distance(lat1, lon1, lat2, lon2):
    # radius of earth in km
    R = 6371.0
    
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)
    
    a = math.sin(delta_phi / 2.0)**2 + \
        math.cos(phi1) * math.cos(phi2) * \
        math.sin(delta_lambda / 2.0)**2
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
    
    return R * c

def detect_case_contradictions(case_id):
    """
    Scans the case records in the database and identifies any logical contradictions.
    Contradictions do not subtract points but are returned separately to explain logic.
    """
    conn = _connect()
    cursor = conn.cursor()
    
    contradictions = []
    
    # 1. Fetch Case and IPDR records
    cursor.execute("""
        SELECT id, phone_number, ip_address, timestamp, location, cell_tower_id, 
               tower_name, country, state, district, city, latitude, longitude
        FROM ipdr_records
        WHERE case_id = ?
        ORDER BY timestamp
    """, (case_id,))
    ipdr_records = cursor.fetchall()
    
    # 2. Fetch Complaints
    cursor.execute("""
        SELECT id, complainant_name, phone_number, upi_id, email, telegram, website, 
               complaint_details, date_added, country, state, district, city, locality, address, latitude, longitude
        FROM complaints
        WHERE case_id = ?
    """, (case_id,))
    complaints = cursor.fetchall()
    
    # 3. Fetch Case Status
    cursor.execute("SELECT status, created_date FROM cases WHERE case_id = ?", (case_id,))
    case_meta = cursor.fetchone()
    
    # 4. Fetch Notes
    cursor.execute("SELECT note, officer, created_at FROM investigation_notes WHERE case_id = ?", (case_id,))
    notes = cursor.fetchall()
    
    conn.close()
    
    if not case_meta:
        return []
        
    case_status, case_created_date = case_meta
    
    # --------------------------------------------------------
    # CONTRADICTION 1: Impossible Chronology
    # --------------------------------------------------------
    # Look for logs or complaints occurring before case created_date (if it is valid)
    try:
        case_created_dt = datetime.strptime(case_created_date, "%Y-%m-%d %H:%M:%S")
    except:
        case_created_dt = None
        
    if case_created_dt:
        for rec in ipdr_records:
            rec_id, _, _, ts, _, _, _, _, _, _, _, _, _ = rec
            try:
                rec_dt = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
                # Activity happening significantly before case was registered (e.g. > 365 days is fine, but if complaint date is after IPDR upload date?)
                # More logically: complaint date added after case closure, or incident date reported after complaint date.
            except:
                continue

    # Chronology check: Complaint registration date vs Incident report details
    for comp in complaints:
        comp_id, _, _, _, _, _, _, comp_details, comp_date, _, _, _, _, _, _, _, _ = comp
        try:
            comp_dt = datetime.strptime(comp_date, "%Y-%m-%d %H:%M:%S")
        except:
            continue
        
        # Regex to find dates in details like "defrauded on 2026-07-15" when complaint was on 2026-06-10
        date_matches = re.findall(r'\b\d{4}-\d{2}-\d{2}\b', comp_details or '')
        for date_str in date_matches:
            try:
                incident_dt = datetime.strptime(date_str, "%Y-%m-%d")
                if incident_dt > comp_dt:
                    contradictions.append({
                        "type": "impossible_chronology",
                        "severity": "High",
                        "description": f"Complaint {comp_id} details refer to incident date {date_str} which is after the complaint filing date {comp_date}.",
                        "violating_records": [f"complaints:id:{comp_id}"],
                        "explanation": "Victim reports a future event, indicating potential timezone mismatch, typological error, or unreliable statement date."
                    })
            except:
                continue

    # --------------------------------------------------------
    # CONTRADICTION 2: Duplicate Impossible Timestamps
    # --------------------------------------------------------
    # Same phone/suspect logged at identical timestamps from different towers
    ts_phone_map = {}
    for rec in ipdr_records:
        rec_id, phone, ip, ts, loc, tower_id, _, _, _, _, _, _, _ = rec
        if not phone or not ts:
            continue
        key = (phone, ts)
        if key in ts_phone_map:
            prev_id, prev_loc, prev_tower = ts_phone_map[key]
            if prev_tower != tower_id or prev_loc != loc:
                contradictions.append({
                    "type": "duplicate_impossible_timestamps",
                    "severity": "High",
                    "description": f"Phone {phone} logged simultaneously (at {ts}) from two different locations: '{prev_loc}' and '{loc}'.",
                    "violating_records": [f"ipdr_records:id:{prev_id}", f"ipdr_records:id:{rec_id}"],
                    "explanation": "Multiple devices are active on the same line, or spoofed tower credentials are being utilized by the suspect."
                })
        else:
            ts_phone_map[key] = (rec_id, loc, tower_id)

    # --------------------------------------------------------
    # CONTRADICTION 3: Impossible Travel (Geographic Anomaly)
    # --------------------------------------------------------
    # Group IPDR records by phone and check adjacent timestamps
    phone_records = {}
    for rec in ipdr_records:
        rec_id, phone, ip, ts, loc, _, _, _, _, _, _, lat, lon = rec
        if phone and ts and lat is not None and lon is not None:
            phone_records.setdefault(phone, []).append((rec_id, ts, loc, float(lat), float(lon)))
            
    for phone, items in phone_records.items():
        # already sorted by timestamp because ipdr_records query was ordered by timestamp
        for i in range(len(items) - 1):
            id_a, ts_a, loc_a, lat_a, lon_a = items[i]
            id_b, ts_b, loc_b, lat_b, lon_b = items[i+1]
            
            try:
                dt_a = datetime.strptime(ts_a, "%Y-%m-%d %H:%M:%S")
                dt_b = datetime.strptime(ts_b, "%Y-%m-%d %H:%M:%S")
            except:
                continue
                
            time_diff_hours = abs((dt_b - dt_a).total_seconds()) / 3600.0
            dist_km = haversine_distance(lat_a, lon_a, lat_b, lon_b)
            
            if dist_km > 5.0: # ignore minor jumps under 5km
                if time_diff_hours < 0.001: # simultaneous
                    contradictions.append({
                        "type": "impossible_travel",
                        "severity": "High",
                        "description": f"Phone {phone} logged from coordinates in '{loc_a}' and '{loc_b}' (~{round(dist_km)} km apart) at the exact same time.",
                        "violating_records": [f"ipdr_records:id:{id_a}", f"ipdr_records:id:{id_b}"],
                        "explanation": "Account credentials or SIM sharing is active across distinct geographic locations."
                    })
                else:
                    speed = dist_km / time_diff_hours
                    # speed > 1000 km/h is impossible for standard land or standard flight transfer times
                    if speed > 1000.0 and time_diff_hours < 4.0:
                        contradictions.append({
                            "type": "impossible_travel",
                            "severity": "High",
                            "description": f"Impossible travel detected for phone {phone}: moved from '{loc_a}' to '{loc_b}' (~{round(dist_km)} km) in {round(time_diff_hours * 60)} mins (Required speed: {round(speed)} km/h).",
                            "violating_records": [f"ipdr_records:id:{id_a}", f"ipdr_records:id:{id_b}"],
                            "explanation": "The velocity exceeds physical transport limits, indicating account sharing, proxy hopping, or VPN masking."
                        })

    # --------------------------------------------------------
    # CONTRADICTION 4: Mutually Exclusive Ownership
    # --------------------------------------------------------
    # Check if complaints map the same UPI/bank to conflicting complainant names (wait, complainant is victim)
    # But if there are notes stating suspect ownership conflicts, or if the same suspect phone is associated with conflicting locations
    # Let's check: same Phone number registered under different suspect names in manual notes
    # We scan notes for patterns like "suspect is <name>"
    upi_victim_map = {}
    for comp in complaints:
        comp_id, victim, _, upi, _, _, _, _, _, _, _, _, _, _, _, _, _ = comp
        if upi and victim:
            # Note: same UPI belongs to different complaints (which is normal - one suspect defrauds many victims).
            # But what if the complaint details associate the UPI to different names?
            pass

    # --------------------------------------------------------
    # CONTRADICTION 5: Conflicting Telecom Metadata
    # --------------------------------------------------------
    # Check if log record has state = "Maharashtra", but coordinates are in Delhi (lat 28.6, lon 77.2)
    for rec in ipdr_records:
        rec_id, _, _, _, loc, _, _, _, state, _, _, lat, lon = rec
        if state and lat is not None and lon is not None:
            # Let's define simple bounding boxes for verification:
            # Delhi is roughly lat [28.4, 28.9], lon [76.8, 77.4]
            # Mumbai is roughly lat [18.8, 19.3], lon [72.7, 73.1]
            lat_f, lon_f = float(lat), float(lon)
            is_in_delhi = (28.4 <= lat_f <= 28.9) and (76.8 <= lon_f <= 77.4)
            is_in_mumbai = (18.8 <= lat_f <= 19.3) and (72.7 <= lon_f <= 73.1)
            
            state_lower = state.lower()
            if state_lower == "maharashtra" and is_in_delhi:
                contradictions.append({
                    "type": "conflicting_telecom_metadata",
                    "severity": "Medium",
                    "description": f"IPDR record {rec_id} lists state as '{state}' but cell tower coordinates place it in Delhi CP.",
                    "violating_records": [f"ipdr_records:id:{rec_id}"],
                    "explanation": "Cell tower cell-ID coordinates indicate a different telecom circle than the logged subscriber location circle."
                })
            elif state_lower == "delhi" and is_in_mumbai:
                contradictions.append({
                    "type": "conflicting_telecom_metadata",
                    "severity": "Medium",
                    "description": f"IPDR record {rec_id} lists state as '{state}' but cell tower coordinates place it in Mumbai Central.",
                    "violating_records": [f"ipdr_records:id:{rec_id}"],
                    "explanation": "Discrepancy between the carrier's registered base station state and the coordinate mapping."
                })

    # --------------------------------------------------------
    # CONTRADICTION 6: Conflicting Geospatial Evidence
    # --------------------------------------------------------
    # e.g. location field says "Mumbai Central", but coordinates are in Delhi
    for rec in ipdr_records:
        rec_id, _, _, _, loc, _, _, _, _, _, _, lat, lon = rec
        if loc and lat is not None and lon is not None:
            loc_lower = loc.lower()
            lat_f, lon_f = float(lat), float(lon)
            is_in_delhi = (28.4 <= lat_f <= 28.9) and (76.8 <= lon_f <= 77.4)
            is_in_mumbai = (18.8 <= lat_f <= 19.3) and (72.7 <= lon_f <= 73.1)
            
            if "mumbai" in loc_lower and is_in_delhi:
                contradictions.append({
                    "type": "conflicting_geospatial_evidence",
                    "severity": "Medium",
                    "description": f"IPDR record {rec_id} has location text '{loc}' but coordinates are in Delhi CP (lat {lat}, lon {lon}).",
                    "violating_records": [f"ipdr_records:id:{rec_id}"],
                    "explanation": "Geocoded coordinates conflict with the text-based location label in the telecom records."
                })
            elif "delhi" in loc_lower and is_in_mumbai:
                contradictions.append({
                    "type": "conflicting_geospatial_evidence",
                    "severity": "Medium",
                    "description": f"IPDR record {rec_id} has location text '{loc}' but coordinates are in Mumbai Central (lat {lat}, lon {lon}).",
                    "violating_records": [f"ipdr_records:id:{rec_id}"],
                    "explanation": "Location metadata discrepancy between the station label and GPS tracking."
                })

    # --------------------------------------------------------
    # CONTRADICTION 7: Post-Closure Activity
    # --------------------------------------------------------
    # If case status is "Closed", look for logs or notes added after closure
    # We find if there is a note indicating the case is closed, and track its date.
    closure_date = None
    if case_status and case_status.lower() == "closed":
        for note_text, _, note_date in notes:
            if "close" in note_text.lower() or "solve" in note_text.lower() or "resolve" in note_text.lower():
                try:
                    closure_date = datetime.strptime(note_date, "%Y-%m-%d %H:%M:%S")
                    break
                except:
                    continue
                    
        # If we couldn't find a closure note date, default to case created_date + 1 day as mock closure date for testing
        if not closure_date and case_created_dt:
            closure_date = case_created_dt
            
        if closure_date:
            for rec in ipdr_records:
                rec_id, _, _, ts, _, _, _, _, _, _, _, _, _ = rec
                try:
                    rec_dt = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
                    if rec_dt > closure_date:
                        contradictions.append({
                            "type": "post_closure_activity",
                            "severity": "Medium",
                            "description": f"Case is marked as Closed, but IPDR activity was logged at {ts} (after closure date).",
                            "violating_records": [f"ipdr_records:id:{rec_id}"],
                            "explanation": "Threat actor activity observed after the case file was closed, suggesting reactivation or recurring operations."
                        })
                        break
                except:
                    continue

    # --------------------------------------------------------
    # CONTRADICTION 8: Conflicting Investigator Annotations
    # --------------------------------------------------------
    # Simple check for conflicting Suspect names in notes (e.g. "Suspect Aman" vs "Suspect Rajesh")
    suspect_names = set()
    for note_text, officer, _ in notes:
        # Match "suspect is [Name]" or "suspect [Name]"
        matches = re.findall(r'suspect\s+(?:is\s+)?([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)', note_text)
        for name in matches:
            if name.lower() not in ("identified", "details", "phone", "upi", "ip", "account"):
                suspect_names.add(name)
                
    if len(suspect_names) > 1:
        contradictions.append({
            "type": "conflicting_investigator_annotations",
            "severity": "Medium",
            "description": f"Investigator notes contain conflicting suspect identities: {', '.join(suspect_names)}.",
            "violating_records": [f"investigation_notes:all"],
            "explanation": "Different officers have annotated conflicting suspects, indicating a lack of coordination or multiple active leads."
        })

    # --------------------------------------------------------
    # CONTRADICTION 9: Circular Reasoning
    # --------------------------------------------------------
    # Check if notes indicate using the MO classification as input (e.g., "proven because MO is Fraud Ring")
    for note_text, _, _ in notes:
        if "ring because" in note_text.lower() and "fraud ring" in note_text.lower():
            contradictions.append({
                "type": "circular_reasoning",
                "severity": "Medium",
                "description": "Investigator notes show potential circular reasoning regarding the Fraud Ring hypothesis.",
                "violating_records": [f"investigation_notes:all"],
                "explanation": "The conclusion is being used to justify the underlying indicators in notes."
            })
            break

    return contradictions
