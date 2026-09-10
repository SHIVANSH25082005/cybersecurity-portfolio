import sqlite3
from datetime import datetime
from services.cache_service import request_cached


@request_cached("timeline")
def get_case_timeline(case_id):

    conn = sqlite3.connect("database/cyberintel.db")
    conn.row_factory = sqlite3.Row

    events = []

    # Case Information
    case = conn.execute(
        """
        SELECT *
        FROM cases
        WHERE case_id = ?
        """,
        (case_id,)
    ).fetchone()

    if case:

        events.append({
            "timestamp": case["created_date"],
            "event_type": "CASE_CREATED",
            "title": "Case Created",
            "details": (
                f"{case['case_name']} "
                f"({case['case_type']})"
            )
        })

    # Complaints
    complaints = conn.execute(
        """
        SELECT *
        FROM complaints
        WHERE case_id = ?
        """,
        (case_id,)
    ).fetchall()

    for complaint in complaints:

        events.append({
            "timestamp": complaint["date_added"],
            "event_type": "COMPLAINT",
            "title": "Complaint Added",
            "details": (
                f"Complainant: {complaint['complainant_name']} | "
                f"Phone: {complaint['phone_number']}"
            )
        })

    # Entities
    entities = conn.execute(
        """
        SELECT *
        FROM entities
        WHERE case_id = ?
        """,
        (case_id,)
    ).fetchall()

    for entity in entities:

        events.append({
            "timestamp": entity["date_added"],
            "event_type": "ENTITY",
            "title": "Entity Discovered",
            "details": (
                f"{entity['entity_type']}: "
                f"{entity['entity_value']}"
            )
        })

    # IPDR Records
    ipdr_records = conn.execute(
        """
        SELECT *
        FROM ipdr_records
        WHERE case_id = ?
        ORDER BY timestamp
        """,
        (case_id,)
    ).fetchall()

    previous_location = None

    for record in ipdr_records:

        current_location = record["location"]

        events.append({
            "timestamp": record["timestamp"],
            "event_type": "IPDR_ACTIVITY",
            "title": "IP Activity",
            "details": (
                f"Phone: {record['phone_number']} | "
                f"IP: {record['ip_address']} | "
                f"Location: {current_location}"
            )
        })

        if (
            previous_location
            and current_location
            and previous_location != current_location
        ):

            events.append({
                "timestamp": record["timestamp"],
                "event_type": "INFRASTRUCTURE_TRANSITION",
                "title": "Infrastructure Transition",
                "details": (
                    f"{previous_location} → "
                    f"{current_location}"
                )
            })

        previous_location = current_location

    events.sort(
        key=lambda x: x["timestamp"] or ""
    )

    conn.close()

    return events


def format_date_str(date_str):
    if not date_str:
        return "an unknown date"
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%Y-%m-%dT%H:%M:%S"):
        try:
            dt = datetime.strptime(date_str, fmt)
            day = str(dt.day)
            month = dt.strftime("%B")
            year = str(dt.year)
            return f"{day} {month} {year}"
        except ValueError:
            continue
    if len(date_str) >= 10:
        try:
            dt = datetime.strptime(date_str[:10], "%Y-%m-%d")
            day = str(dt.day)
            month = dt.strftime("%B")
            year = str(dt.year)
            return f"{day} {month} {year}"
        except ValueError:
            pass
    return date_str


def parse_dt(ts_str):
    if not ts_str:
        return datetime.max
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(ts_str, fmt)
        except ValueError:
            continue
    if len(ts_str) >= 10:
        try:
            return datetime.strptime(ts_str[:10], "%Y-%m-%d")
        except ValueError:
            pass
    return datetime.max


def join_list(items):
    if not items:
        return ""
    if len(items) == 1:
        return items[0]
    if len(items) == 2:
        return f"{items[0]} and {items[1]}"
    return f"{', '.join(items[:-1])}, and {items[-1]}"


def join_clauses(clauses):
    if not clauses:
        return ""
    if len(clauses) == 1:
        return clauses[0]
    if len(clauses) == 2:
        return f"{clauses[0]}, and {clauses[1]}"
    return f"{', '.join(clauses[:-1])}, and {clauses[-1]}"


def get_date_only(ts_str):
    if not ts_str:
        return None
    return ts_str[:10]


def generate_investigation_summary(case_id, workspace=None):
    conn = sqlite3.connect("database/cyberintel.db")
    conn.row_factory = sqlite3.Row

    # Fetch Case details
    case = conn.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,)).fetchone()
    if not case:
        conn.close()
        return None

    # Get sorted timeline events
    timeline = get_case_timeline(case_id)
    conn.close()

    if not timeline:
        return {"paragraphs": ["No chronological events recorded for this case."]}

    # Group timeline events that share the exact same timestamp
    grouped_events = []
    for event in timeline:
        if not grouped_events or grouped_events[-1][0]["timestamp"] != event["timestamp"]:
            grouped_events.append([event])
        else:
            grouped_events[-1].append(event)

    sentences = []
    transition_counter = 0
    current_date = None
    total_groups = len(grouped_events)

    # Process all groups except the last group (handled as the ending sentence)
    for idx in range(total_groups - 1):
        group = grouped_events[idx]
        ts = group[0]["timestamp"]
        date_only = get_date_only(ts)
        
        # Date Prefix
        date_prefix = ""
        if date_only != current_date:
            current_date = date_only
            date_prefix = f"On {format_date_str(date_only)}, "

        # Transition Phrase
        transition = ""
        if idx > 0:
            transitions = [
                "Shortly afterwards, ",
                "Following this, ",
                "Later in the investigation, ",
                "As the inquiry proceeded, ",
                "The next recorded activity showed that ",
                "Subsequent tracking indicated that "
            ]
            transition = transitions[(idx - 1) % len(transitions)]

        if date_prefix:
            start_phrase = date_prefix
        else:
            start_phrase = transition

        group_created = [e for e in group if e["event_type"] == "CASE_CREATED"]
        group_complaints = [e for e in group if e["event_type"] == "COMPLAINT"]
        group_entities = [e for e in group if e["event_type"] == "ENTITY"]
        group_ipdr = [e for e in group if e["event_type"] == "IPDR_ACTIVITY"]
        group_trans = [e for e in group if e["event_type"] == "INFRASTRUCTURE_TRANSITION"]

        group_sentences = []

        if group_created:
            c_name = case["case_name"]
            c_type = case["case_type"]
            c_officer = case["investigator"] or "unassigned investigator"
            desc = (
                f"the investigation into {c_name} ({c_type}) was officially initiated under case ID {case_id}, "
                f"with investigator {c_officer} assigned to lead the inquiry"
            )
            group_sentences.append(desc)

        if group_complaints:
            comp_descs = []
            for comp in group_complaints:
                complainant = "an individual"
                phone = "unspecified phone"
                parts = comp["details"].split("|")
                for part in parts:
                    part = part.strip()
                    if part.startswith("Complainant:"):
                        complainant = part.replace("Complainant:", "").strip()
                    elif part.startswith("Phone:"):
                        phone = part.replace("Phone:", "").strip()
                comp_descs.append(f"a formal complaint was lodged by {complainant} referencing phone number {phone}")
            group_sentences.append(join_list(comp_descs))

        if group_entities:
            entity_items = []
            friendly_types = {
                "Phone": "phone number",
                "UPI": "UPI handle",
                "Email": "email address",
                "Telegram": "Telegram channel",
                "Website": "fraudulent web domain",
                "Bank": "beneficiary bank account",
                "Bank Account": "beneficiary bank account",
                "Account": "beneficiary account",
                "IFSC": "IFSC bank routing code"
            }
            for ent in group_entities:
                det = ent["details"]
                etype = "entity"
                eval = ""
                if ":" in det:
                    parts = det.split(":", 1)
                    etype = parts[0].strip()
                    eval = parts[1].strip()
                else:
                    eval = det
                
                friendly_name = friendly_types.get(etype, etype.lower())
                entity_items.append(f"a {friendly_name} ({eval})")
            
            desc = f"intelligence extraction resulted in the identification of {join_list(entity_items)}, which were registered in the case file"
            group_sentences.append(desc)

        if group_ipdr:
            ip_details = []
            for record in group_ipdr:
                ip = "unknown IP"
                loc = "an unknown location"
                phone = "unspecified phone"
                parts = record["details"].split("|")
                for part in parts:
                    part = part.strip()
                    if part.startswith("IP:"):
                        ip = part.replace("IP:", "").strip()
                    elif part.startswith("Location:"):
                        loc = part.replace("Location:", "").strip()
                    elif part.startswith("Phone:"):
                        phone = part.replace("Phone:", "").strip()
                ip_details.append(f"target subscriber {phone} using IP address {ip} located in {loc}")
            
            desc = f"device connections were logged for {join_list(ip_details)}"
            group_sentences.append(desc)

        if group_trans:
            for trans in group_trans:
                transition_counter += 1
                details = trans["details"].replace(" → ", " to ")
                ordinals = {1: "first", 2: "second", 3: "third", 4: "fourth", 5: "fifth"}
                ord_str = ordinals.get(transition_counter, "subsequent")
                desc = f"the target's digital infrastructure shifted from {details}, representing the {ord_str} observed change in network location during the investigation"
                group_sentences.append(desc)

        if group_sentences:
            if start_phrase:
                combined = start_phrase + join_clauses(group_sentences)
            else:
                combined = join_clauses(group_sentences)
            
            combined = combined[0].upper() + combined[1:] + "."
            sentences.append(combined)

    # 5. Process the last group as the final ending sentence
    last_group = grouped_events[-1]
    last_ts = last_group[0]["timestamp"]
    last_date = format_date_str(get_date_only(last_ts))
    
    last_group_created = [e for e in last_group if e["event_type"] == "CASE_CREATED"]
    last_group_complaints = [e for e in last_group if e["event_type"] == "COMPLAINT"]
    last_group_entities = [e for e in last_group if e["event_type"] == "ENTITY"]
    last_group_ipdr = [e for e in last_group if e["event_type"] == "IPDR_ACTIVITY"]
    last_group_trans = [e for e in last_group if e["event_type"] == "INFRASTRUCTURE_TRANSITION"]

    last_clauses = []
    if last_group_created:
        c_name = case["case_name"]
        last_clauses.append(f"the case file for {c_name} was created")
    if last_group_complaints:
        comp_descs = []
        for comp in last_group_complaints:
            complainant = "an individual"
            phone = "unspecified phone"
            parts = comp["details"].split("|")
            for part in parts:
                part = part.strip()
                if part.startswith("Complainant:"):
                    complainant = part.replace("Complainant:", "").strip()
                elif part.startswith("Phone:"):
                    phone = part.replace("Phone:", "").strip()
            comp_descs.append(f"an additional complaint was registered by {complainant} (phone {phone})")
        last_clauses.append(join_list(comp_descs))
    if last_group_entities:
        entity_items = []
        friendly_types = {
            "Phone": "phone number",
            "UPI": "UPI handle",
            "Email": "email address",
            "Telegram": "Telegram channel",
            "Website": "fraudulent web domain",
            "Bank": "beneficiary bank account",
            "Bank Account": "beneficiary bank account",
            "Account": "beneficiary account",
            "IFSC": "IFSC bank routing code"
        }
        for ent in last_group_entities:
            det = ent["details"]
            etype = "entity"
            eval = ""
            if ":" in det:
                parts = det.split(":", 1)
                etype = parts[0].strip()
                eval = parts[1].strip()
            else:
                eval = det
            friendly_name = friendly_types.get(etype, etype.lower())
            entity_items.append(f"a {friendly_name} ({eval})")
        last_clauses.append(f"additional digital identifiers were uncovered, including {join_list(entity_items)}")
    if last_group_ipdr:
        ip_details = []
        for record in last_group_ipdr:
            ip = "unknown IP"
            loc = "an unknown location"
            phone = "unspecified phone"
            parts = record["details"].split("|")
            for part in parts:
                part = part.strip()
                if part.startswith("IP:"):
                    ip = part.replace("IP:", "").strip()
                elif part.startswith("Location:"):
                    loc = part.replace("Location:", "").strip()
                elif part.startswith("Phone:"):
                    phone = part.replace("Phone:", "").strip()
            ip_details.append(f"target subscriber {phone} using IP address {ip} located in {loc}")
        last_clauses.append(f"device connections were logged for {join_list(ip_details)}")
    if last_group_trans:
        for trans in last_group_trans:
            details = trans["details"].replace(" → ", " to ")
            last_clauses.append(f"the target's digital infrastructure transitioned {details}")

    latest_description = join_clauses(last_clauses)
    
    ending_sentence = (
        f"The most recent recorded activity in the reconstructed timeline occurred on {last_date}, "
        f"when {latest_description}. No further events have been recorded after this point."
    )
    sentences.append(ending_sentence)

    # Group sentences into paragraphs of 2 sentences each for readability
    paragraphs = []
    current_paragraph = []
    for s in sentences:
        current_paragraph.append(s)
        if len(current_paragraph) >= 2:
            paragraphs.append(" ".join(current_paragraph))
            current_paragraph = []
    if current_paragraph:
        paragraphs.append(" ".join(current_paragraph))

    return {"paragraphs": paragraphs}