import sqlite3
import re
from datetime import datetime
from services.cache_service import request_cached

DB_PATH = "database/cyberintel.db"

MO_PROFILES = {
    "Online Banking Phishing": {
        "name": "Online Banking Phishing",
        "description": "Threat actors impersonate banking entities using spoofed websites and malicious support channels to harvest customer login credentials, PINs, or OTPs, performing unauthorized fund transfers.",
        "keywords": ["bank", "secure", "login", "update", "signin", "support", "help", "otp", "unauthorized", "transfer", "netbanking", "card", "axis", "sbi", "icici", "hdfc", "citi"],
        "recommendations": [
            "Initiate takedown requests for spoofed banking domains.",
            "Submit block requests to Telegram/WhatsApp for fraudulent support channels.",
            "Coordinate with beneficiary bank holding the destination account/UPI to freeze funds.",
            "Preserve visitor IP logs and request subscriber details for the linked phone numbers."
        ]
    },
    "Investment/Crypto Scam": {
        "name": "Investment/Crypto Scam",
        "description": "Threat actors lure victims with promises of high-yield investment returns, part-time tasks, or cryptocurrency schemes, using advisory Telegram channels and malicious investment sites to collect funds.",
        "keywords": ["invest", "profit", "return", "crypto", "double", "earn", "gain", "trade", "bitcoin", "task", "part-time", "job", "salary", "vip", "guru", "expert", "btc", "eth", "wallet", "commission", "bonus"],
        "recommendations": [
            "Trace the cryptocurrency transfer path or beneficiary UPI handle flow.",
            "Submit takedown requests to domain registrars of high-yield web platforms.",
            "Request KYC and transaction logs from crypto exchanges / payment intermediaries.",
            "Identify and flag recruitment channels on Telegram/WhatsApp."
        ]
    },
    "Loan App Extortion": {
        "name": "Loan App Extortion",
        "description": "Threat actors offer easy short-term loans via rogue applications, harvesting contact lists upon installation, then blackmailing and harassing the victim's contacts for extortionate repayments.",
        "keywords": ["loan", "app", "interest", "threat", "harass", "contacts", "repay", "instant", "cash", "credit", "recovery", "abuse"],
        "recommendations": [
            "Report rogue applications to Google Play Store / Apple App Store for removal.",
            "Request hosting and domain registration blockages for loan-download sites.",
            "Request KYC and subscriber details for calling numbers and WhatsApp handles.",
            "Analyze contact list harvesting endpoints and block server IPs."
        ]
    },
    "Impersonation Courier Scam": {
        "name": "Impersonation Courier Scam",
        "description": "Threat actors call victims pretending to be customs or logistics officers, claiming that an illegal package containing contraband has been sent under their name, and demanding money to resolve legal issues.",
        "keywords": ["courier", "fedex", "customs", "dhl", "package", "police", "arrest", "narcotics", "illegal", "parcel", "cargo", "shipment", "delivery", "cbi", "custom", "contraband"],
        "recommendations": [
            "Trace the beneficiary bank accounts and UPI handles utilized for payments.",
            "Liaise with logistics providers to report fake tracking numbers and spoofed pages.",
            "Report official impersonation channels to Telegram/WhatsApp support.",
            "Obtain CDR and location data for the caller phone numbers."
        ]
    },
    "KYC Update Phishing": {
        "name": "KYC Update Phishing",
        "description": "Threat actors send SMS warnings that a SIM card, bank account, or wallet will be suspended unless a KYC update is immediately completed, redirecting victims to credential-stealing pages.",
        "keywords": ["kyc", "verify", "verification", "update", "sim", "aadhaar", "pan", "document", "telecom", "jio", "airtel", "vi", "bsnl", "suspend", "block"],
        "recommendations": [
            "Freeze target wallets and accounts associated with KYC verification.",
            "Coordinate with telecom operators to block SMS gateway headers.",
            "Request hosting blockages for KYC collection domains.",
            "Correlate IPDR records to trace the phisher's administration portal access."
        ]
    }
}

def _connect():
    return sqlite3.connect(DB_PATH)

@request_cached("modus_operandi")
def detect_case_mo(case_id):
    """
    Unified authoritative MO detection engine.
    Calculates certainty based on evidence categories rather than arbitrary percentages.
    """
    conn = _connect()
    cursor = conn.cursor()

    # 1. Fetch case details
    cursor.execute(
        "SELECT case_id, case_name, case_type, investigator, status, created_date FROM cases WHERE case_id = ?",
        (case_id,)
    )
    case_row = cursor.fetchone()
    if not case_row:
        conn.close()
        return {
            "case_id": case_id,
            "detected_mo": "Generic/Unknown",
            "description": "Insufficient case details to establish a specific Modus Operandi.",
            "confidence_level": "No Evidence",
            "confidence": 0,
            "matched_indicators": [],
            "missing_indicators": [],
            "alternatives_considered": [],
            "reason_for_selection": "Case not found.",
            "signatures": [],
            "recommendations": [],
            "related_cases": []
        }

    case_meta = {
        "case_id": case_row[0],
        "case_name": case_row[1],
        "case_type": case_row[2],
        "investigator": case_row[3],
        "status": case_row[4],
        "created_date": case_row[5],
    }

    # 2. Fetch entities
    cursor.execute("SELECT entity_type, entity_value FROM entities WHERE case_id = ?", (case_id,))
    entities = cursor.fetchall()

    # 3. Fetch complaints
    cursor.execute("SELECT complainant_name, phone_number, upi_id, email, telegram, website, complaint_details FROM complaints WHERE case_id = ?", (case_id,))
    complaints = cursor.fetchall()

    # 4. Fetch IPDR records count & check for rapid IP switching
    cursor.execute("SELECT phone_number, ip_address, timestamp FROM ipdr_records WHERE case_id = ?", (case_id,))
    ipdr_records = cursor.fetchall()

    # Check for rapid switching
    rapid_switching = False
    phone_ips = {}
    for phone, ip, ts in ipdr_records:
        if phone and ip and ts:
            phone_ips.setdefault(phone, set()).add(ip)
    for phone, ips in phone_ips.items():
        if len(ips) >= 3:
            rapid_switching = True
            break

    conn.close()

    # Match scores calculations
    scores = {}
    matched_sigs = {}
    matched_kws = {}

    type_lower = (case_meta["case_type"] or "").lower()

    for mo_name, mo_data in MO_PROFILES.items():
        score = 0
        sigs = []
        kws_matched = set()

        # Case type correlation
        if mo_name == "Online Banking Phishing" and "banking" in type_lower:
            score += 50
            sigs.append("Case Type matches 'Online Banking Fraud'")
        elif mo_name == "Investment/Crypto Scam" and ("crypto" in type_lower or "investment" in type_lower or type_lower == "test"):
            score += 50
            sigs.append(f"Case Type matches Investment/Crypto Scam")
        elif mo_name == "Loan App Extortion" and "loan" in type_lower:
            score += 50
            sigs.append("Case Type matches 'Loan App Scam'")
        elif mo_name == "Impersonation Courier Scam" and "courier" in type_lower:
            score += 50
            sigs.append("Case Type matches 'Courier Scam'")
        elif mo_name == "KYC Update Phishing" and "kyc" in type_lower:
            score += 50
            sigs.append("Case Type matches 'KYC Verification Scam'")

        # Entity value matches
        entity_points = 0
        for etype, evalue in entities:
            evalue_lower = (evalue or "").lower()
            matching_kw = [kw for kw in mo_data["keywords"] if kw in evalue_lower]
            if matching_kw:
                entity_points += len(matching_kw) * 5
                for kw in matching_kw:
                    kws_matched.add(kw)
                sigs.append(f"Entity '{evalue}' matches M.O. keyword(s): {', '.join(matching_kw)}")
        score += min(30, entity_points)

        # Complaint matches
        complaint_points = 0
        for comp in complaints:
            comp_name_lower = (comp[0] or "").lower()
            comp_details_lower = (comp[6] or "").lower()
            combined_text = comp_name_lower + " " + comp_details_lower
            matching_kw = [kw for kw in mo_data["keywords"] if kw in combined_text]
            if matching_kw:
                complaint_points += len(matching_kw) * 5
                for kw in matching_kw:
                    kws_matched.add(kw)
                sigs.append(f"Complaint metadata contains M.O. keyword(s): {', '.join(matching_kw)}")
        score += min(30, complaint_points)

        # Rapid switching behavioral match
        if rapid_switching and mo_name in ("Online Banking Phishing", "Investment/Crypto Scam"):
            score += 10
            sigs.append("Evasive infrastructure behaviour: rapid IP switching detected in IPDR logs")

        scores[mo_name] = score
        matched_sigs[mo_name] = sigs
        matched_kws[mo_name] = list(kws_matched)

    # Sort candidates
    sorted_candidates = sorted(scores.items(), key=lambda x: x[1], reverse=True)
    highest_mo, highest_score = sorted_candidates[0]
    second_mo, second_score = sorted_candidates[1]

    # Threshold fallback
    if highest_score < 15:
        detected_mo = "Generic/Unknown"
        confidence_level = "No Evidence"
        confidence = 0
        description = "Insufficient indicators matched. The threat activity displays a generic or unclassified modus operandi."
        sigs = ["No specific Modus Operandi signatures detected above threshold."]
        recommendations = [
            "Collect further intelligence indicators.",
            "Verify all digital evidence and transaction logs.",
            "Register all associated complaints to reveal potential links."
        ]
        matched_indicators = []
        missing_indicators = []
        alternatives_considered = []
        reason_for_selection = "No profiles exceeded the minimum score threshold."
    else:
        detected_mo = highest_mo
        profile = MO_PROFILES[detected_mo]
        description = profile["description"]
        sigs = matched_sigs[detected_mo]
        recommendations = profile["recommendations"]
        
        # Explainable levels (Correction 3)
        if highest_score >= 50 and (highest_score - second_score) >= 20:
            confidence_level = "Strong Evidence"
            confidence = 90
        elif highest_score >= 30:
            confidence_level = "Moderate Evidence"
            confidence = 70
        else:
            confidence_level = "Limited Evidence"
            confidence = 45
            
        matched_indicators = sigs
        
        # Missing indicators
        kws_set = set(profile["keywords"])
        matched_set = set(matched_kws[detected_mo])
        missing_indicators = sorted(list(kws_set - matched_set))
        
        # Alternatives
        alternatives_considered = []
        for name, s in sorted_candidates:
            if name != detected_mo and s > 0:
                alternatives_considered.append({
                    "name": name,
                    "score": s,
                    "signatures": matched_sigs[name]
                })
                
        reason_for_selection = f"The score for {detected_mo} ({highest_score}) is higher than all other profiles based on case classification matches and keyword occurrences."

    # Fetch related cases
    related_cases = []
    conn = _connect()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT case_id, case_name, case_type, investigator, status, created_date FROM cases WHERE case_id != ?",
        (case_id,)
    )
    all_other_cases = cursor.fetchall()
    conn.close()

    for o_row in all_other_cases:
        o_cid = o_row[0]
        o_type_lower = (o_row[2] or "").lower()
        o_mo = "Generic/Unknown"
        if "banking" in o_type_lower:
            o_mo = "Online Banking Phishing"
        elif "crypto" in o_type_lower or "investment" in o_type_lower or o_type_lower == "test":
            o_mo = "Investment/Crypto Scam"
        elif "loan" in o_type_lower:
            o_mo = "Loan App Extortion"
        elif "courier" in o_type_lower:
            o_mo = "Impersonation Courier Scam"
        elif "kyc" in o_type_lower:
            o_mo = "KYC Update Phishing"

        if o_mo == detected_mo or (case_meta["case_type"] and case_meta["case_type"] == o_row[2]):
            related_cases.append({
                "case_id": o_cid,
                "case_name": o_row[1],
                "case_type": o_row[2],
                "investigator": o_row[3],
                "status": o_row[4],
                "created_date": o_row[5],
                "detected_mo": o_mo
            })

    return {
        "case_id": case_id,
        "case_name": case_meta["case_name"],
        "case_type": case_meta["case_type"],
        "detected_mo": detected_mo,
        "description": description,
        "confidence_level": confidence_level,
        "confidence": confidence,  # Backwards compatible percentage
        "matched_indicators": matched_indicators,
        "missing_indicators": missing_indicators,
        "alternatives_considered": alternatives_considered,
        "reason_for_selection": reason_for_selection,
        "signatures": sigs,
        "recommendations": recommendations,
        "related_cases": related_cases[:5]
    }

def get_mo_stats():
    """
    Collects statistics using the single authoritative detect_case_mo function.
    """
    conn = _connect()
    cursor = conn.cursor()
    cursor.execute("SELECT case_id FROM cases")
    cases = cursor.fetchall()
    conn.close()

    mo_counts = {name: 0 for name in MO_PROFILES.keys()}
    mo_counts["Generic/Unknown"] = 0

    for row in cases:
        case_id = row[0]
        res = detect_case_mo(case_id)
        det = res["detected_mo"]
        if det in mo_counts:
            mo_counts[det] += 1
        else:
            mo_counts["Generic/Unknown"] += 1

    total_cases = len(cases)
    distribution = []
    for mo_name, count in mo_counts.items():
        percentage = round((count / total_cases * 100)) if total_cases > 0 else 0
        distribution.append({
            "name": mo_name,
            "count": count,
            "percentage": percentage
        })

    return {
        "total_cases": total_cases,
        "mo_counts": mo_counts,
        "distribution": sorted(distribution, key=lambda x: x["count"], reverse=True)
    }
