import os
import json
import sqlite3

SOP_FILE_PATH = "database/sop_knowledge_base.json"
DB_PATH = "database/cyberintel.db"

DEFAULT_SOPS = [
    {
        "id": "sop_online_banking",
        "title": "Online Banking Fraud SOP",
        "category": "cybercrime_workflows",
        "description": "Standard operating procedure for investigating online banking fraud, phishing, and unauthorized money transfers.",
        "target_case_types": ["Online Banking Fraud"],
        "target_mo_categories": ["Online Banking Phishing"],
        "steps": [
            "Obtain the transaction details, including transaction ID, timestamp, and target account/UPI.",
            "Send an immediate freeze request to the beneficiary bank or payment gateway using the official nodal email.",
            "Request IPDR logs from the payment gateway to track the IP address used for the transaction.",
            "Submit a domain takedown request if spoofed/phishing banking sites were identified.",
            "Draft and issue a legal request under Section 91 CrPC (or equivalent local laws) to collect KYC documents."
        ],
        "legal_provisions": [
            "Section 91 CrPC (Summons to produce document)",
            "Section 66D IT Act (Cheating by personation)"
        ],
        "resources": [
            "National Cyber Crime Reporting Portal (NCRP) Nodal Contact List",
            "Draft Nodal Email Template for Bank Freeze"
        ]
    }
]

def _load_sops():
    if not os.path.exists(SOP_FILE_PATH):
        return DEFAULT_SOPS
    try:
        with open(SOP_FILE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return DEFAULT_SOPS

def get_all_sops(query=None, category=None):
    sops = _load_sops()
    
    # Filter by category
    if category:
        sops = [s for s in sops if s.get("category") == category]
        
    # Search by keyword
    if query:
        q = query.lower()
        filtered = []
        for s in sops:
            # Check title, description
            if q in s.get("title", "").lower() or q in s.get("description", "").lower():
                filtered.append(s)
                continue
            # Check steps
            if any(q in step.lower() for step in s.get("steps", [])):
                filtered.append(s)
                continue
            # Check legal provisions
            if any(q in prov.lower() for prov in s.get("legal_provisions", [])):
                filtered.append(s)
                continue
            # Check resources
            if any(q in res.lower() for res in s.get("resources", [])):
                filtered.append(s)
                continue
        sops = filtered
        
    return sops

def get_relevant_sops_for_case(case_id, case_type=None, detected_mo=None):
    if not case_type or not detected_mo:
        # Fetch case details from database
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT case_type FROM cases WHERE case_id = ?", (case_id,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            case_type = row[0]
            
        # Detect Modus Operandi to get detected M.O.
        try:
            from services.modus_operandi_service import detect_case_mo
            mo_data = detect_case_mo(case_id)
            detected_mo = mo_data.get("detected_mo")
        except Exception:
            detected_mo = "Generic/Unknown"

    sops = _load_sops()
    matched = []
    
    for s in sops:
        is_match = False
        
        # Match case type (support "all" wildcard as general SOP)
        target_types = [t.lower() for t in s.get("target_case_types", [])]
        if case_type and (case_type.lower() in target_types or "all" in target_types):
            is_match = True
            
        # Match Modus Operandi category
        target_mos = [m.lower() for m in s.get("target_mo_categories", [])]
        if detected_mo and detected_mo.lower() in target_mos:
            is_match = True
            
        if is_match:
            matched.append(s)
            
    return matched
