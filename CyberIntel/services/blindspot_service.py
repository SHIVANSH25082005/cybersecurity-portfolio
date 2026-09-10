def detect_blind_spots(case_id, workspace=None):
    """
    Orchestration service for detecting investigation blind spots.
    Separates investigative evidence categories from case documentation/workflow items.
    """
    if workspace is None:
        from app import get_case_workspace
        workspace = get_case_workspace(case_id)

    # 1. Extract case indicators from pre-loaded workspace data
    entities = workspace.get("report", {}).get("entities", [])
    complaints = workspace.get("report", {}).get("complaints", [])
    ipdr_count = workspace.get("report", {}).get("ipdr_count", 0)
    complaint_count = workspace.get("report", {}).get("complaint_count", 0)
    entity_count = workspace.get("report", {}).get("entity_count", 0)
    evidence_items = workspace.get("evidence_items", [])
    notes = workspace.get("notes", [])
    tasks = workspace.get("tasks", [])

    has_phone = any(e[1] == "Phone" for e in entities) or any(c[2] for c in complaints)
    has_upi = any(e[1] == "UPI" for e in entities) or any(c[3] for c in complaints)
    has_email = any(e[1] == "Email" for e in entities) or any(c[4] for c in complaints)
    has_telegram = any(e[1] == "Telegram" for e in entities) or any(c[5] for c in complaints)
    has_website = any(e[1] == "Website" or e[1] == "Domain" for e in entities) or any(c[6] for c in complaints)

    # 2. Genuine Investigative Evidence Categories (10 categories)
    evidence_categories = {
        "Complaint": {
            "present": complaint_count > 0,
            "explanation": "No official complaint records have been registered for this case."
        },
        "Phone": {
            "present": has_phone,
            "explanation": "No suspect or victim contact phone numbers have been cataloged."
        },
        "UPI": {
            "present": has_upi,
            "explanation": "No UPI identifiers have been linked to trace financial transaction flow."
        },
        "Email": {
            "present": has_email,
            "explanation": "No email addresses have been identified for credential or communication analysis."
        },
        "Telegram": {
            "present": has_telegram,
            "explanation": "No Telegram handles have been recorded for online support/recruitment channel mapping."
        },
        "Website": {
            "present": has_website,
            "explanation": "No website domains have been recorded for web application takedown mapping."
        },
        "IPDR": {
            "present": ipdr_count > 0,
            "explanation": "Required for validating infrastructure switching and communication patterns."
        },
        "Timeline": {
            "present": ipdr_count > 0 or complaint_count > 0,
            "explanation": "Temporal reconstruction cannot be fully validated without active IPDR or complaint date markers."
        },
        "Evidence Files": {
            "present": len(evidence_items) > 0,
            "explanation": "No supporting digital evidence has been attached to prove chain of custody."
        },
        "Linked Entities": {
            "present": entity_count > 0,
            "explanation": "No intelligence indicators or profiles are linked to this case."
        }
    }

    present_categories = [name for name, data in evidence_categories.items() if data["present"]]
    missing_categories = [name for name, data in evidence_categories.items() if not data["present"]]

    total_count = len(evidence_categories)
    present_count = len(present_categories)
    completeness_score = round((present_count / total_count) * 100) if total_count > 0 else 0

    # 3. Compile 'Why It Matters' (strictly for missing investigative evidence)
    why_it_matters = []
    for name in missing_categories:
        why_it_matters.append({
            "category": name,
            "explanation": evidence_categories[name]["explanation"]
        })

    # 4. Separate Case Management / Documentation Status (Workflow items)
    workflow_status = {
        "notes_present": len(notes) > 0,
        "tasks_present": len(tasks) > 0
    }

    # 5. Compile 'Highest Priority Next Steps'
    RECOMMENDATION_MAPPING = {
        "Rapid infrastructure switching detected": {
            "step": "Upload IPDR",
            "reason": "Required to validate infrastructure movement."
        },
        "Preserve IP logs": {
            "step": "Analyze IP Details",
            "reason": "Investigate shared IP address overlap."
        },
        "Request subscriber details and CDR": {
            "step": "Request CDR",
            "reason": "Required to identify subscriber identity."
        },
        "identify linked UPI owner details": {
            "step": "Request UPI KYC",
            "reason": "Enables bank freeze and identification of beneficiary details."
        },
        "Financial indicator reuse detected": {
            "step": "Collect beneficiary KYC",
            "reason": "Required to identify beneficiary details."
        },
        "Open the closest matching case": {
            "step": "Compare Case Details",
            "reason": "Compares shared indicators and chronology."
        },
        "Upload core digital evidence": {
            "step": "Attach Evidence Files",
            "reason": "Strengthens evidentiary support."
        },
        "Review open investigation tasks": {
            "step": "Assign Pending Tasks",
            "reason": "Enables tracking of legal requests."
        }
    }

    priority_steps = []
    existing_recs = workspace.get("recommendations", [])

    for rec in existing_recs:
        for key, val in RECOMMENDATION_MAPPING.items():
            if key in rec:
                if val not in priority_steps:
                    priority_steps.append(val)

    # Fallback next steps based on missing evidence
    if len(priority_steps) < 3:
        if "IPDR" in missing_categories and not any(p["step"] == "Upload IPDR" for p in priority_steps):
            priority_steps.append({
                "step": "Upload IPDR",
                "reason": "Required to validate infrastructure movement."
            })
        if "Evidence Files" in missing_categories and not any(p["step"] == "Attach Evidence Files" for p in priority_steps):
            priority_steps.append({
                "step": "Attach Evidence Files",
                "reason": "Strengthens evidentiary support."
            })
        if not workflow_status["notes_present"] and not any(p["step"] == "Complete Investigation Notes" for p in priority_steps):
            priority_steps.append({
                "step": "Complete Investigation Notes",
                "reason": "Improves case file completeness."
            })
        if not workflow_status["tasks_present"] and not any(p["step"] == "Create Case Tasks" for p in priority_steps):
            priority_steps.append({
                "step": "Create Case Tasks",
                "reason": "Enables tracking of pending actions."
            })

    return {
        "completeness_score": completeness_score,
        "total_categories": total_count,
        "present_count": present_count,
        "present_categories": present_categories,
        "missing_categories": missing_categories,
        "why_it_matters": why_it_matters,
        "workflow": workflow_status,
        "priority_steps": priority_steps[:3]
    }
