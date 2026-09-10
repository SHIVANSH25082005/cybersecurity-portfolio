import sqlite3
from confidence_analysis import calculate_ip_confidence
from time_analysis import calculate_time_proximity
from services.contradiction_service import detect_case_contradictions
from services.cache_service import request_cached


@request_cached("hypothesis")
def generate_hypothesis(case_id, workspace=None):
    """
    Generates ranked hypotheses for the given case.
    Ensures court-defensible output without fake probabilities.
    Includes the 'No Supported Investigative Hypothesis' state if evidence is insufficient.
    """
    if workspace is None:
        # Self-contained database fallback to avoid circular imports
        conn = sqlite3.connect("database/cyberintel.db")
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM complaints WHERE case_id = ?", (case_id,))
        complaints = cursor.fetchall()
        
        cursor.execute("SELECT entity_type, entity_value, source FROM entities WHERE case_id = ?", (case_id,))
        entities = cursor.fetchall()
        
        cursor.execute("SELECT * FROM ipdr_records WHERE case_id = ?", (case_id,))
        ipdr_records = cursor.fetchall()
        
        conn.close()
        
        workspace = {
            "report": {
                "complaints": complaints,
                "entities": entities,
                "ipdr_records": ipdr_records,
                "risk_level": "LOW",
                "rapid_switching": []
            },
            "financial": {},
            "shared_phone": False,
            "shared_ip": False,
            "shared_upi": False,
            "infrastructure": [],
            "priority_level": "LOW"
        }

    # 1. Gather all inputs
    complaints = workspace.get("report", {}).get("complaints", [])
    complaint_count = len(complaints)
    
    entities = workspace.get("report", {}).get("entities", [])
    ipdr_records = workspace.get("report", {}).get("ipdr_records", [])
    ipdr_count = len(ipdr_records)
    
    financial = workspace.get("financial", {})
    financial_reuse = bool(financial.get("reused"))
    
    shared_phone = workspace.get("shared_phone", False)
    shared_ip = workspace.get("shared_ip", False)
    
    # Check UPI sharing
    upis_in_case = [c[3] for c in complaints if len(c) > 3 and c[3]]
    has_internal_upi_share = len(upis_in_case) > len(set(upis_in_case))
    has_upi_share = workspace.get("shared_upi", False) or has_internal_upi_share
    
    # Check IP sharing
    infrastructure = workspace.get("infrastructure", [])
    has_same_ip = any(len(infra) > 2 and infra[2] > 1 for infra in infrastructure)
    
    # Extract unique IPs
    case_ips = []
    seen_ips = set()
    for r in ipdr_records:
        if len(r) > 2 and r[2] and r[2] not in seen_ips:
            seen_ips.add(r[2])
            case_ips.append(r[2])
            
    # Check rapid IP switching
    rapid_switching = bool(workspace.get("report", {}).get("rapid_switching", []))
    
    # Check timeline overlap
    has_timeline_overlap = False
    timeline_evidence = []
    for ip in case_ips[:8]:
        time_results = calculate_time_proximity(ip, case_id)
        for res in time_results:
            if res["minutes"] <= 120:
                has_timeline_overlap = True
                timeline_evidence.append(res)
                
    risk_level = workspace.get("report", {}).get("risk_level", "LOW")
    priority_level = workspace.get("priority_level", "LOW")
    
    # Gather contradictions
    contradictions_list = detect_case_contradictions(case_id)
    high_contradictions = [c for c in contradictions_list if c["severity"] == "High"]
    
    # 2. Check if total evidence is insufficient
    total_indicators = len(entities) + len(case_ips)
    is_insufficient = (complaint_count == 0 and ipdr_count == 0) or (total_indicators < 2 and complaint_count <= 1)

    # 3. Calculate scores for the 5 scenarios
    hypothesis_scores = {}
    details = {}
    
    # --- Hypothesis A: Fraud Ring (Coordinated Syndicate) ---
    ring_score = 0
    ring_support = []
    ring_contradict = []
    ring_missing = []
    
    if complaint_count > 1:
        ring_score += 3
        ring_support.append(f"Multiple complaints ({complaint_count}) are associated with the case.")
    else:
        ring_contradict.append("Case contains only a single complaint, which contradicts the coordinated syndicate model.")
        
    if shared_phone or has_upi_share or financial_reuse:
        ring_score += 4
        ring_support.append("Reused identity elements (Phone, UPI, or financial accounts) are observed across complaints.")
    else:
        ring_missing.append("Missing evidence of shared suspect credentials/UPI accounts across complainants.")
        
    if shared_ip or has_same_ip:
        ring_score += 4
        ring_support.append("Shared internet infrastructure (same IP address logs) overlaps between different suspects/devices.")
    else:
        ring_missing.append("No common IP address overlaps detected between different phone numbers.")
        
    if rapid_switching:
        ring_score += 2
        ring_support.append("Evasive network behavior (rapid IP switching) is active in telecom logs.")
        
    if has_timeline_overlap:
        ring_score += 2
        ring_support.append("Suspicious timeline overlap: phone logins occurred close in time from the same IP.")
        
    if risk_level in ("HIGH", "CRITICAL") or priority_level in ("HIGH", "CRITICAL"):
        ring_score += 1
        ring_support.append("Syndicate indicators trigger elevated risk alerts.")
        
    if high_contradictions:
        ring_contradict.append(f"High-severity contradiction detected: {high_contradictions[0]['description']}.")
        
    hypothesis_scores["Fraud Ring"] = ring_score
    details["Fraud Ring"] = {
        "supporting": ring_support,
        "contradicting": ring_contradict,
        "missing": ring_missing,
        "alt_explanations": ["Activity might represent a single highly active spammer rather than a coordinated group."]
    }
    
    # --- Hypothesis B: Repeat Offender ---
    repeat_score = 0
    repeat_support = []
    repeat_contradict = []
    repeat_missing = []
    
    if shared_phone or has_upi_share or financial_reuse:
        repeat_score += 5
        repeat_support.append("Identifiers (phone/UPI/accounts) match records in other cases or are reused internally.")
    else:
        repeat_contradict.append("No identity elements (phone numbers, UPI IDs, bank accounts) are shared with other cases.")
        
    if complaint_count > 1:
        repeat_score += 2
        repeat_support.append(f"Multiple complaints ({complaint_count}) link to the same identifiers.")
        
    if has_same_ip or shared_ip:
        # Repeat offenders often change IPs, so lack of shared IP doesn't contradict, but having it is neutral/slight positive
        repeat_score += 1
        
    hypothesis_scores["Repeat Offender"] = repeat_score
    details["Repeat Offender"] = {
        "supporting": repeat_support,
        "contradicting": repeat_contradict,
        "missing": repeat_missing,
        "alt_explanations": ["Shared phone lines could indicate a public call booth or spoofed caller ID circle."]
    }

    # --- Hypothesis C: Shared Infrastructure ---
    infra_score = 0
    infra_support = []
    infra_contradict = []
    infra_missing = []
    
    if shared_ip or has_same_ip or rapid_switching:
        infra_score += 5
        infra_support.append("Case indicators are linked through common IP addresses or network gateways.")
    else:
        infra_contradict.append("No IP address overlaps or network infrastructure reuse detected.")
        
    if has_timeline_overlap:
        infra_score += 2
        infra_support.append("Timeline correlation confirms active simultaneous sessions on the shared network.")
        
    if not (shared_phone or has_upi_share):
        infra_score += 2
        infra_support.append("No suspect identities are shared, pointing to independent actors sharing network nodes.")
        
    hypothesis_scores["Shared Infrastructure"] = infra_score
    details["Shared Infrastructure"] = {
        "supporting": infra_support,
        "contradicting": infra_contradict,
        "missing": infra_missing,
        "alt_explanations": ["IP address could be a Carrier NAT mobile gateway shared by thousands of innocent users."]
    }

    # --- Hypothesis D: Independent Complaints ---
    indep_score = 0
    indep_support = []
    indep_contradict = []
    indep_missing = []
    
    if complaint_count > 1:
        indep_score += 3
        indep_support.append(f"Case has {complaint_count} independent complaints.")
    else:
        indep_contradict.append("Single complaint file does not require grouping independent cases.")
        
    if not (shared_phone or has_upi_share or shared_ip or has_same_ip or rapid_switching or has_timeline_overlap):
        indep_score += 5
        indep_support.append("No indicator overlaps or shared network sessions are detected.")
    else:
        indep_contradict.append("Common identifiers or shared IPs are observed, contradicting independent complaints.")
        
    hypothesis_scores["Independent Complaints"] = indep_score
    details["Independent Complaints"] = {
        "supporting": indep_support,
        "contradicting": indep_contradict,
        "missing": indep_missing,
        "alt_explanations": ["Victims might have been targeted by the same syndicate but using completely isolated campaigns."]
    }

    # --- Hypothesis E: Single Fraud Actor ---
    single_score = 0
    single_support = []
    single_contradict = []
    single_missing = []
    
    if complaint_count == 1:
        single_score += 4
        single_support.append("Case is restricted to a single isolated complaint.")
    else:
        single_contradict.append(f"Multiple complaints ({complaint_count}) suggest a wider target scope than a single actor.")
        
    if not (shared_phone or has_upi_share or shared_ip or has_same_ip):
        single_score += 3
        single_support.append("No indicators connect this case to external investigations or other entities.")
    else:
        single_contradict.append("Shared elements are linked to other investigations or multiple suspect nodes.")
        
    hypothesis_scores["Single Fraud Actor"] = single_score
    details["Single Fraud Actor"] = {
        "supporting": single_support,
        "contradicting": single_contradict,
        "missing": single_missing,
        "alt_explanations": ["Actor could be part of a larger syndicate but operating with unique disposable identifiers."]
    }

    # 4. Rank hypotheses
    ranked_list = []
    sorted_scores = sorted(hypothesis_scores.items(), key=lambda x: x[1], reverse=True)
    
    primary_hypothesis_name, primary_score = sorted_scores[0]

    # Determine confidence level of hypothesis assessment.
    #
    # IMPORTANT — decision order:
    #   1. If the scoring engines produced a positive primary score, that result
    #      is authoritative regardless of the pre-score is_insufficient flag.
    #      is_insufficient is a data-volume heuristic evaluated before scoring;
    #      if it conflicts with a positive scored result the scored result wins.
    #   2. If primary_score == 0 the scoring engines found nothing to support any
    #      hypothesis — fall back to "No Supported Investigative Hypothesis".
    #   3. is_insufficient may still contribute an "Insufficient Evidence"
    #      confidence label, but only when primary_score is also zero.
    if primary_score > 0:
        likely_scenario = primary_hypothesis_name
        overall_confidence = "Strong" if primary_score >= 8 else ("Moderate" if primary_score >= 4 else "Limited")
        if primary_hypothesis_name == "Fraud Ring":
            overall_assessment = f"Strong indications of a coordinated Fraud Ring operating with shared infrastructure."
        elif primary_hypothesis_name == "Repeat Offender":
            overall_assessment = f"Indications suggest threat activity associated with a Repeat Offender."
        elif primary_hypothesis_name == "Shared Infrastructure":
            overall_assessment = f"Shared infrastructure detected. Multiple accounts utilize common network gateways."
        elif primary_hypothesis_name == "Independent Complaints":
            overall_assessment = f"Multiple complaints recorded with zero indicator overlap, representing independent actors."
        else:
            overall_assessment = f"Activity appears isolated to a Single Fraud Actor without external correlation."
    elif is_insufficient:
        # Scores are also zero AND the pre-score gate confirms thin evidence.
        likely_scenario = "No Supported Investigative Hypothesis"
        overall_confidence = "Insufficient Evidence"
        overall_assessment = "The available case evidence is insufficient to defensibly support any investigative hypothesis."
    else:
        # Scores are zero but evidence volume was not flagged as thin.
        likely_scenario = "No Supported Investigative Hypothesis"
        overall_confidence = "Limited"
        overall_assessment = "No predefined hypothesis meets the minimum evidence score requirements."

    # Build ranked hypothesis objects
    for rank_idx, (name, score) in enumerate(sorted_scores):
        str_val = "High" if score >= 8 else ("Medium" if score >= 4 else "Low")
        if primary_score <= 0:
            str_val = "None"
            
        item_details = details[name]
        
        # Calculate reason ranked above alternatives
        if name == primary_hypothesis_name:
            reason_ranked = "Has the highest support score based on the combination of indicator sharing and complaint patterns."
        else:
            reason_ranked = f"Ranked lower because its score ({score}) is less than the primary candidate's score ({primary_score})."
            
        ranked_list.append({
            "name": name,
            "strength": str_val,
            "score": score,
            "supporting_evidence": item_details["supporting"],
            "contradicting_evidence": item_details["contradicting"],
            "missing_evidence": item_details["missing"],
            "reason_ranked_above_alternatives": reason_ranked,
            "alternative_explanations": item_details["alt_explanations"]
        })

    # If insufficient evidence, we override primary hypothesis
    if likely_scenario == "No Supported Investigative Hypothesis":
        missing_categories = []
        if complaint_count == 0:
            missing_categories.append("Incident Complaints (NCR Portal PDF or manual registrations)")
        if ipdr_count == 0:
            missing_categories.append("Telecom IPDR/CDR logs")
        if len(entities) == 0:
            missing_categories.append("Suspect Indicators (UPI IDs, bank accounts, emails)")
            
        primary_hypothesis = {
            "name": "No Supported Investigative Hypothesis",
            "strength": "None",
            "score": 0,
            "supporting_evidence": ["No indicators are present to map to a threat profile."],
            "contradicting_evidence": [],
            "missing_evidence": missing_categories,
            "reason_ranked_above_alternatives": "Assigned because case evidence did not meet minimum sufficiency thresholds.",
            "alternative_explanations": ["Further digital forensics or telecom subscriber details may reveal coordinates."]
        }
    else:
        primary_hypothesis = [h for h in ranked_list if h["name"] == likely_scenario][0]

    # Reasoning blocks for backwards compatibility UI
    reasoning_blocks = []
    if likely_scenario != "No Supported Investigative Hypothesis":
        for h in ranked_list:
            if h["score"] > 0:
                reasoning_blocks.append({
                    "text": f"Matches pattern for {h['name']}.",
                    "has_evidence": True,
                    "evidence_type": h["name"].lower().replace(" ", "_"),
                    "evidence_data": {
                        "supporting": h["supporting_evidence"],
                        "contradictions": h["contradicting_evidence"]
                    }
                })

    # Recommended next actions primarily based on hypothesis (Correction 5)
    actions = []
    if likely_scenario == "Fraud Ring":
        actions = [
            "Initiate immediate cross-case coordinate mapping.",
            "Request gateway/router logs for the shared IP address.",
            "Submit UPI freeze requests for beneficiary accounts.",
            "Analyze full tower CDR registry for common suspects."
        ]
    elif likely_scenario == "Repeat Offender":
        actions = [
            "Retrieve historic investigator annotations for matching IDs.",
            "Request suspect KYC and account logs from the bank.",
            "Log custody and issue notice for the suspect phone line."
        ]
    elif likely_scenario == "Shared Infrastructure":
        actions = [
            "Request ISP subscriber coordinates for administrative login logs.",
            "Perform tower sector analysis for overlapping phone numbers.",
            "Liaise with hosting providers to block proxy nodes."
        ]
    elif likely_scenario == "Independent Complaints":
        actions = [
            "Verify victim details and statement dates.",
            "Wait for additional digital evidence logs.",
            "Request beneficiary bank statements for each victim separately."
        ]
    elif likely_scenario == "Single Fraud Actor":
        actions = [
            "Request CDR logs for caller phone number.",
            "Retrieve bank beneficiary details for the transaction.",
            "Collect and verify victim device screenshot metadata."
        ]
    else:
        # Insufficient Evidence recommendations (Correction 8)
        actions = [
            "Obtain and upload telecom IPDR logs for the suspect phone.",
            "Verify complainant names and register official complaints.",
            "Liaise with beneficiary banks to recover transaction timestamps."
        ]

    return {
        "primary_hypothesis": primary_hypothesis,
        "ranked_hypotheses": ranked_list,
        "overall_assessment": overall_assessment,
        "likely_scenario": likely_scenario,
        "confidence_level": overall_confidence,
        "reasoning": reasoning_blocks,
        "next_actions": actions
    }
