def build_case_recommendations(report, workspace_signals=None, limit=10, case_id=None):
    """
    Builds scenario-aware investigator recommendations based on the primary hypothesis.
    Each recommendation includes an explanation of why it is suggested.
    """
    workspace_signals = workspace_signals or {}
    recommendations = []

    # 1. Determine Case ID to fetch the hypothesis
    if not case_id:
        case_data = report.get("case")
        if case_data:
            if isinstance(case_data, dict):
                case_id = case_data.get("case_id")
            elif isinstance(case_data, (list, tuple)) and len(case_data) > 0:
                case_id = case_data[0]

    # 2. Fetch hypothesis
    primary_hypothesis = "No Supported Investigative Hypothesis"
    if case_id:
        try:
            from services.hypothesis_service import generate_hypothesis
            hyp_res = generate_hypothesis(case_id)
            primary_hypothesis = hyp_res.get("likely_scenario", "No Supported Investigative Hypothesis")
        except Exception as e:
            print("Error generating hypothesis in recommendations service:", e)

    # 3. Primary scenario-aware recommendations
    if primary_hypothesis == "Fraud Ring":
        recommendations.extend([
            "Initiate immediate cross-case coordinate mapping. Reason: Coordinated Fraud Ring hypothesis requires tracing shared actors across circles.",
            "Request gateway/router logs for the shared IP address. Reason: Identifies the administration gateway for the network nodes.",
            "Submit UPI freeze requests for beneficiary accounts. Reason: Coordination with payment banks blocks immediate fund outflow.",
            "Analyze full tower CDR registry for common suspects. Reason: Correlates phone activity timing with victim transaction timestamps."
        ])
    elif primary_hypothesis == "Repeat Offender":
        recommendations.extend([
            "Retrieve historic investigator annotations for matching IDs. Reason: Reused identifiers are linked to prior cases.",
            "Request suspect KYC and account logs from the bank. Reason: Establish identification of the repeat offender's primary bank account.",
            "Log custody and issue notice for the suspect phone line. Reason: Formal demand to telecom operator for subscriber details."
        ])
    elif primary_hypothesis == "Shared Infrastructure":
        recommendations.extend([
            "Request ISP subscriber coordinates for administrative login logs. Reason: Gateway IP address is shared, requiring billing coordinates.",
            "Perform tower sector analysis for overlapping phone numbers. Reason: Verifies if distinct phones are logging from the same physical tower.",
            "Liaise with hosting providers to block proxy nodes. Reason: Suspicious server hosting patterns demand server-level blocks."
        ])
    elif primary_hypothesis == "Independent Complaints":
        recommendations.extend([
            "Verify victim details and statement dates. Reason: Disconnected complaints require verifying separate victim timelines.",
            "Request beneficiary bank statements for each victim separately. Reason: Independent cases should be traced along separate financial flows.",
            "Wait for additional digital evidence logs. Reason: Incomplete connections suggest waiting for further indicators."
        ])
    elif primary_hypothesis == "Single Fraud Actor":
        recommendations.extend([
            "Request CDR logs for caller phone number. Reason: Isolated complaint activity is traced via caller tower locations.",
            "Retrieve bank beneficiary details for the transaction. Reason: Directly maps target account owner of the fraud event.",
            "Collect and verify victim device screenshot metadata. Reason: Validates transaction receipt authenticity."
        ])
    else:
        # Insufficient Evidence / No Supported Hypothesis recommendations
        recommendations.extend([
            "Obtain and upload telecom IPDR logs for the suspect phone. Reason: Lack of indicators prevents threat model classification.",
            "Verify complainant names and register official complaints. Reason: Minimum case data not established.",
            "Liaise with beneficiary banks to recover transaction timestamps. Reason: Critical time coordinates are missing."
        ])

    # 4. Modify with workspace signals (secondary indicators)
    if workspace_signals.get("missing_evidence"):
        recommendations.append(
            "Upload core digital evidence and verify SHA256 integrity. Reason: Missing digital files or integrity hashes in the case database."
        )
    if workspace_signals.get("open_tasks"):
        recommendations.append(
            "Review open investigation tasks and assign owners. Reason: Tasks are currently marked Open, requiring execution review."
        )

    # Deduplicate while preserving order
    deduped = []
    seen = set()
    for item in recommendations:
        if item and item not in seen:
            seen.add(item)
            deduped.append(item)
            
    return deduped[:limit]
