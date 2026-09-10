def priority_from_signals(
    risk_level,
    linked_case_count=0,
    unique_ip_count=0,
    rapid_switch_count=0,
    complaint_count=0,
    financial_reuse_count=0,
    high_alert_count=0,
    similarity_top_score=0,
):
    points = 0
    points += linked_case_count * 8
    points += unique_ip_count * 3
    points += rapid_switch_count * 20
    points += complaint_count * 10
    points += financial_reuse_count * 18
    points += high_alert_count * 12
    if similarity_top_score >= 70:
        points += 10
    elif similarity_top_score >= 50:
        points += 5

    if risk_level == "HIGH":
        points += 30
    elif risk_level == "MEDIUM":
        points += 15

    if points >= 90:
        level = "CRITICAL"
    elif points >= 55:
        level = "HIGH"
    elif points >= 25:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {"level": level, "points": points}
