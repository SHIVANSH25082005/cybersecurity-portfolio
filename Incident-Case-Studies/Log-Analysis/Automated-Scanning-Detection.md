# Automated Scanning Detection – Log Analysis

## Overview
This project analyzes firewall, IDS, and application logs to identify automated reconnaissance and scanning activity targeting sensitive endpoints within a simulated enterprise environment.

---

## Normal Traffic Characteristics
- HTTPS traffic using common browsers such as Google Chrome, Mozilla Firefox, and curl.
- Benign request patterns accessing standard application paths.
- Predictable timing between requests.

---

## Suspicious Activity Observed
- User agents associated with scanning tools such as **Nmap** and **SQLMap**.
- Repeated requests targeting sensitive endpoints including:
  - /admin/config
  - /wp-login.php
  - /upload
  - /?admin
- Very short time intervals between requests, indicating automation.

---

## Source IP Analysis
- Multiple source IP addresses observed attempting similar request patterns.
- Many IPs originated from internal-looking address ranges.
- Requests were repeated rapidly across multiple IPs, suggesting automated scanning behavior.

---

## Detection and Security Controls
- Firewall, IDS, and application-level controls blocked most malicious attempts.
- Alerts were generated based on abnormal request behavior.
- No confirmed system compromise was observed.

---

## Analyst Conclusion
The observed activity is consistent with automated reconnaissance and scanning attempts targeting administrative interfaces. Existing security controls successfully prevented unauthorized access.

---

## Recommendations
- Continue monitoring for automated scanning activity.
- Improve alerting for repeated requests to sensitive endpoints.
- Correlate user agent and timing patterns for early detection.
