# Hospital Ransomware Incident – Case Study (Simulated)

## Overview
This case study analyzes a simulated ransomware attack targeting a hospital environment. The attack disrupted access to critical systems and medical records, impacting normal hospital operations and patient care.

---

## Attack Vector
The attackers delivered a phishing email containing a malicious attachment disguised as a legitimate medical or diagnostic document. When the attachment was opened by a hospital staff member, ransomware was executed within the environment.

---

## Attack Progression
- A phishing email was delivered to a hospital employee.
- The malicious attachment was opened on an endpoint system.
- Malware executed and ransomware was deployed.
- Ransomware spread to internal systems and servers.
- Critical systems and medical records were encrypted.
- Normal hospital operations were disrupted.

---

## Indicators of Compromise (IOCs)
- Suspicious email with an unusual attachment.
- Unexpected file execution on endpoint systems.
- Sudden spike in file encryption activity.
- Inaccessibility of critical hospital servers and records.
- Alerts related to abnormal system behavior.

---

## Detection and Response
**Detection**
- Security alerts were triggered after the malicious attachment was opened.
- Staff reported unusual system behavior and loss of access to records.

**Response**
- Infected systems were isolated from the network.
- Incident response procedures were initiated.
- Impact assessment and containment actions were performed.

---

## Prevention and Mitigation
- Implement advanced email filtering to detect phishing attempts.
- Conduct regular security awareness training for hospital staff.
- Deploy endpoint protection and anti-malware solutions.
- Enforce multi-factor authentication (MFA) for system access.
- Maintain regular backups of critical data.

---

## MITRE ATT&CK Mapping
- Initial Access: Phishing (T1566)
- Execution: User Execution (T1204)
- Impact: Data Encrypted for Impact (T1486)

---

## Conclusion
The ransomware attack succeeded due to social engineering and insufficient security controls. The incident highlights the importance of user awareness, strong email security, and layered defenses to reduce the risk and impact of ransomware attacks in healthcare environments.
