# Account Compromise Incident – Case Study (Simulated)

## Overview
This case study analyzes a simulated account compromise incident affecting a technology company. An employee account was accessed without authorization, allowing an attacker to gain access to internal systems and sensitive data.

---

## Attack Vector
The attacker obtained valid employee credentials from a previous data breach. The employee reused the same password across multiple platforms, and multi-factor authentication (MFA) was not enabled on the account.

---

## Attack Progression
- Stolen credentials were used in automated login attempts.
- Multiple authentication attempts were observed.
- Unauthorized access to an employee account was successful.
- The attacker accessed internal dashboards and sensitive data.
- Data was copied without authorization.

---

## Indicators of Compromise (IOCs)
- Multiple failed login attempts followed by a successful login.
- Login attempts from unusual geographic locations.
- Access activity outside normal business hours.
- Unusual access to sensitive internal resources.

---

## Detection and Response
**Detection**
- Alerts triggered due to abnormal login behavior.
- Authentication logs revealed repeated failed login attempts.

**Response**
- The compromised account was disabled.
- Credentials were reset.
- Suspicious IP addresses were blocked.
- MFA was enforced on affected accounts.

---

## Prevention and Mitigation
- Enforce strong password policies.
- Implement mandatory multi-factor authentication.
- Monitor and alert on failed login attempts.
- Apply login rate limiting.
- Conduct regular security awareness training.

---

## MITRE ATT&CK Mapping
- Initial Access: Valid Accounts (T1078)
- Credential Access: Credential Dumping / Reuse (T1555)
- Impact: Account Takeover

---

## Conclusion
The account compromise occurred due to password reuse and lack of MFA. Implementing stronger authentication controls and continuous monitoring would significantly reduce the risk of similar incidents.
