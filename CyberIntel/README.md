# CyberIntel Working Model
# Cybercrime Intelligence & Investigation Platform
## Demonstration Edition

---

## Overview

This is the fully self-contained working demonstration copy of the
**Cybercrime Intelligence & Investigation Platform**.

It includes a pre-loaded database with **CASE999 "Operation Phantom Net"**
— a complete, cross-linked investigation designed to demonstrate every
module of the platform.

---

## Quick Start

### Prerequisites

- Python 3.9 or higher
- pip

### 1. Install Dependencies

Open a terminal in this folder and run:

    pip install -r requirements.txt

### 2. Start the Application

    python app.py

### 3. Open in Browser

    http://127.0.0.1:5000

### 4. Open the Demonstration Case

    http://127.0.0.1:5000/workspace/CASE999

---

## Platform Modules

| Module | URL |
|--------|-----|
| Dashboard | / |
| Cases | /cases |
| Case Workspace | /workspace/CASE999 |
| Complaint Registration | /complaint |
| Intelligence Records | /records |
| Entity Profile | /entity?entity=9876543210 |
| Global Search | /search?q=bankhelp@okaxis |
| IPDR Upload | /ipdr_upload |
| IPDR Records | /ipdr_records |
| Common IP Analysis | /common_ip |
| Confidence Analysis | /confidence_analysis |
| Timeline Reconstruction | /timeline_reconstruction |
| Intelligence Assessment | /intelligence_assessment?case_id=CASE999 |
| Financial Intelligence | /workspace/CASE999 (Financial tab) |
| Geo-spatial Intelligence | /geo_spatial |
| Modus Operandi Detection | /modus_operandi?case_id=CASE999 |
| Recommendation Engine | /workspace/CASE999 (Recommendations tab) |
| Knowledge Base / SOPs | /sop |
| Case Correlation | /case_correlation?case_id=CASE999 |
| Case Similarity | /case_similarity?case_id=CASE999 |
| Link Analysis Graph | /link_analysis |
| Intelligence Fusion | /fusion |
| Evidence Management | /workspace/CASE999 (Evidence tab) |
| Investigation Report | /download_report/CASE999 |

---

## Demonstration Case: CASE999

### Operation Phantom Net — Multi-Layered Phishing Syndicate

**Case Type:** Phishing Scam
**Investigator:** ACP Shivansh Verma
**Status:** Open

### Complaints (4)
- **Rajesh Mehta** — Delhi | ₹2,45,000 lost via UPI bankhelp@okaxis
- **Priya Sharma** — Mumbai | ₹5,10,000 lost via fake crypto investment portal
- **Amit Joshi** — Jaipur | Credentials stolen via phishing SMS link
- **Sunita Reddy** — Bengaluru | Drained via fake KYC portal

### Intelligence Profiles (21 entities)
- 4 Phone Numbers (2 shared with CASE001/CASE003)
- 4 UPI IDs (2 shared with CASE001/CASE002)
- 3 Emails (1 shared with CASE001/CASE004)
- 2 Telegram channels (1 shared with CASE001)
- 2 Websites (1 shared with CASE001)
- 3 Bank Accounts + 3 IFSC codes

### IPDR Records (12 entries)
- 4 devices tracked across Delhi, Mumbai, Jaipur, Bengaluru
- 4 unique IPs (2 shared with CASE001/CASE002)
- Cell towers: TOW_DL_001, TOW_DL_002, TOW_MH_001, TOW_RJ_001, TOW_KA_001
- Infrastructure switching signals detected

### Evidence (4 files, SHA256 verified)
- CASE999_complaint_log.txt
- CASE999_bank_statement.txt
- CASE999_chat_export.txt
- CASE999_ip_analysis_notes.txt

### Cross-Case Correlations
- Phone 9876543210 shared across CASE001, CASE100, CASE101, CASE999
- UPI bankhelp@okaxis shared across CASE001, CASE003, CASE999
- IP 49.37.120.10 shared across CASE001, CASE002, CASE999
- IP 103.88.44.20 shared across CASE001, CASE999

---

## Working Model Data Folder

The `working_model/` folder contains all demonstration assets:

    working_model/
    ipdr/           # IPDR Excel files for upload
    evidence/       # Evidence files for upload
    documents/      # Supporting documents
    notes/          # Investigation notes
    reports/        # Generated PDF reports
    validation/     # Validation report (CASE999_validation_report.txt)
    screenshots/    # UI screenshots
    exports/        # Data exports
    scripts/        # Automation scripts
      generate_case999.py   # Re-generate CASE999 data
      validate_case999.py   # Run end-to-end validation

---

## Regenerate Demonstration Data

If you need to reset CASE999 to its original state:

    python working_model/scripts/generate_case999.py

---

## Run End-to-End Validation

With the Flask server running (`python app.py`), in a second terminal:

    python working_model/scripts/validate_case999.py

Expected result: 24/25 PASS, 0 FAIL

---

## Validation Results

Last validated: 2026-07-02
Score: 24/25 PASS (96%)

| Module | Status |
|--------|--------|
| Dashboard | PASS |
| Case Management | PASS |
| Investigation Workspace | PASS |
| Complaint Registration | PASS |
| Intelligence Center | PASS |
| Entity Intelligence Profile | WARNING (page loads, case cross-reference by query) |
| Global Search | PASS |
| IPDR Records | PASS |
| Common IP Analysis | PASS |
| Timeline Reconstruction | PASS |
| Confidence Analysis | PASS (Overall: Strong) |
| Graph Preview | PASS (29 nodes, 28 edges) |
| Link Analysis Graph | PASS |
| Geo-spatial Intelligence | PASS |
| Financial Intelligence | PASS |
| Modus Operandi Detection | PASS |
| Knowledge Base / SOPs | PASS |
| Case Correlation | PASS (cross-case links detected) |
| Case Similarity | PASS |
| Intelligence Fusion | PASS |
| Evidence Management | PASS |
| Chain of Custody | PASS (4 items, 4 custody events) |
| SHA256 Integrity | PASS |
| Advanced Reporting (PDF) | PASS (405,267 byte report) |
| Cross-Module DB Integrity | PASS |

---

## Requirements

See `requirements.txt`:
- Flask
- pandas
- openpyxl
- networkx
- matplotlib
- numpy
- reportlab
- gunicorn
