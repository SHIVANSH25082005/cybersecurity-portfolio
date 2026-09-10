# Cybersecurity Portfolio

This repository contains hands-on cybersecurity projects completed as part of my learning journey through practical exercises and cybersecurity certifications.

The projects focus on cybercrime intelligence, incident analysis, security monitoring, log forensics, and security automation using Python. All projects are designed to reflect real-world SOC (Security Operations Center) and threat intelligence investigator tasks.

---

## 🔐 Projects Included

### 1. Cybercrime Intelligence & Investigation Platform (CyberIntel)
- [CyberIntel Platform](CyberIntel/README.md)  
  *A comprehensive, self-contained cybercrime intelligence and investigation platform designed for law enforcement, threat intelligence, and digital forensics analysts.*
  - **Key Features**:
    - **Case Workspace & Management**: End-to-end investigation workflow (includes pre-loaded demonstration case **CASE999 "Operation Phantom Net"**).
    - **IPDR Analysis & Common IP Discovery**: Analyzes Internet Protocol Detail Records, extracts patterns of life, and maps cellular/tower-based suspect activities.
    - **Entity Profiling & Link Analysis**: Correlates phone numbers, suspect identities, bank accounts, UPI IDs, and IP relationships using NetworkX graph modeling.
    - **Timeline Reconstruction**: Chronologically maps attacker interactions, call records, and digital evidence.
    - **Automated Evidence & Reporting**: Generates case evidence logs, validation reports, and executive investigation PDFs.
  - **Tech Stack**: Python, Flask, SQLite, NetworkX, Pandas, Matplotlib, ReportLab.
  - **Quick Start**:
    ```bash
    cd CyberIntel
    pip install -r requirements.txt
    python app.py
    # Access dashboard at http://127.0.0.1:5000
    ```

---

### 2. Incident Case Studies
- [Hospital Ransomware Incident – Case Study](Incident-Case-Studies/Hospital-Ransomware-Case-Study.md)  
  *Analyzed a ransomware attack scenario targeting a hospital, including attack progression, IOCs, detection, response, and MITRE ATT&CK mapping.*

- [Account Compromise Incident – Case Study](Incident-Case-Studies/Account-Compromise-Case-Study.md)  
  *Investigated an account compromise caused by credential reuse and lack of MFA, focusing on detection, response, and prevention.*

---

### 3. Log Analysis
- [Automated Scanning Detection – Log Analysis](Log-Analysis/Automated-Scanning-Detection.md)  
  *Analyzed firewall, IDS, and application logs to identify automated reconnaissance and scanning activity.*

---

### 4. Python Security Scripts
- [Password Strength Checker (Python)](Python-Security-Scripts/password_strength_checker.py)  
  *Developed a Python script to evaluate password strength based on security policy rules.*

---

## 🛠️ Skills Demonstrated
- Cybercrime intelligence analysis & multi-source evidence fusion
- IPDR (Internet Protocol Detail Record) log forensics & telecom analysis
- Security incident analysis & SOC-style documentation
- Threat detection, automated scanning detection & log analysis
- Entity profiling, graph-based relationship discovery & timeline reconstruction
- MITRE ATT&CK framework mapping
- Python scripting & full-stack investigation platform development

---

## 📌 Notes
- Case studies are simulated scenarios based on real-world attack patterns and industry practices.
- The goal of this portfolio is to demonstrate security thinking, analysis methodology, and practical application of cybersecurity fundamentals.
