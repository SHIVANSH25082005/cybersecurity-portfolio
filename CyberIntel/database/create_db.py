import sqlite3

connection = sqlite3.connect("database/cyberintel.db")

cursor = connection.cursor()

# Intelligence Database
cursor.execute("""
CREATE TABLE IF NOT EXISTS entities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type TEXT NOT NULL,
    entity_value TEXT NOT NULL,
    source TEXT,
    date_added TEXT,
    case_id TEXT
)
""")

# Complaint Database
cursor.execute("""
CREATE TABLE IF NOT EXISTS complaints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    complainant_name TEXT,
    phone_number TEXT,
    upi_id TEXT,
    email TEXT,
    telegram TEXT,
    website TEXT,
    complaint_details TEXT,
    date_added TEXT,
    case_id TEXT
)
""")

# IPDR Database
cursor.execute("""
CREATE TABLE IF NOT EXISTS ipdr_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    phone_number TEXT,
    ip_address TEXT,
    timestamp TEXT,
    location TEXT,
    case_id TEXT
)
""")

# Case Database
cursor.execute("""
CREATE TABLE IF NOT EXISTS cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT UNIQUE,
    case_name TEXT,
    case_type TEXT,
    investigator TEXT,
    status TEXT,
    created_date TEXT
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS evidence_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id TEXT UNIQUE,
    case_id TEXT,
    file_name TEXT,
    file_type TEXT,
    description TEXT,
    uploaded_by TEXT,
    uploaded_at TEXT,
    sha256_hash TEXT,
    status TEXT DEFAULT 'Stored'
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS evidence_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id TEXT,
    case_id TEXT,
    actor TEXT,
    action TEXT,
    event_time TEXT,
    notes TEXT
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS investigation_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT,
    note TEXT,
    officer TEXT,
    created_at TEXT
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS investigation_tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT,
    task TEXT,
    status TEXT DEFAULT 'Open',
    owner TEXT,
    due_date TEXT,
    created_at TEXT
)
""")

# ==========================
# Database Indexes
# ==========================

# Entities
cursor.execute(
    "CREATE INDEX IF NOT EXISTS idx_entities_case ON entities(case_id)"
)
cursor.execute(
    "CREATE INDEX IF NOT EXISTS idx_entities_value ON entities(entity_value)"
)
cursor.execute(
    "CREATE INDEX IF NOT EXISTS idx_entities_type ON entities(entity_type)"
)

# Complaints
cursor.execute(
    "CREATE INDEX IF NOT EXISTS idx_complaints_case ON complaints(case_id)"
)
cursor.execute(
    "CREATE INDEX IF NOT EXISTS idx_complaints_phone ON complaints(phone_number)"
)
cursor.execute(
    "CREATE INDEX IF NOT EXISTS idx_complaints_upi ON complaints(upi_id)"
)
cursor.execute(
    "CREATE INDEX IF NOT EXISTS idx_complaints_email ON complaints(email)"
)
cursor.execute(
    "CREATE INDEX IF NOT EXISTS idx_complaints_telegram ON complaints(telegram)"
)
cursor.execute(
    "CREATE INDEX IF NOT EXISTS idx_complaints_website ON complaints(website)"
)

# IPDR
cursor.execute(
    "CREATE INDEX IF NOT EXISTS idx_ipdr_case ON ipdr_records(case_id)"
)
cursor.execute(
    "CREATE INDEX IF NOT EXISTS idx_ipdr_ip ON ipdr_records(ip_address)"
)
cursor.execute(
    "CREATE INDEX IF NOT EXISTS idx_ipdr_phone ON ipdr_records(phone_number)"
)
cursor.execute(
    "CREATE INDEX IF NOT EXISTS idx_ipdr_timestamp ON ipdr_records(timestamp)"
)

# Cases
cursor.execute(
    "CREATE INDEX IF NOT EXISTS idx_cases_caseid ON cases(case_id)"
)
cursor.execute(
    "CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status)"
)
cursor.execute(
    "CREATE INDEX IF NOT EXISTS idx_cases_investigator ON cases(investigator)"
)

# Evidence
cursor.execute(
    "CREATE INDEX IF NOT EXISTS idx_evidence_case ON evidence_items(case_id)"
)
cursor.execute(
    "CREATE INDEX IF NOT EXISTS idx_evidence_evidenceid ON evidence_items(evidence_id)"
)

cursor.execute(
    "CREATE INDEX IF NOT EXISTS idx_evidence_events_case ON evidence_events(case_id)"
)
cursor.execute(
    "CREATE INDEX IF NOT EXISTS idx_evidence_events_evidenceid ON evidence_events(evidence_id)"
)

# Notes
cursor.execute(
    "CREATE INDEX IF NOT EXISTS idx_notes_case ON investigation_notes(case_id)"
)

# Tasks
cursor.execute(
    "CREATE INDEX IF NOT EXISTS idx_tasks_case ON investigation_tasks(case_id)"
)
cursor.execute(
    "CREATE INDEX IF NOT EXISTS idx_tasks_status ON investigation_tasks(status)"
)

cursor.execute(
    "CREATE INDEX IF NOT EXISTS idx_notes_case ON investigation_notes(case_id)"
)

# Tasks
cursor.execute(
    "CREATE INDEX IF NOT EXISTS idx_tasks_case ON investigation_tasks(case_id)"
)
cursor.execute(
    "CREATE INDEX IF NOT EXISTS idx_tasks_status ON investigation_tasks(status)"
)

# ==========================
# Legal Correspondence Tables
# ==========================

cursor.execute("""
CREATE TABLE IF NOT EXISTS notices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    notice_id TEXT UNIQUE,
    case_id TEXT,
    generated_date TEXT,
    organization TEXT,
    notice_type TEXT,
    related_entity_type TEXT,
    related_entity_value TEXT,
    status TEXT,
    content TEXT,
    pdf_path TEXT,
    notes TEXT
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS notice_templates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization TEXT,
    notice_type TEXT,
    template_content TEXT
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS notice_activity_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    notice_id TEXT,
    action TEXT,
    timestamp TEXT,
    actor TEXT
)
""")

# Indexes for Legal Correspondence
cursor.execute(
    "CREATE INDEX IF NOT EXISTS idx_notices_case ON notices(case_id)"
)
cursor.execute(
    "CREATE INDEX IF NOT EXISTS idx_notices_noticeid ON notices(notice_id)"
)
cursor.execute(
    "CREATE INDEX IF NOT EXISTS idx_notice_templates_org_type ON notice_templates(organization, notice_type)"
)
cursor.execute(
    "CREATE INDEX IF NOT EXISTS idx_notice_activity_notice ON notice_activity_log(notice_id)"
)

# Seed notice templates if empty
cursor.execute("SELECT COUNT(*) FROM notice_templates")
if cursor.fetchone()[0] == 0:
    default_templates = [
        # Telecom Operator
        ("Telecom Operator", "Subscriber Details", "LEGAL NOTICE FOR SUBSCRIBER DETAILS\n(Under Section 91 of CrPC / Section 94 of BNSS or applicable law)\n\nFrom:\nInvestigator: {investigator}\nPolice Station: {police_station}\nDate: {current_date}\n\nTo:\nThe Nodal Officer,\n{organization}\n\nSubject: Request for Subscriber Details of Mobile Number: {entity_value}\n\nRef: Case ID: {case_id} (Title: {case_title})\n\nDear Sir/Madam,\n\nIn connection with the investigation of the case ref: {case_id} ({case_title}), you are requested to provide customer subscriber details, CAF, and associated KYC documents for mobile number {entity_value}.\n\nSincerely,\n{investigator}\nInvestigating Officer"),
        ("Telecom Operator", "CAF", "LEGAL NOTICE FOR CAF & KYC DOCUMENTS\n(Under Section 91 of CrPC / Section 94 of BNSS or applicable law)\n\nFrom:\nInvestigator: {investigator}\nPolice Station: {police_station}\nDate: {current_date}\n\nTo:\nThe Nodal Officer,\n{organization}\n\nSubject: Request for CAF of Mobile Number: {entity_value}\n\nRef: Case ID: {case_id} (Title: {case_title})\n\nDear Sir/Madam,\n\nIn connection with the investigation of the case ref: {case_id} ({case_title}), you are requested to provide the Customer Application Form (CAF) and verification documents for mobile number {entity_value}.\n\nSincerely,\n{investigator}\nInvestigating Officer"),
        ("Telecom Operator", "CDR", "LEGAL NOTICE FOR CALL DETAIL RECORDS (CDR)\n(Under Section 91 of CrPC / Section 94 of BNSS or applicable law)\n\nFrom:\nInvestigator: {investigator}\nPolice Station: {police_station}\nDate: {current_date}\n\nTo:\nThe Nodal Officer,\n{organization}\n\nSubject: Request for CDR of Mobile Number: {entity_value}\n\nRef: Case ID: {case_id} (Title: {case_title})\n\nDear Sir/Madam,\n\nIn connection with the investigation of the case ref: {case_id} ({case_title}), you are requested to provide Call Detail Records (CDR) with Cell ID tower locations for mobile number {entity_value}.\n\nSincerely,\n{investigator}\nInvestigating Officer"),
        ("Telecom Operator", "IPDR", "LEGAL NOTICE FOR IP DETAIL RECORDS (IPDR)\n(Under Section 91 of CrPC / Section 94 of BNSS or applicable law)\n\nFrom:\nInvestigator: {investigator}\nPolice Station: {police_station}\nDate: {current_date}\n\nTo:\nThe Nodal Officer,\n{organization}\n\nSubject: Request for IPDR of Mobile Number: {entity_value}\n\nRef: Case ID: {case_id} (Title: {case_title})\n\nDear Sir/Madam,\n\nIn connection with the investigation of the case ref: {case_id} ({case_title}), you are requested to provide IP Detail Records (IPDR) for mobile number {entity_value}.\n\nSincerely,\n{investigator}\nInvestigating Officer"),
        ("Telecom Operator", "IMEI History", "LEGAL NOTICE FOR IMEI HISTORY\n(Under Section 91 of CrPC / Section 94 of BNSS or applicable law)\n\nFrom:\nInvestigator: {investigator}\nPolice Station: {police_station}\nDate: {current_date}\n\nTo:\nThe Nodal Officer,\n{organization}\n\nSubject: Request for IMEI History of Mobile Number: {entity_value}\n\nRef: Case ID: {case_id} (Title: {case_title})\n\nDear Sir/Madam,\n\nIn connection with the investigation of the case ref: {case_id} ({case_title}), you are requested to provide the handset IMEI history associated with mobile number {entity_value}.\n\nSincerely,\n{investigator}\nInvestigating Officer"),
        ("Telecom Operator", "Preservation Request", "LEGAL NOTICE FOR DATA PRESERVATION\n(Under Section 91 of CrPC / Section 94 of BNSS or applicable law)\n\nFrom:\nInvestigator: {investigator}\nPolice Station: {police_station}\nDate: {current_date}\n\nTo:\nThe Nodal Officer,\n{organization}\n\nSubject: Request for Data Preservation for Mobile Number: {entity_value}\n\nRef: Case ID: {case_id} (Title: {case_title})\n\nDear Sir/Madam,\n\nIn connection with the investigation of the case ref: {case_id} ({case_title}), you are requested to preserve all logs, subscriber records, and activity data related to mobile number {entity_value} until further directions.\n\nSincerely,\n{investigator}\nInvestigating Officer"),
        ("Telecom Operator", "Other", "LEGAL NOTICE / INVESTIGATION REQUEST\n(Under Section 91 of CrPC / Section 94 of BNSS or applicable law)\n\nFrom:\nInvestigator: {investigator}\nPolice Station: {police_station}\nDate: {current_date}\n\nTo:\nThe Nodal Officer,\n{organization}\n\nSubject: Information Request regarding mobile/entity: {entity_value}\n\nRef: Case ID: {case_id} (Title: {case_title})\n\nDear Sir/Madam,\n\nIn connection with the investigation of the case ref: {case_id} ({case_title}), you are requested to provide information regarding mobile/entity {entity_value}.\n\nSincerely,\n{investigator}\nInvestigating Officer"),

        # Bank
        ("Bank", "Account Details", "LEGAL NOTICE FOR BANK ACCOUNT DETAILS\n(Under Section 91 of CrPC / Section 94 of BNSS or applicable law)\n\nFrom:\nInvestigator: {investigator}\nPolice Station: {police_station}\nDate: {current_date}\n\nTo:\nThe Nodal Officer,\n{organization}\n\nSubject: Request for Account Details of Account: {entity_value}\n\nRef: Case ID: {case_id} (Title: {case_title})\n\nDear Sir/Madam,\n\nIn connection with the investigation of the case ref: {case_id} ({case_title}), you are requested to provide account opening details and registered information for bank account {entity_value}.\n\nSincerely,\n{investigator}\nInvestigating Officer"),
        ("Bank", "KYC", "LEGAL NOTICE FOR KYC DOCUMENTS\n(Under Section 91 of CrPC / Section 94 of BNSS or applicable law)\n\nFrom:\nInvestigator: {investigator}\nPolice Station: {police_station}\nDate: {current_date}\n\nTo:\nThe Nodal Officer,\n{organization}\n\nSubject: Request for KYC Documents of Account: {entity_value}\n\nRef: Case ID: {case_id} (Title: {case_title})\n\nDear Sir/Madam,\n\nIn connection with the investigation of the case ref: {case_id} ({case_title}), you are requested to provide copies of KYC documents (PAN, Aadhaar, Photo, etc.) for account {entity_value}.\n\nSincerely,\n{investigator}\nInvestigating Officer"),
        ("Bank", "Transaction History", "LEGAL NOTICE FOR TRANSACTION STATEMENT\n(Under Section 91 of CrPC / Section 94 of BNSS or applicable law)\n\nFrom:\nInvestigator: {investigator}\nPolice Station: {police_station}\nDate: {current_date}\n\nTo:\nThe Nodal Officer,\n{organization}\n\nSubject: Request for Transaction Statement of Account: {entity_value}\n\nRef: Case ID: {case_id} (Title: {case_title})\n\nDear Sir/Madam,\n\nIn connection with the investigation of the case ref: {case_id} ({case_title}), you are requested to provide transactional history and certified statements for bank account {entity_value}.\n\nSincerely,\n{investigator}\nInvestigating Officer"),
        ("Bank", "Freeze Account", "LEGAL NOTICE FOR BANK ACCOUNT FREEZING\n(Under Section 102 of CrPC / Section 106 of BNSS)\n\nFrom:\nInvestigator: {investigator}\nPolice Station: {police_station}\nDate: {current_date}\n\nTo:\nThe Nodal Officer,\n{organization}\n\nSubject: Freeze Order / Lien request for Account: {entity_value}\n\nRef: Case ID: {case_id} (Title: {case_title})\n\nDear Sir/Madam,\n\nIn connection with the investigation of cyber crime ref: {case_id} ({case_title}), it has been found that the proceeds of crime have been routed to bank account {entity_value}. You are hereby ordered to immediately FREEZE the account / mark LIEN on it and stop debit transactions.\n\nSincerely,\n{investigator}\nInvestigating Officer"),
        ("Bank", "Preservation Request", "LEGAL NOTICE FOR ACCOUNT DATA PRESERVATION\n(Under Section 91 of CrPC / Section 94 of BNSS or applicable law)\n\nFrom:\nInvestigator: {investigator}\nPolice Station: {police_station}\nDate: {current_date}\n\nTo:\nThe Nodal Officer,\n{organization}\n\nSubject: Request to Preserve Account Data for Account: {entity_value}\n\nRef: Case ID: {case_id} (Title: {case_title})\n\nDear Sir/Madam,\n\nIn connection with the investigation of the case ref: {case_id} ({case_title}), you are requested to preserve all records and security logs for bank account {entity_value}.\n\nSincerely,\n{investigator}\nInvestigating Officer"),
        ("Bank", "Other", "LEGAL NOTICE / INVESTIGATION REQUEST\n(Under Section 91 of CrPC / Section 94 of BNSS or applicable law)\n\nFrom:\nInvestigator: {investigator}\nPolice Station: {police_station}\nDate: {current_date}\n\nTo:\nThe Nodal Officer,\n{organization}\n\nSubject: Information Request regarding account: {entity_value}\n\nRef: Case ID: {case_id} (Title: {case_title})\n\nDear Sir/Madam,\n\nIn connection with the investigation of the case ref: {case_id} ({case_title}), you are requested to provide information regarding bank account {entity_value}.\n\nSincerely,\n{investigator}\nInvestigating Officer"),

        # Payment Gateway
        ("Payment Gateway", "Merchant Details", "LEGAL NOTICE FOR MERCHANT DETAILS\n(Under Section 91 of CrPC / Section 94 of BNSS or applicable law)\n\nFrom:\nInvestigator: {investigator}\nPolice Station: {police_station}\nDate: {current_date}\n\nTo:\nThe Nodal Officer,\n{organization}\n\nSubject: Request for Merchant Details: {entity_value}\n\nRef: Case ID: {case_id} (Title: {case_title})\n\nDear Sir/Madam,\n\nIn connection with the investigation of the case ref: {case_id} ({case_title}), you are requested to provide merchant profile, registration info, and KYC data for merchant/entity {entity_value}.\n\nSincerely,\n{investigator}\nInvestigating Officer"),
        ("Payment Gateway", "Transaction History", "LEGAL NOTICE FOR TRANSACTION STATEMENT\n(Under Section 91 of CrPC / Section 94 of BNSS or applicable law)\n\nFrom:\nInvestigator: {investigator}\nPolice Station: {police_station}\nDate: {current_date}\n\nTo:\nThe Nodal Officer,\n{organization}\n\nSubject: Request for transaction list: {entity_value}\n\nRef: Case ID: {case_id} (Title: {case_title})\n\nDear Sir/Madam,\n\nIn connection with the investigation of the case ref: {case_id} ({case_title}), you are requested to provide transaction records and logs for PG account/merchant {entity_value}.\n\nSincerely,\n{investigator}\nInvestigating Officer"),
        ("Payment Gateway", "Settlement Details", "LEGAL NOTICE FOR SETTLEMENT DETAILS\n(Under Section 91 of CrPC / Section 94 of BNSS or applicable law)\n\nFrom:\nInvestigator: {investigator}\nPolice Station: {police_station}\nDate: {current_date}\n\nTo:\nThe Nodal Officer,\n{organization}\n\nSubject: Request for Settlement details: {entity_value}\n\nRef: Case ID: {case_id} (Title: {case_title})\n\nDear Sir/Madam,\n\nIn connection with the investigation of the case ref: {case_id} ({case_title}), you are requested to provide settlement account details and transaction payouts for merchant {entity_value}.\n\nSincerely,\n{investigator}\nInvestigating Officer"),
        ("Payment Gateway", "Freeze Request", "LEGAL NOTICE FOR MERCHANT WALLET FREEZING\n(Under Section 102 of CrPC / Section 106 of BNSS)\n\nFrom:\nInvestigator: {investigator}\nPolice Station: {police_station}\nDate: {current_date}\n\nTo:\nThe Nodal Officer,\n{organization}\n\nSubject: Freeze Order for PG/Merchant Wallet: {entity_value}\n\nRef: Case ID: {case_id} (Title: {case_title})\n\nDear Sir/Madam,\n\nIn connection with the investigation of cyber crime ref: {case_id} ({case_title}), you are hereby ordered to immediately FREEZE all payouts, transactions, and balances associated with merchant wallet {entity_value}.\n\nSincerely,\n{investigator}\nInvestigating Officer"),
        ("Payment Gateway", "Preservation Request", "LEGAL NOTICE FOR DATA PRESERVATION\n(Under Section 91 of CrPC / Section 94 of BNSS or applicable law)\n\nFrom:\nInvestigator: {investigator}\nPolice Station: {police_station}\nDate: {current_date}\n\nTo:\nThe Nodal Officer,\n{organization}\n\nSubject: Request for Data Preservation: {entity_value}\n\nRef: Case ID: {case_id} (Title: {case_title})\n\nDear Sir/Madam,\n\nIn connection with the investigation of the case ref: {case_id} ({case_title}), you are requested to preserve merchant and transaction history logs for {entity_value}.\n\nSincerely,\n{investigator}\nInvestigating Officer"),
        ("Payment Gateway", "Other", "LEGAL NOTICE / INFORMATION REQUEST\n(Under Section 91 of CrPC / Section 94 of BNSS or applicable law)\n\nFrom:\nInvestigator: {investigator}\nPolice Station: {police_station}\nDate: {current_date}\n\nTo:\nThe Nodal Officer,\n{organization}\n\nSubject: Information Request regarding merchant: {entity_value}\n\nRef: Case ID: {case_id} (Title: {case_title})\n\nDear Sir/Madam,\n\nIn connection with the investigation of the case ref: {case_id} ({case_title}), you are requested to provide information regarding {entity_value}.\n\nSincerely,\n{investigator}\nInvestigating Officer"),

        # Email Provider
        ("Email Provider", "Account Information", "LEGAL NOTICE FOR EMAIL ACCOUNT DETAILS\n(Under Section 91 of CrPC / Section 94 of BNSS or applicable law)\n\nFrom:\nInvestigator: {investigator}\nPolice Station: {police_station}\nDate: {current_date}\n\nTo:\nThe Nodal Officer,\n{organization}\n\nSubject: Request for Email Account Info of email: {entity_value}\n\nRef: Case ID: {case_id} (Title: {case_title})\n\nDear Sir/Madam,\n\nIn connection with the investigation of the case ref: {case_id} ({case_title}), you are requested to provide registration information, backup email/phone, and recovery info for email account {entity_value}.\n\nSincerely,\n{investigator}\nInvestigating Officer"),
        ("Email Provider", "Login Logs", "LEGAL NOTICE FOR EMAIL LOGIN LOGS\n(Under Section 91 of CrPC / Section 94 of BNSS or applicable law)\n\nFrom:\nInvestigator: {investigator}\nPolice Station: {police_station}\nDate: {current_date}\n\nTo:\nThe Nodal Officer,\n{organization}\n\nSubject: Request for Login Logs of Email: {entity_value}\n\nRef: Case ID: {case_id} (Title: {case_title})\n\nDear Sir/Madam,\n\nIn connection with the investigation of the case ref: {case_id} ({case_title}), you are requested to provide login IP history, access logs, and associated user agent strings for email account {entity_value}.\n\nSincerely,\n{investigator}\nInvestigating Officer"),
        ("Email Provider", "Preservation Request", "LEGAL NOTICE FOR EMAIL ACCOUNT PRESERVATION\n(Under Section 91 of CrPC / Section 94 of BNSS or applicable law)\n\nFrom:\nInvestigator: {investigator}\nPolice Station: {police_station}\nDate: {current_date}\n\nTo:\nThe Nodal Officer,\n{organization}\n\nSubject: Request for Email Preservation: {entity_value}\n\nRef: Case ID: {case_id} (Title: {case_title})\n\nDear Sir/Madam,\n\nIn connection with the investigation of the case ref: {case_id} ({case_title}), you are requested to preserve all email box data, metadata, and login logs for email account {entity_value} until further directions.\n\nSincerely,\n{investigator}\nInvestigating Officer"),
        ("Email Provider", "Other", "LEGAL NOTICE / INVESTIGATION REQUEST\n(Under Section 91 of CrPC / Section 94 of BNSS or applicable law)\n\nFrom:\nInvestigator: {investigator}\nPolice Station: {police_station}\nDate: {current_date}\n\nTo:\nThe Nodal Officer,\n{organization}\n\nSubject: Information Request regarding email: {entity_value}\n\nRef: Case ID: {case_id} (Title: {case_title})\n\nDear Sir/Madam,\n\nIn connection with the investigation of the case ref: {case_id} ({case_title}), you are requested to provide information regarding email account {entity_value}.\n\nSincerely,\n{investigator}\nInvestigating Officer"),

        # Domain Registrar
        ("Domain Registrar", "Registrant Details", "LEGAL NOTICE FOR REGISTRANT DETAILS\n(Under Section 91 of CrPC / Section 94 of BNSS or applicable law)\n\nFrom:\nInvestigator: {investigator}\nPolice Station: {police_station}\nDate: {current_date}\n\nTo:\nThe Nodal Officer,\n{organization}\n\nSubject: Request for Registrant Details of Domain: {entity_value}\n\nRef: Case ID: {case_id} (Title: {case_title})\n\nDear Sir/Madam,\n\nIn connection with the investigation of the case ref: {case_id} ({case_title}), you are requested to provide registrant contact information, registration logs, payment info, and identity docs for domain {entity_value}.\n\nSincerely,\n{investigator}\nInvestigating Officer"),
        ("Domain Registrar", "Domain Information", "LEGAL NOTICE FOR DOMAIN REGISTRATION RECORDS\n(Under Section 91 of CrPC / Section 94 of BNSS or applicable law)\n\nFrom:\nInvestigator: {investigator}\nPolice Station: {police_station}\nDate: {current_date}\n\nTo:\nThe Nodal Officer,\n{organization}\n\nSubject: Request for Registration History of Domain: {entity_value}\n\nRef: Case ID: {case_id} (Title: {case_title})\n\nDear Sir/Madam,\n\nIn connection with the investigation of the case ref: {case_id} ({case_title}), you are requested to provide domain registration history and related DNS/nameserver details for domain {entity_value}.\n\nSincerely,\n{investigator}\nInvestigating Officer"),
        ("Domain Registrar", "Preservation Request", "LEGAL NOTICE FOR DOMAIN DATA PRESERVATION\n(Under Section 91 of CrPC / Section 94 of BNSS or applicable law)\n\nFrom:\nInvestigator: {investigator}\nPolice Station: {police_station}\nDate: {current_date}\n\nTo:\nThe Nodal Officer,\n{organization}\n\nSubject: Request for Data Preservation of Domain: {entity_value}\n\nRef: Case ID: {case_id} (Title: {case_title})\n\nDear Sir/Madam,\n\nIn connection with the investigation of the case ref: {case_id} ({case_title}), you are requested to preserve registrant logs, domain control histories, and registration details for domain {entity_value}.\n\nSincerely,\n{investigator}\nInvestigating Officer"),
        ("Domain Registrar", "Other", "LEGAL NOTICE / DOMAIN INFORMATION REQUEST\n(Under Section 91 of CrPC / Section 94 of BNSS or applicable law)\n\nFrom:\nInvestigator: {investigator}\nPolice Station: {police_station}\nDate: {current_date}\n\nTo:\nThe Nodal Officer,\n{organization}\n\nSubject: Information Request regarding domain: {entity_value}\n\nRef: Case ID: {case_id} (Title: {case_title})\n\nDear Sir/Madam,\n\nIn connection with the investigation of the case ref: {case_id} ({case_title}), you are requested to provide information regarding domain {entity_value}.\n\nSincerely,\n{investigator}\nInvestigating Officer"),

        # Hosting Provider
        ("Hosting Provider", "Hosting Details", "LEGAL NOTICE FOR HOSTING DETAILS\n(Under Section 91 of CrPC / Section 94 of BNSS or applicable law)\n\nFrom:\nInvestigator: {investigator}\nPolice Station: {police_station}\nDate: {current_date}\n\nTo:\nThe Nodal Officer,\n{organization}\n\nSubject: Request for Hosting Details of Server/IP/Domain: {entity_value}\n\nRef: Case ID: {case_id} (Title: {case_title})\n\nDear Sir/Madam,\n\nIn connection with the investigation of the case ref: {case_id} ({case_title}), you are requested to provide billing account information, access logs, hosting plan details, and backup contents for server/website {entity_value}.\n\nSincerely,\n{investigator}\nInvestigating Officer"),
        ("Hosting Provider", "Preservation Request", "LEGAL NOTICE FOR WEBSITE DATA PRESERVATION\n(Under Section 91 of CrPC / Section 94 of BNSS or applicable law)\n\nFrom:\nInvestigator: {investigator}\nPolice Station: {police_station}\nDate: {current_date}\n\nTo:\nThe Nodal Officer,\n{organization}\n\nSubject: Request for Server Data Preservation of: {entity_value}\n\nRef: Case ID: {case_id} (Title: {case_title})\n\nDear Sir/Madam,\n\nIn connection with the investigation of the case ref: {case_id} ({case_title}), you are requested to preserve all web files, databases, transaction history, and server logs associated with {entity_value}.\n\nSincerely,\n{investigator}\nInvestigating Officer"),
        ("Hosting Provider", "Other", "LEGAL NOTICE / INFORMATION REQUEST\n(Under Section 91 of CrPC / Section 94 of BNSS or applicable law)\n\nFrom:\nInvestigator: {investigator}\nPolice Station: {police_station}\nDate: {current_date}\n\nTo:\nThe Nodal Officer,\n{organization}\n\nSubject: Information Request regarding hosting: {entity_value}\n\nRef: Case ID: {case_id} (Title: {case_title})\n\nDear Sir/Madam,\n\nIn connection with the investigation of the case ref: {case_id} ({case_title}), you are requested to provide details for hosting site/entity {entity_value}.\n\nSincerely,\n{investigator}\nInvestigating Officer"),

        # Social Media Platform
        ("Social Media Platform", "Account Information", "LEGAL NOTICE FOR SOCIAL MEDIA ACCOUNT\n(Under Section 91 of CrPC / Section 94 of BNSS or applicable law)\n\nFrom:\nInvestigator: {investigator}\nPolice Station: {police_station}\nDate: {current_date}\n\nTo:\nThe Nodal Officer,\n{organization}\n\nSubject: Request for Account Info of Profile: {entity_value}\n\nRef: Case ID: {case_id} (Title: {case_title})\n\nDear Sir/Madam,\n\nIn connection with the investigation of the case ref: {case_id} ({case_title}), you are requested to provide account registration details, linked phone/email, registration IP, and session login logs for profile {entity_value}.\n\nSincerely,\n{investigator}\nInvestigating Officer"),
        ("Social Media Platform", "Preservation Request", "LEGAL NOTICE FOR PROFILE DATA PRESERVATION\n(Under Section 91 of CrPC / Section 94 of BNSS or applicable law)\n\nFrom:\nInvestigator: {investigator}\nPolice Station: {police_station}\nDate: {current_date}\n\nTo:\nThe Nodal Officer,\n{organization}\n\nSubject: Request for Profile Data Preservation of: {entity_value}\n\nRef: Case ID: {case_id} (Title: {case_title})\n\nDear Sir/Madam,\n\nIn connection with the investigation of the case ref: {case_id} ({case_title}), you are requested to preserve all profile contents, posts, communications, and login histories for profile {entity_value}.\n\nSincerely,\n{investigator}\nInvestigating Officer"),
        ("Social Media Platform", "Other", "LEGAL NOTICE / PROFILE INFORMATION REQUEST\n(Under Section 91 of CrPC / Section 94 of BNSS or applicable law)\n\nFrom:\nInvestigator: {investigator}\nPolice Station: {police_station}\nDate: {current_date}\n\nTo:\nThe Nodal Officer,\n{organization}\n\nSubject: Information Request regarding profile: {entity_value}\n\nRef: Case ID: {case_id} (Title: {case_title})\n\nDear Sir/Madam,\n\nIn connection with the investigation of the case ref: {case_id} ({case_title}), you are requested to provide information regarding social media handle/profile {entity_value}.\n\nSincerely,\n{investigator}\nInvestigating Officer"),

        # Other
        ("Other", "Preservation Request", "LEGAL NOTICE FOR DATA PRESERVATION\n(Under Section 91 of CrPC / Section 94 of BNSS or applicable law)\n\nFrom:\nInvestigator: {investigator}\nPolice Station: {police_station}\nDate: {current_date}\n\nTo:\nThe Nodal Officer,\n{organization}\n\nSubject: Request for Data Preservation of Entity: {entity_value}\n\nRef: Case ID: {case_id} (Title: {case_title})\n\nDear Sir/Madam,\n\nIn connection with the investigation of the case ref: {case_id} ({case_title}), you are requested to preserve all logs, subscriber records, and activity data related to entity {entity_value}.\n\nSincerely,\n{investigator}\nInvestigating Officer"),
        ("Other", "General Notice", "LEGAL NOTICE / INVESTIGATION ORDER\n(Under Section 91 of CrPC / Section 94 of BNSS or applicable law)\n\nFrom:\nInvestigator: {investigator}\nPolice Station: {police_station}\nDate: {current_date}\n\nTo:\nThe Nodal Officer,\n{organization}\n\nSubject: Request for Information regarding Entity: {entity_value}\n\nRef: Case ID: {case_id} (Title: {case_title})\n\nDear Sir/Madam,\n\nIn connection with the investigation of the case ref: {case_id} ({case_title}), you are requested to provide details and documents related to entity {entity_value}.\n\nSincerely,\n{investigator}\nInvestigating Officer"),
        ("Other", "Other", "LEGAL NOTICE / INVESTIGATION REQUEST\n(Under Section 91 of CrPC / Section 94 of BNSS or applicable law)\n\nFrom:\nInvestigator: {investigator}\nPolice Station: {police_station}\nDate: {current_date}\n\nTo:\nThe Nodal Officer,\n{organization}\n\nSubject: Information Request regarding Entity: {entity_value}\n\nRef: Case ID: {case_id} (Title: {case_title})\n\nDear Sir/Madam,\n\nIn connection with the investigation of the case ref: {case_id} ({case_title}), you are requested to provide information regarding entity {entity_value}.\n\nSincerely,\n{investigator}\nInvestigating Officer"),
    ]
    cursor.executemany(
        "INSERT INTO notice_templates (organization, notice_type, template_content) VALUES (?, ?, ?)",
        default_templates
    )

connection.commit()
connection.close()
