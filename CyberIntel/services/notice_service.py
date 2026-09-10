import os
import sqlite3
import datetime
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

# Organization to Notice Types mapping
ORGANIZATION_NOTICE_TYPES = {
    "Telecom Operator": [
        "Subscriber Details",
        "CAF",
        "CDR",
        "IPDR",
        "IMEI History",
        "Preservation Request",
        "Other"
    ],
    "Bank": [
        "Freeze Account",
        "KYC",
        "Account Details",
        "Transaction History",
        "Preservation Request",
        "Other"
    ],
    "Email Provider": [
        "Account Information",
        "Login Logs",
        "Preservation Request",
        "Other"
    ],
    "Domain Registrar": [
        "Registrant Details",
        "Domain Information",
        "Preservation Request",
        "Other"
    ],
    "Hosting Provider": [
        "Hosting Details",
        "Preservation Request",
        "Other"
    ],
    "Social Media Platform": [
        "Account Information",
        "Preservation Request",
        "Other"
    ],
    "Payment Gateway": [
        "Merchant Details",
        "Transaction History",
        "Settlement Details",
        "Freeze Request",
        "Preservation Request",
        "Other"
    ],
    "Other": [
        "Preservation Request",
        "General Notice",
        "Other"
    ]
}

def get_db_connection():
    return sqlite3.connect("database/cyberintel.db")

def get_notice_template(organization, notice_type):
    """Fetch template from the database or return a fallback default template."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT template_content 
        FROM notice_templates 
        WHERE organization = ? AND notice_type = ?
    """, (organization, notice_type))
    row = cursor.fetchone()
    conn.close()
    
    if row:
        return row[0]
    
    # Fallback default template if not in DB
    return """LEGAL NOTICE / INVESTIGATION ORDER
(Under Section 91 of CrPC / Section 94 of BNSS or applicable law)

From:
Investigator: {investigator}
Police Station: {police_station}
Date: {current_date}

To:
The Nodal Officer,
{organization}

Subject: Request for {notice_type} regarding Entity: {entity_type} - {entity_value}

Ref: Case ID: {case_id} (Title: {case_title})

Dear Sir/Madam,

In connection with the investigation of the case ref: {case_id} ({case_title}), you are hereby requested to provide details and documents related to:
Entity: {entity_value}
Request Type: {notice_type}

Please provide this information in digital format within 48 hours of receipt of this notice.

Sincerely,
{investigator}
Investigating Officer"""

def generate_notice_number():
    """Generate a unique notice number in the format NOTICE-YYYY-XXXX."""
    conn = get_db_connection()
    cursor = conn.cursor()
    current_year = datetime.datetime.now().strftime("%Y")
    
    cursor.execute("SELECT COUNT(*) FROM notices WHERE notice_id LIKE ?", (f"NOTICE-{current_year}-%",))
    count = cursor.fetchone()[0]
    conn.close()
    
    return f"NOTICE-{current_year}-{count + 1:04d}"

def save_notice(case_id, organization, notice_type, related_entity_type, related_entity_value, content, status, notes=""):
    """Save notice to DB, generate PDF, log activity."""
    notice_id = generate_notice_number()
    generated_date = datetime.datetime.now().strftime("%Y-%m-%d")
    
    # Path where PDF will be saved
    notice_dir = os.path.join("uploads", "notices", case_id)
    os.makedirs(notice_dir, exist_ok=True)
    pdf_filename = f"{notice_id}.pdf"
    pdf_path = os.path.join(notice_dir, pdf_filename)
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Generate the PDF file
        build_pdf(pdf_path, notice_id, content)
        
        cursor.execute("""
            INSERT INTO notices (
                notice_id, case_id, generated_date, organization, notice_type, 
                related_entity_type, related_entity_value, status, content, pdf_path, notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            notice_id, case_id, generated_date, organization, notice_type,
            related_entity_type, related_entity_value, status, content, pdf_path, notes
        ))
        
        # Log meaningful activities
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("""
            INSERT INTO notice_activity_log (notice_id, action, timestamp, actor)
            VALUES (?, ?, ?, ?)
        """, (notice_id, "Notice Created", timestamp, "Investigator"))
        
        cursor.execute("""
            INSERT INTO notice_activity_log (notice_id, action, timestamp, actor)
            VALUES (?, ?, ?, ?)
        """, (notice_id, "PDF Generated", timestamp, "Investigator"))
        
        if status != "Draft":
            cursor.execute("""
                INSERT INTO notice_activity_log (notice_id, action, timestamp, actor)
                VALUES (?, ?, ?, ?)
            """, (notice_id, f"Status set to {status}", timestamp, "Investigator"))
            
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()
        
    return notice_id

def update_notice(notice_id, new_status, new_notes, actor="Investigator"):
    """Update status, notes and log status transition if changed."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Check current status
        cursor.execute("SELECT status, notes FROM notices WHERE notice_id = ?", (notice_id,))
        row = cursor.fetchone()
        if not row:
            return False
            
        old_status, old_notes = row
        
        cursor.execute("""
            UPDATE notices 
            SET status = ?, notes = ?
            WHERE notice_id = ?
        """, (new_status, new_notes, notice_id))
        
        # Log status change if status changed
        if old_status != new_status:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute("""
                INSERT INTO notice_activity_log (notice_id, action, timestamp, actor)
                VALUES (?, ?, ?, ?)
            """, (notice_id, f"Status Changed: {old_status} -> {new_status}", timestamp, actor))
            
        conn.commit()
        return True
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()

def get_notice_by_id(notice_id):
    """Retrieve details of a notice."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM notices WHERE notice_id = ?", (notice_id,))
    row = cursor.fetchone()
    conn.close()
    
    if row:
        return {
            "id": row[0],
            "notice_id": row[1],
            "case_id": row[2],
            "generated_date": row[3],
            "organization": row[4],
            "notice_type": row[5],
            "related_entity_type": row[6],
            "related_entity_value": row[7],
            "status": row[8],
            "content": row[9],
            "pdf_path": row[10],
            "notes": row[11]
        }
    return None

def get_case_notices(case_id):
    """Retrieve all notices generated for a specific case."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT notice_id, generated_date, organization, notice_type, 
               related_entity_type, related_entity_value, status, notes
        FROM notices
        WHERE case_id = ?
        ORDER BY id DESC
    """, (case_id,))
    rows = cursor.fetchall()
    conn.close()
    
    notices = []
    for r in rows:
        notices.append({
            "notice_id": r[0],
            "generated_date": r[1],
            "organization": r[2],
            "notice_type": r[3],
            "related_entity_type": r[4],
            "related_entity_value": r[5],
            "status": r[6],
            "notes": r[7]
        })
    return notices

def get_notice_activity_log(notice_id):
    """Retrieve the activity log for a notice."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT action, timestamp, actor
        FROM notice_activity_log
        WHERE notice_id = ?
        ORDER BY id DESC
    """, (notice_id,))
    rows = cursor.fetchall()
    conn.close()
    
    logs = []
    for r in rows:
        logs.append({
            "action": r[0],
            "timestamp": r[1],
            "actor": r[2]
        })
    return logs

def build_pdf(pdf_path, notice_id, content):
    """Helper to generate a professional PDF from raw text content using ReportLab."""
    doc = SimpleDocTemplate(
        pdf_path,
        rightMargin=54,
        leftMargin=54,
        topMargin=54,
        bottomMargin=54
    )
    styles = getSampleStyleSheet()
    
    # Custom styles to look premium
    title_style = ParagraphStyle(
        'NoticeTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=18,
        leading=22,
        textColor=colors.HexColor('#0f172a'),
        spaceAfter=15,
        alignment=1 # Center
    )
    
    meta_style = ParagraphStyle(
        'NoticeMeta',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#475569'),
        spaceAfter=12
    )
    
    body_style = ParagraphStyle(
        'NoticeBody',
        parent=styles['BodyText'],
        fontName='Helvetica',
        fontSize=10.5,
        leading=16,
        textColor=colors.HexColor('#1e293b'),
        spaceAfter=10
    )
    
    elements = []
    
    # Title
    elements.append(Paragraph("OFFICIAL INVESTIGATION NOTICE", title_style))
    elements.append(Paragraph(f"Notice ID: {notice_id}", meta_style))
    elements.append(Spacer(1, 10))
    
    # Parse text by newlines and put them in Paragraphs
    paragraphs = content.split('\n')
    for p in paragraphs:
        p_text = p.strip()
        if p_text:
            elements.append(Paragraph(p_text.replace('\n', '<br/>'), body_style))
        else:
            elements.append(Spacer(1, 10))
            
    doc.build(elements)
