import sqlite3

DB_PATH = "database/cyberintel.db"

def get_record_provenance(table_name, record_id):
    """
    Returns record-level provenance and evidence type classification for any record.
    Classifications match:
    - Direct Evidence
    - Corroborated Evidence
    - Derived Evidence
    - Historical Intelligence
    - Imported Data
    - Investigator Observation
    - Automated Inference
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    provenance = {
        "origin_module": "Data Ingestion Engine",
        "source_record_type": table_name,
        "case_id": "Unknown",
        "record_identifier": f"{table_name}:{record_id}",
        "timestamp": "N/A",
        "fields_involved": [],
        "classification": "Imported Data"
    }
    
    try:
        if table_name == "ipdr_records":
            cursor.execute("""
                SELECT case_id, timestamp, ip_address, phone_number, location 
                FROM ipdr_records 
                WHERE id = ? OR phone_number = ? OR ip_address = ?
                LIMIT 1
            """, (record_id, record_id, record_id))
            row = cursor.fetchone()
            if row:
                provenance.update({
                    "origin_module": "Telecom IPDR/CDR Processor",
                    "case_id": row[0],
                    "timestamp": row[1],
                    "fields_involved": ["ip_address", "phone_number", "location"],
                    "classification": "Direct Evidence"
                })
        elif table_name == "complaints":
            cursor.execute("""
                SELECT case_id, date_added, complainant_name, phone_number, upi_id 
                FROM complaints 
                WHERE id = ? OR phone_number = ? OR upi_id = ?
                LIMIT 1
            """, (record_id, record_id, record_id))
            row = cursor.fetchone()
            if row:
                provenance.update({
                    "origin_module": "National Cyber Crime Portal Ingest",
                    "case_id": row[0],
                    "timestamp": row[1],
                    "fields_involved": ["complainant_name", "phone_number", "upi_id"],
                    "classification": "Direct Evidence"
                })
        elif table_name == "entities":
            cursor.execute("""
                SELECT case_id, date_added, entity_type, entity_value, source 
                FROM entities 
                WHERE id = ? OR entity_value = ?
                LIMIT 1
            """, (record_id, record_id))
            row = cursor.fetchone()
            if row:
                source = row[4]
                classification = "Derived Evidence"
                if source == "Pipeline":
                    classification = "Automated Inference"
                elif source in ("Manual", "Investigator"):
                    classification = "Investigator Observation"
                
                provenance.update({
                    "origin_module": "Entity Extraction Pipeline",
                    "case_id": row[0],
                    "timestamp": row[1],
                    "fields_involved": ["entity_type", "entity_value"],
                    "classification": classification
                })
        elif table_name == "evidence_items":
            cursor.execute("""
                SELECT case_id, uploaded_at, evidence_id, file_name, file_type 
                FROM evidence_items 
                WHERE id = ? OR evidence_id = ?
                LIMIT 1
            """, (record_id, record_id))
            row = cursor.fetchone()
            if row:
                provenance.update({
                    "origin_module": "Evidence Management Store",
                    "case_id": row[0],
                    "timestamp": row[1],
                    "fields_involved": ["file_name", "file_type"],
                    "classification": "Corroborated Evidence"
                })
        elif table_name == "investigation_notes":
            cursor.execute("SELECT case_id, created_at, officer FROM investigation_notes WHERE id = ?", (record_id,))
            row = cursor.fetchone()
            if row:
                provenance.update({
                    "origin_module": "Investigator Collaboration Suite",
                    "case_id": row[0],
                    "timestamp": row[1],
                    "fields_involved": ["note", "officer"],
                    "classification": "Investigator Observation"
                })
    except Exception as e:
        print(f"Provenance fetch error for {table_name}:{record_id}:", e)
    finally:
        conn.close()
        
    return provenance
