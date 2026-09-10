import sqlite3

def find_ip_relationships():

    conn = sqlite3.connect("database/cyberintel.db")
    cursor = conn.cursor()

    cursor.execute("""
    SELECT ip_address
    FROM ipdr_records
    GROUP BY ip_address
    HAVING COUNT(DISTINCT phone_number) > 1
    """)

    shared_ips = cursor.fetchall()

    results = []

    for ip in shared_ips:

        ip_address = ip[0]

        cursor.execute("""
        SELECT DISTINCT phone_number
        FROM ipdr_records
        WHERE ip_address = ?
        """, (ip_address,))

        phones = [row[0] for row in cursor.fetchall()]

        cursor.execute("""
        SELECT DISTINCT case_id
        FROM ipdr_records
        WHERE ip_address = ?
        """, (ip_address,))

        cases = [row[0] for row in cursor.fetchall()]

        results.append({
            "ip": ip_address,
            "phones": phones,
            "cases": cases
        })

    conn.close()

    return results