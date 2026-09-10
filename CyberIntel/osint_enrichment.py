import sqlite3


def get_osint_data(indicator):

    conn = sqlite3.connect("database/cyberintel.db")
    cursor = conn.cursor()

    cursor.execute("""
    SELECT *
    FROM osint_data
    WHERE indicator = ?
    """, (indicator,))

    result = cursor.fetchone()

    conn.close()

    return result