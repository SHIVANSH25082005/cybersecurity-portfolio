import sqlite3

conn = sqlite3.connect("database/cyberintel.db")
cursor = conn.cursor()

cursor.execute("PRAGMA table_info(cases)")

for row in cursor.fetchall():
    print(row)

conn.close()