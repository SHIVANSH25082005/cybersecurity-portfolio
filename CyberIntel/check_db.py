import sqlite3

print("ROOT DATABASE")
conn = sqlite3.connect("cyberintel.db")
cursor = conn.cursor()

cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
print(cursor.fetchall())

conn.close()

print("\nDATABASE FOLDER DATABASE")
conn = sqlite3.connect("database/cyberintel.db")
cursor = conn.cursor()

cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
print(cursor.fetchall())

conn.close()

import sqlite3

conn = sqlite3.connect("database/cyberintel.db")
cursor = conn.cursor()

cursor.execute("""
SELECT
complainant_name,
phone_number,
case_id
FROM complaints
""")

rows = cursor.fetchall()

for row in rows:
    print(row)

conn.close()
import sqlite3

conn = sqlite3.connect("database/cyberintel.db")
cursor = conn.cursor()

cursor.execute("""
SELECT
phone_number,
ip_address,
case_id
FROM ipdr_records
LIMIT 10
""")

for row in cursor.fetchall():
    print(row)

conn.close()

