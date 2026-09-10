import sqlite3

conn = sqlite3.connect("database/cyberintel.db")
cursor = conn.cursor()

cursor.execute("DROP TABLE IF EXISTS cases")

conn.commit()
conn.close()

print("Cases table removed")

