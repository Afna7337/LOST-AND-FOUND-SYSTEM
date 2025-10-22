import sqlite3

conn = sqlite3.connect('database.db')  # your DB file
cursor = conn.cursor()

# Add the column 'is_police' to the user table
cursor.execute("ALTER TABLE user ADD COLUMN is_police BOOLEAN DEFAULT 0")

conn.commit()
conn.close()

print("Column 'is_police' added successfully!")
