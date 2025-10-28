# database_setup.py
import sqlite3

conn = sqlite3.connect('database.db')
cursor = conn.cursor()

cursor.execute("DROP TABLE IF EXISTS users")
print("Old 'users' table dropped.")

# Thêm cột "profile_info TEXT"
cursor.execute("""
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    public_key TEXT NOT NULL,
    encrypted_private_key TEXT,
    profile_info TEXT 
);
""")
conn.commit()
conn.close()

print("✅ Database 'database.db' and table 'users' created successfully (with profile_info column).")