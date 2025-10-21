# database_setup.py
import sqlite3

conn = sqlite3.connect('database.db')
cursor = conn.cursor()

# Xóa bảng cũ nếu tồn tại để tạo lại với cấu trúc mới
cursor.execute("DROP TABLE IF EXISTS users")
print("Old 'users' table dropped.")

# Tạo bảng users với các cột cần thiết
cursor.execute("""
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    public_key TEXT NOT NULL,
    encrypted_private_key TEXT 
);
""")
conn.commit()
conn.close()

print("✅ Database 'database.db' and table 'users' created successfully.")