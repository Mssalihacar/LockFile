import sqlite3
import os

DB_PATH = "vault/vault.db"

def create_database():
    os.makedirs("vault/encrypted", exist_ok=True)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        salt BLOB NOT NULL,
        key_verify_hash BLOB NOT NULL,
        public_key BLOB NOT NULL,
        encrypted_private_key BLOB NOT NULL,
        created_at TEXT NOT NULL
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT NOT NULL,
        encrypted_filename TEXT NOT NULL,
        owner_id INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (owner_id) REFERENCES users(id)
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS permissions (
        file_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        encrypted_fek BLOB NOT NULL,
        permission_level TEXT NOT NULL,
        PRIMARY KEY (file_id, user_id),
        FOREIGN KEY (file_id) REFERENCES files(id),
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    """)

    conn.commit()
    conn.close()
    print("RSA destekli veritabanı oluşturuldu.")

if __name__ == "__main__":
    create_database()