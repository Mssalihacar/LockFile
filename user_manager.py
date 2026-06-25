import secrets
from datetime import datetime

from crypto_engine import (
    derive_master_key,
    hash_key,
    generate_rsa_key_pair,
    encrypt_private_key
)


def get_user_id(username, db_conn):
    cursor = db_conn.cursor()
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    return result[0] if result else None


def get_user_public_key(user_id, db_conn):
    cursor = db_conn.cursor()
    cursor.execute("SELECT public_key FROM users WHERE id = ?", (user_id,))
    result = cursor.fetchone()
    return result[0] if result else None


def get_user_encrypted_private_key(user_id, db_conn):
    cursor = db_conn.cursor()
    cursor.execute(
        "SELECT encrypted_private_key FROM users WHERE id = ?",
        (user_id,)
    )
    result = cursor.fetchone()
    return result[0] if result else None


def register_user(username, password, db_conn):
    cursor = db_conn.cursor()

    if get_user_id(username, db_conn) is not None:
        print("Bu kullanıcı adı zaten kayıtlı.")
        return False

    salt = secrets.token_bytes(32)
    master_key = derive_master_key(password, salt)
    key_verify_hash = hash_key(master_key)

    private_pem, public_pem = generate_rsa_key_pair()
    encrypted_private_key = encrypt_private_key(private_pem, master_key)

    created_at = datetime.now().isoformat()

    cursor.execute(
        """
        INSERT INTO users
        (username, salt, key_verify_hash, public_key, encrypted_private_key, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            username,
            salt,
            key_verify_hash,
            public_pem,
            encrypted_private_key,
            created_at
        )
    )

    db_conn.commit()
    print("Kullanıcı ve RSA anahtar çifti oluşturuldu.")
    return True


def login_user(username, password, db_conn):
    cursor = db_conn.cursor()

    cursor.execute(
        """
        SELECT id, salt, key_verify_hash
        FROM users
        WHERE username = ?
        """,
        (username,)
    )

    result = cursor.fetchone()

    if result is None:
        print("Kullanıcı bulunamadı.")
        return None

    user_id, salt, stored_key_hash = result

    master_key = derive_master_key(password, salt)
    calculated_hash = hash_key(master_key)

    if calculated_hash != stored_key_hash:
        print("Hatalı parola.")
        return None

    print("Giriş başarılı.")
    return {
        "user_id": user_id,
        "username": username,
        "master_key": master_key
    }