import sqlite3

from acl_manager import (
    add_permission,
    check_permission,
    revoke_permission,
    get_encrypted_fek
)

DB_PATH = "vault/vault.db"

conn = sqlite3.connect(DB_PATH)

print("=== ACL Testi ===")

file_id = 1
user_id = 1
fake_encrypted_fek = b"ornek_sifreli_fek"

add_permission(file_id, user_id, fake_encrypted_fek, "READ", conn)

permission = check_permission(file_id, user_id, conn)
print("Yetki:", permission)

encrypted_fek = get_encrypted_fek(file_id, user_id, conn)
print("FEK var mi:", encrypted_fek is not None)

revoke_permission(file_id, user_id, conn)

permission_after_revoke = check_permission(file_id, user_id, conn)
print("Revoke sonrasi yetki:", permission_after_revoke)

conn.close()