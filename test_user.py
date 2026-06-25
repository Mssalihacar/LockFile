import sqlite3

from user_manager import register_user, login_user, get_user_id

DB_PATH = "vault/vault.db"

conn = sqlite3.connect(DB_PATH)

print("=== Kullanıcı Kayıt Testi ===")
register_user("ahmet", "123456", conn)
register_user("ayse", "abcdef", conn)

print("\n=== Aynı Kullanıcıyı Tekrar Kaydetme Testi ===")
register_user("ahmet", "999999", conn)

print("\n=== Doğru Giriş Testi ===")
session = login_user("ahmet", "123456", conn)
print(session)

print("\n=== Yanlış Parola Testi ===")
wrong_session = login_user("ahmet", "yanlis", conn)
print(wrong_session)

print("\n=== Kullanıcı ID Testi ===")
print("ahmet ID:", get_user_id("ahmet", conn))
print("ayse ID:", get_user_id("ayse", conn))

conn.close()