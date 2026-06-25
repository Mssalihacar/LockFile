import os
import sys
import shutil
import sqlite3

DB_PATH = "vault/vault.db"
ENCRYPTED_FOLDER = "vault/encrypted"


def tamper_encrypted_file(file_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT filename, encrypted_filename
        FROM files
        WHERE id = ?
        """,
        (file_id,)
    )

    result = cursor.fetchone()
    conn.close()

    if result is None:
        print("Bu ID'ye ait dosya bulunamadı.")
        return

    original_filename, encrypted_filename = result

    encrypted_path = os.path.join(
        ENCRYPTED_FOLDER,
        encrypted_filename
    )

    if not os.path.exists(encrypted_path):
        print("Şifreli dosya vault/encrypted içinde bulunamadı.")
        return

    backup_path = encrypted_path + ".backup"

    if not os.path.exists(backup_path):
        shutil.copyfile(encrypted_path, backup_path)
        print("Yedek oluşturuldu:", backup_path)

    with open(encrypted_path, "rb") as f:
        data = bytearray(f.read())

    if len(data) == 0:
        print("Dosya boş olduğu için bozulamadı.")
        return

    # İlk byte'ı değiştiriyoruz.
    # Bu küçük değişiklik bile AES-GCM bütünlük kontrolünü bozacaktır.
    data[0] = data[0] ^ 255

    with open(encrypted_path, "wb") as f:
        f.write(data)

    print("Şifreli dosya kasıtlı olarak bozuldu.")
    print("Orijinal dosya adı:", original_filename)
    print("Şifreli dosya:", encrypted_filename)
    print("Şimdi web arayüzünden bu dosyayı indirmeyi dene.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Kullanım:")
        print("python tamper_file.py DOSYA_ID")
        print("Örnek:")
        print("python tamper_file.py 1")
    else:
        tamper_encrypted_file(int(sys.argv[1]))