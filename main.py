import os
import uuid
import sqlite3
import argparse
from datetime import datetime

from cryptography.exceptions import InvalidTag

from crypto_engine import (
    generate_fek,
    encrypt_file,
    decrypt_file,
    wrap_key,
    unwrap_key
)

from user_manager import (
    register_user,
    login_user,
    get_user_id
)

from acl_manager import (
    add_permission,
    get_encrypted_fek
)

DB_PATH = "vault/vault.db"
ENCRYPTED_FOLDER = "vault/encrypted"


def upload_file(filepath, session, conn):
    if not os.path.exists(filepath):
        print("Dosya bulunamadi.")
        return

    with open(filepath, "rb") as f:
        plaintext_data = f.read()

    fek = generate_fek()
    encrypted_data = encrypt_file(plaintext_data, fek)

    encrypted_filename = str(uuid.uuid4()) + ".enc"
    encrypted_path = os.path.join(ENCRYPTED_FOLDER, encrypted_filename)

    with open(encrypted_path, "wb") as f:
        f.write(encrypted_data)

    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO files
        (filename, encrypted_filename, owner_id, created_at)
        VALUES (?, ?, ?, ?)
        """,
        (
            os.path.basename(filepath),
            encrypted_filename,
            session["user_id"],
            datetime.now().isoformat()
        )
    )

    conn.commit()
    file_id = cursor.lastrowid

    wrapped_fek = wrap_key(fek, session["master_key"])

    add_permission(
        file_id,
        session["user_id"],
        wrapped_fek,
        "OWNER",
        conn
    )

    print("Dosya sifrelendi ve yuklendi.")
    print("Dosya ID:", file_id)


def download_file(filename, session, conn):
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT id, encrypted_filename
        FROM files
        WHERE filename = ?
        """,
        (filename,)
    )

    result = cursor.fetchone()

    if result is None:
        print("Dosya bulunamadi.")
        return

    file_id, encrypted_filename = result

    wrapped_fek = get_encrypted_fek(
        file_id,
        session["user_id"],
        conn
    )

    if wrapped_fek is None:
        print("Bu dosya icin yetkiniz yok.")
        return

    try:
        fek = unwrap_key(
            wrapped_fek,
            session["master_key"]
        )

        encrypted_path = os.path.join(
            ENCRYPTED_FOLDER,
            encrypted_filename
        )

        with open(encrypted_path, "rb") as f:
            encrypted_data = f.read()

        decrypted_data = decrypt_file(
            encrypted_data,
            fek
        )

    except InvalidTag:
        print("Guvenlik hatasi: Dosya degistirilmis veya anahtar gecersiz.")
        print("AES-GCM butunluk dogrulamasi basarisiz oldu.")
        return

    except FileNotFoundError:
        print("Sifreli dosya sistemde bulunamadi.")
        return

    output_filename = "decrypted_" + filename

    with open(output_filename, "wb") as f:
        f.write(decrypted_data)

    print("Dosya basariyla cozuldu.")
    print("Kaydedilen dosya:", output_filename)


def grant_access(filename, target_username, session, conn):
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT id, owner_id
        FROM files
        WHERE filename = ?
        """,
        (filename,)
    )

    result = cursor.fetchone()

    if result is None:
        print("Dosya bulunamadi.")
        return

    file_id, owner_id = result

    if session["user_id"] != owner_id:
        print("Bu dosyanin sahibi degilsiniz.")
        return

    owner_wrapped_fek = get_encrypted_fek(
        file_id,
        session["user_id"],
        conn
    )

    try:
        fek = unwrap_key(
            owner_wrapped_fek,
            session["master_key"]
        )

    except InvalidTag:
        print("FEK cozulemedi. Anahtar veya veri bozulmus olabilir.")
        return

    target_password = input("Hedef kullanicinin parolasi: ")

    target_session = login_user(
        target_username,
        target_password,
        conn
    )

    if target_session is None:
        print("Hedef kullanici dogrulanamadi.")
        return

    wrapped_fek_for_target = wrap_key(
        fek,
        target_session["master_key"]
    )

    add_permission(
        file_id,
        target_session["user_id"],
        wrapped_fek_for_target,
        "READ",
        conn
    )

    print("Yetki basariyla verildi.")


def strong_revoke_access(filename, target_username, session, conn):
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT id, encrypted_filename, owner_id
        FROM files
        WHERE filename = ?
        """,
        (filename,)
    )

    result = cursor.fetchone()

    if result is None:
        print("Dosya bulunamadi.")
        return

    file_id, encrypted_filename, owner_id = result

    if session["user_id"] != owner_id:
        print("Bu dosyanin sahibi degilsiniz.")
        return

    target_user_id = get_user_id(target_username, conn)

    if target_user_id is None:
        print("Kullanici bulunamadi.")
        return

    owner_wrapped_fek = get_encrypted_fek(
        file_id,
        owner_id,
        conn
    )

    try:
        old_fek = unwrap_key(
            owner_wrapped_fek,
            session["master_key"]
        )

        encrypted_path = os.path.join(
            ENCRYPTED_FOLDER,
            encrypted_filename
        )

        with open(encrypted_path, "rb") as f:
            encrypted_data = f.read()

        plaintext_data = decrypt_file(
            encrypted_data,
            old_fek
        )

    except InvalidTag:
        print("Revoke basarisiz: Dosya veya FEK bozulmus.")
        return

    new_fek = generate_fek()

    new_encrypted_data = encrypt_file(
        plaintext_data,
        new_fek
    )

    with open(encrypted_path, "wb") as f:
        f.write(new_encrypted_data)

    cursor.execute(
        """
        SELECT user_id, permission_level
        FROM permissions
        WHERE file_id = ?
        """,
        (file_id,)
    )

    users = cursor.fetchall()

    cursor.execute(
        """
        DELETE FROM permissions
        WHERE file_id = ?
        """,
        (file_id,)
    )

    conn.commit()

    for current_user_id, permission_level in users:
        if current_user_id == target_user_id:
            continue

        if current_user_id == owner_id:
            current_master_key = session["master_key"]

        else:
            cursor.execute(
                """
                SELECT username
                FROM users
                WHERE id = ?
                """,
                (current_user_id,)
            )

            current_username = cursor.fetchone()[0]

            print(f"{current_username} kullanicisi icin parola giriniz:")
            temp_password = input("Parola: ")

            temp_session = login_user(
                current_username,
                temp_password,
                conn
            )

            if temp_session is None:
                print(f"{current_username} icin yeni FEK olusturulamadi.")
                continue

            current_master_key = temp_session["master_key"]

        new_wrapped_fek = wrap_key(
            new_fek,
            current_master_key
        )

        add_permission(
            file_id,
            current_user_id,
            new_wrapped_fek,
            permission_level,
            conn
        )

    print("Guclu revoke tamamlandi.")
    print("Dosya yeni FEK ile yeniden sifrelendi.")


def list_files(session, conn):
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT files.filename,
               permissions.permission_level
        FROM files
        JOIN permissions
        ON files.id = permissions.file_id
        WHERE permissions.user_id = ?
        """,
        (session["user_id"],)
    )

    results = cursor.fetchall()

    if len(results) == 0:
        print("Erisilebilen dosya yok.")
        return

    print("\n=== Erisilebilir Dosyalar ===\n")

    for filename, level in results:
        print(f"Dosya: {filename} | Yetki: {level}")


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("command")
    parser.add_argument("arg1", nargs="?")

    args = parser.parse_args()

    conn = sqlite3.connect(DB_PATH)

    if args.command == "register":
        username = input("Kullanici adi: ")
        password = input("Parola: ")

        register_user(username, password, conn)

    elif args.command == "upload":
        username = input("Kullanici adi: ")
        password = input("Parola: ")

        session = login_user(username, password, conn)

        if session is None:
            return

        upload_file(args.arg1, session, conn)

    elif args.command == "download":
        username = input("Kullanici adi: ")
        password = input("Parola: ")

        session = login_user(username, password, conn)

        if session is None:
            return

        download_file(args.arg1, session, conn)

    elif args.command == "grant":
        username = input("Kullanici adi: ")
        password = input("Parola: ")

        session = login_user(username, password, conn)

        if session is None:
            return

        target_username = input("Yetki verilecek kullanici: ")

        grant_access(
            args.arg1,
            target_username,
            session,
            conn
        )

    elif args.command == "revoke":
        username = input("Kullanici adi: ")
        password = input("Parola: ")

        session = login_user(username, password, conn)

        if session is None:
            return

        target_username = input("Yetkisi alinacak kullanici: ")

        strong_revoke_access(
            args.arg1,
            target_username,
            session,
            conn
        )

    elif args.command == "list":
        username = input("Kullanici adi: ")
        password = input("Parola: ")

        session = login_user(username, password, conn)

        if session is None:
            return

        list_files(session, conn)

    else:
        print("Gecersiz komut.")

    conn.close()


if __name__ == "__main__":
    main()