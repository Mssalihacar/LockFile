def check_permission(file_id, user_id, db_conn):
    cursor = db_conn.cursor()

    cursor.execute(
        """
        SELECT permission_level
        FROM permissions
        WHERE file_id = ? AND user_id = ?
        """,
        (file_id, user_id)
    )

    result = cursor.fetchone()

    if result is None:
        return None

    return result[0]


def add_permission(file_id, user_id, encrypted_fek, level, db_conn):
    cursor = db_conn.cursor()

    cursor.execute(
        """
        INSERT OR REPLACE INTO permissions
        (file_id, user_id, encrypted_fek, permission_level)
        VALUES (?, ?, ?, ?)
        """,
        (file_id, user_id, encrypted_fek, level)
    )

    db_conn.commit()
    return True


def revoke_permission(file_id, user_id, db_conn):
    cursor = db_conn.cursor()

    cursor.execute(
        """
        DELETE FROM permissions
        WHERE file_id = ? AND user_id = ?
        """,
        (file_id, user_id)
    )

    db_conn.commit()

    if cursor.rowcount == 0:
        print("Silinecek yetki bulunamadı.")
        return False

    print("Yetki başarıyla kaldırıldı.")
    return True


def get_encrypted_fek(file_id, user_id, db_conn):
    cursor = db_conn.cursor()

    cursor.execute(
        """
        SELECT encrypted_fek
        FROM permissions
        WHERE file_id = ? AND user_id = ?
        """,
        (file_id, user_id)
    )

    result = cursor.fetchone()

    if result is None:
        return None

    return result[0]