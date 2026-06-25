import os
import uuid
import sqlite3
from datetime import datetime

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    send_file
)

from cryptography.exceptions import InvalidTag

from crypto_engine import (
    generate_fek,
    encrypt_file,
    decrypt_file,
    wrap_fek_with_public_key,
    unwrap_fek_with_private_key
)

from user_manager import (
    register_user,
    login_user,
    get_user_id,
    get_user_public_key,
    get_user_encrypted_private_key
)

from acl_manager import (
    add_permission,
    revoke_permission,
    get_encrypted_fek
)


app = Flask(__name__)
app.secret_key = "tasarim2_secret_key"

DB_PATH = "vault/vault.db"
ENCRYPTED_FOLDER = "vault/encrypted"


def get_db():
    """
    SQLite veritabanına bağlantı oluşturur.
    """

    return sqlite3.connect(DB_PATH)


def get_current_session():
    """
    Giriş yapan kullanıcının oturum bilgilerini döndürür.

    Oturum yoksa None döndürür.
    """

    if "user_id" not in session:
        return None

    return {
        "user_id": session["user_id"],
        "username": session["username"],
        "master_key": bytes.fromhex(session["master_key"])
    }


def get_permission(file_id, user_id, conn):
    """
    Kullanıcının belirtilen dosyadaki yetki seviyesini döndürür.

    Yetki kaydı yoksa None döndürür.
    """

    cursor = conn.cursor()

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


def get_file_info(file_id, conn):
    """
    Dosyanın adını, şifreli dosya adını ve sahibini döndürür.
    """

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT filename, encrypted_filename, owner_id
        FROM files
        WHERE id = ?
        """,
        (file_id,)
    )

    return cursor.fetchone()


@app.route("/")
def index():
    """
    Ana adrese girildiğinde kullanıcıyı giriş sayfasına yönlendirir.
    """

    if "user_id" in session:
        return redirect(url_for("dashboard"))

    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    """
    Yeni kullanıcı kaydı oluşturur.
    """

    message = ""

    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        if username == "" or password == "":
            message = "Kullanıcı adı ve parola boş bırakılamaz."

            return render_template(
                "register.html",
                message=message
            )

        conn = get_db()

        try:
            success = register_user(
                username,
                password,
                conn
            )

        except Exception as error:
            success = False
            message = f"Kullanıcı oluşturulamadı: {str(error)}"

        finally:
            conn.close()

        if success:
            return redirect(url_for("login"))

        if message == "":
            message = "Kullanıcı oluşturulamadı."

    return render_template(
        "register.html",
        message=message
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Kullanıcının kullanıcı adı ve parolasını kontrol eder.

    Giriş başarılıysa kullanıcı bilgilerini Flask session içine kaydeder.
    """

    message = ""

    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        if username == "" or password == "":
            message = "Kullanıcı adı ve parola boş bırakılamaz."

            return render_template(
                "login.html",
                message=message
            )

        conn = get_db()

        try:
            user_session = login_user(
                username,
                password,
                conn
            )

        except Exception as error:
            user_session = None
            message = f"Giriş sırasında hata oluştu: {str(error)}"

        finally:
            conn.close()

        if user_session is not None:
            session.clear()

            session["user_id"] = user_session["user_id"]
            session["username"] = user_session["username"]

            session["master_key"] = (
                user_session["master_key"].hex()
            )

            return redirect(url_for("dashboard"))

        if message == "":
            message = "Kullanıcı adı veya parola hatalı."

    return render_template(
        "login.html",
        message=message
    )


@app.route("/logout")
def logout():
    """
    Kullanıcı oturumunu kapatır.
    """

    session.clear()

    return redirect(url_for("login"))


@app.route("/dashboard")
def dashboard():
    """
    Sistemdeki bütün dosyaları listeler.

    Kullanıcının dosyada yetkisi yoksa YETKI_YOK değeri gösterilir.
    """

    user_session = get_current_session()

    if user_session is None:
        return redirect(url_for("login"))

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT
            files.id,
            files.filename,
            users.username AS owner_username,
            COALESCE(
                permissions.permission_level,
                'YETKI_YOK'
            ) AS permission_level
        FROM files

        JOIN users
        ON files.owner_id = users.id

        LEFT JOIN permissions
        ON files.id = permissions.file_id
        AND permissions.user_id = ?

        ORDER BY files.id DESC
        """,
        (user_session["user_id"],)
    )

    files = cursor.fetchall()

    conn.close()

    return render_template(
        "dashboard.html",
        username=user_session["username"],
        files=files,
        message=request.args.get("message", "")
    )


@app.route("/upload", methods=["POST"])
def upload():
    """
    Kullanıcının seçtiği dosyayı şifreleyerek sisteme yükler.

    Dosyayı yükleyen kullanıcı OWNER olarak kaydedilir.
    """

    user_session = get_current_session()

    if user_session is None:
        return redirect(url_for("login"))

    uploaded_file = request.files.get("file")

    if uploaded_file is None or uploaded_file.filename == "":
        return redirect(
            url_for(
                "dashboard",
                message="Dosya seçilmedi."
            )
        )

    plaintext_data = uploaded_file.read()

    fek = generate_fek()

    encrypted_data = encrypt_file(
        plaintext_data,
        fek
    )

    encrypted_filename = str(uuid.uuid4()) + ".enc"

    encrypted_path = os.path.join(
        ENCRYPTED_FOLDER,
        encrypted_filename
    )

    try:
        with open(encrypted_path, "wb") as file:
            file.write(encrypted_data)

    except Exception as error:
        return redirect(
            url_for(
                "dashboard",
                message=f"Şifreli dosya kaydedilemedi: {str(error)}"
            )
        )

    conn = get_db()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            INSERT INTO files
            (
                filename,
                encrypted_filename,
                owner_id,
                created_at
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                uploaded_file.filename,
                encrypted_filename,
                user_session["user_id"],
                datetime.now().isoformat()
            )
        )

        conn.commit()

        file_id = cursor.lastrowid

        owner_public_key = get_user_public_key(
            user_session["user_id"],
            conn
        )

        encrypted_fek_for_owner = wrap_fek_with_public_key(
            fek,
            owner_public_key
        )

        add_permission(
            file_id,
            user_session["user_id"],
            encrypted_fek_for_owner,
            "OWNER",
            conn
        )

    except Exception as error:
        conn.rollback()

        if os.path.exists(encrypted_path):
            os.remove(encrypted_path)

        conn.close()

        return redirect(
            url_for(
                "dashboard",
                message=f"Dosya yüklenemedi: {str(error)}"
            )
        )

    conn.close()

    return redirect(
        url_for(
            "dashboard",
            message=(
                "Dosya başarıyla şifrelendi "
                "ve sisteme yüklendi."
            )
        )
    )


@app.route("/download/<int:file_id>")
def download(file_id):
    """
    Kullanıcının yetkili olduğu dosyayı çözer ve indirir.
    """

    user_session = get_current_session()

    if user_session is None:
        return redirect(url_for("login"))

    conn = get_db()

    file_info = get_file_info(
        file_id,
        conn
    )

    if file_info is None:
        conn.close()

        return redirect(
            url_for(
                "dashboard",
                message="Dosya bulunamadı."
            )
        )

    filename, encrypted_filename, owner_id = file_info

    encrypted_fek = get_encrypted_fek(
        file_id,
        user_session["user_id"],
        conn
    )

    if encrypted_fek is None:
        conn.close()

        return redirect(
            url_for(
                "dashboard",
                message=(
                    "Bu dosyayı görüyorsunuz fakat "
                    "açma yetkiniz yok."
                )
            )
        )

    encrypted_private_key = get_user_encrypted_private_key(
        user_session["user_id"],
        conn
    )

    try:
        fek = unwrap_fek_with_private_key(
            encrypted_fek,
            encrypted_private_key,
            user_session["master_key"]
        )

        encrypted_path = os.path.join(
            ENCRYPTED_FOLDER,
            encrypted_filename
        )

        with open(encrypted_path, "rb") as file:
            encrypted_data = file.read()

        decrypted_data = decrypt_file(
            encrypted_data,
            fek
        )

    except InvalidTag:
        conn.close()

        return redirect(
            url_for(
                "dashboard",
                message=(
                    "Güvenlik hatası: Dosya değiştirilmiş, "
                    "anahtar bozulmuş veya parola geçersiz."
                )
            )
        )

    except FileNotFoundError:
        conn.close()

        return redirect(
            url_for(
                "dashboard",
                message=(
                    "Şifreli dosya sistemde bulunamadı."
                )
            )
        )

    except Exception as error:
        conn.close()

        return redirect(
            url_for(
                "dashboard",
                message=f"Dosya çözülemedi: {str(error)}"
            )
        )

    output_path = "decrypted_" + filename

    try:
        with open(output_path, "wb") as file:
            file.write(decrypted_data)

    except Exception as error:
        conn.close()

        return redirect(
            url_for(
                "dashboard",
                message=f"Dosya hazırlanamadı: {str(error)}"
            )
        )

    conn.close()

    return send_file(
        output_path,
        as_attachment=True
    )


@app.route("/update/<int:file_id>", methods=["POST"])
def update_file(file_id):
    """
    OWNER veya WRITE yetkisi bulunan kullanıcının
    dosyayı güncellemesini sağlar.
    """

    user_session = get_current_session()

    if user_session is None:
        return redirect(url_for("login"))

    new_file = request.files.get("file")

    if new_file is None or new_file.filename == "":
        return redirect(
            url_for(
                "dashboard",
                message="Güncellenecek dosya seçilmedi."
            )
        )

    conn = get_db()

    permission = get_permission(
        file_id,
        user_session["user_id"],
        conn
    )

    if permission not in ["OWNER", "WRITE"]:
        conn.close()

        return redirect(
            url_for(
                "dashboard",
                message=(
                    "Bu dosyayı güncelleme "
                    "yetkiniz yok."
                )
            )
        )

    file_info = get_file_info(
        file_id,
        conn
    )

    if file_info is None:
        conn.close()

        return redirect(
            url_for(
                "dashboard",
                message="Dosya bulunamadı."
            )
        )

    filename, encrypted_filename, owner_id = file_info

    encrypted_fek = get_encrypted_fek(
        file_id,
        user_session["user_id"],
        conn
    )

    encrypted_private_key = get_user_encrypted_private_key(
        user_session["user_id"],
        conn
    )

    try:
        fek = unwrap_fek_with_private_key(
            encrypted_fek,
            encrypted_private_key,
            user_session["master_key"]
        )

        new_plaintext_data = new_file.read()

        new_encrypted_data = encrypt_file(
            new_plaintext_data,
            fek
        )

        encrypted_path = os.path.join(
            ENCRYPTED_FOLDER,
            encrypted_filename
        )

        with open(encrypted_path, "wb") as file:
            file.write(new_encrypted_data)

    except InvalidTag:
        conn.close()

        return redirect(
            url_for(
                "dashboard",
                message=(
                    "Dosya güncellenemedi: "
                    "Anahtar veya veri hatalı."
                )
            )
        )

    except Exception as error:
        conn.close()

        return redirect(
            url_for(
                "dashboard",
                message=(
                    f"Dosya güncellenemedi: "
                    f"{str(error)}"
                )
            )
        )

    conn.close()

    return redirect(
        url_for(
            "dashboard",
            message=(
                "Dosya içeriği başarıyla güncellendi."
            )
        )
    )


@app.route("/grant", methods=["POST"])
def grant():
    """
    Dosya sahibinin başka bir kullanıcıya
    READ veya WRITE yetkisi vermesini sağlar.
    """

    user_session = get_current_session()

    if user_session is None:
        return redirect(url_for("login"))

    file_id_text = request.form.get(
        "file_id",
        ""
    ).strip()

    target_username = request.form.get(
        "target_username",
        ""
    ).strip()

    permission_level = request.form.get(
        "permission_level",
        ""
    ).strip()

    if not file_id_text.isdigit():
        return redirect(
            url_for(
                "dashboard",
                message="Geçerli bir dosya ID girin."
            )
        )

    file_id = int(file_id_text)

    if permission_level not in ["READ", "WRITE"]:
        return redirect(
            url_for(
                "dashboard",
                message="Geçersiz yetki türü."
            )
        )

    if target_username == "":
        return redirect(
            url_for(
                "dashboard",
                message="Hedef kullanıcı adı boş bırakılamaz."
            )
        )

    conn = get_db()

    file_info = get_file_info(
        file_id,
        conn
    )

    if file_info is None:
        conn.close()

        return redirect(
            url_for(
                "dashboard",
                message="Dosya bulunamadı."
            )
        )

    filename, encrypted_filename, owner_id = file_info

    if user_session["user_id"] != owner_id:
        conn.close()

        return redirect(
            url_for(
                "dashboard",
                message="Bu dosyanın sahibi değilsiniz."
            )
        )

    target_user_id = get_user_id(
        target_username,
        conn
    )

    if target_user_id is None:
        conn.close()

        return redirect(
            url_for(
                "dashboard",
                message="Hedef kullanıcı bulunamadı."
            )
        )

    if target_user_id == owner_id:
        conn.close()

        return redirect(
            url_for(
                "dashboard",
                message=(
                    "Dosya sahibine ayrıca "
                    "yetki verilemez."
                )
            )
        )

    owner_encrypted_fek = get_encrypted_fek(
        file_id,
        user_session["user_id"],
        conn
    )

    owner_encrypted_private_key = (
        get_user_encrypted_private_key(
            user_session["user_id"],
            conn
        )
    )

    target_public_key = get_user_public_key(
        target_user_id,
        conn
    )

    try:
        fek = unwrap_fek_with_private_key(
            owner_encrypted_fek,
            owner_encrypted_private_key,
            user_session["master_key"]
        )

        encrypted_fek_for_target = (
            wrap_fek_with_public_key(
                fek,
                target_public_key
            )
        )

    except InvalidTag:
        conn.close()

        return redirect(
            url_for(
                "dashboard",
                message=(
                    "FEK çözülemedi. Anahtar veya "
                    "veri bozulmuş olabilir."
                )
            )
        )

    except Exception as error:
        conn.close()

        return redirect(
            url_for(
                "dashboard",
                message=(
                    f"Yetki verilemedi: "
                    f"{str(error)}"
                )
            )
        )

    add_permission(
        file_id,
        target_user_id,
        encrypted_fek_for_target,
        permission_level,
        conn
    )

    conn.close()

    return redirect(
        url_for(
            "dashboard",
            message=(
                f"{target_username} kullanıcısına "
                f"{permission_level} yetkisi verildi."
            )
        )
    )


@app.route("/revoke", methods=["POST"])
def revoke():
    """
    Dosya sahibinin başka bir kullanıcının
    yetkisini kaldırmasını sağlar.
    """

    user_session = get_current_session()

    if user_session is None:
        return redirect(url_for("login"))

    file_id_text = request.form.get(
        "file_id",
        ""
    ).strip()

    target_username = request.form.get(
        "target_username",
        ""
    ).strip()

    if not file_id_text.isdigit():
        return redirect(
            url_for(
                "dashboard",
                message="Geçerli bir dosya ID girin."
            )
        )

    file_id = int(file_id_text)

    if target_username == "":
        return redirect(
            url_for(
                "dashboard",
                message="Hedef kullanıcı adı boş bırakılamaz."
            )
        )

    conn = get_db()

    file_info = get_file_info(
        file_id,
        conn
    )

    if file_info is None:
        conn.close()

        return redirect(
            url_for(
                "dashboard",
                message="Dosya bulunamadı."
            )
        )

    filename, encrypted_filename, owner_id = file_info

    if user_session["user_id"] != owner_id:
        conn.close()

        return redirect(
            url_for(
                "dashboard",
                message="Bu dosyanın sahibi değilsiniz."
            )
        )

    target_user_id = get_user_id(
        target_username,
        conn
    )

    if target_user_id is None:
        conn.close()

        return redirect(
            url_for(
                "dashboard",
                message="Hedef kullanıcı bulunamadı."
            )
        )

    if target_user_id == owner_id:
        conn.close()

        return redirect(
            url_for(
                "dashboard",
                message=(
                    "Dosya sahibinin yetkisi "
                    "kaldırılamaz."
                )
            )
        )

    revoke_permission(
        file_id,
        target_user_id,
        conn
    )

    conn.close()

    return redirect(
        url_for(
            "dashboard",
            message=(
                f"{target_username} kullanıcısının "
                f"yetkisi kaldırıldı."
            )
        )
    )


@app.route("/delete/<int:file_id>", methods=["POST"])
def delete_file(file_id):
    """
    Dosyayı yalnızca gerçek sahibi silebilir.

    Silme işlemi sırasında:
    - sahibin kimliği kontrol edilir,
    - dosyaya ait bütün yetkiler silinir,
    - files tablosundaki kayıt silinir,
    - şifreli .enc dosyası diskten kaldırılır.
    """

    user_session = get_current_session()

    if user_session is None:
        return redirect(url_for("login"))

    conn = get_db()
    cursor = conn.cursor()

    file_info = get_file_info(
        file_id,
        conn
    )

    if file_info is None:
        conn.close()

        return redirect(
            url_for(
                "dashboard",
                message="Silinmek istenen dosya bulunamadı."
            )
        )

    filename, encrypted_filename, owner_id = file_info

    if user_session["user_id"] != owner_id:
        conn.close()

        return redirect(
            url_for(
                "dashboard",
                message=(
                    "Bu dosyayı yalnızca "
                    "dosyanın sahibi silebilir."
                )
            )
        )

    encrypted_path = os.path.join(
        ENCRYPTED_FOLDER,
        encrypted_filename
    )

    try:
        cursor.execute(
            """
            DELETE FROM permissions
            WHERE file_id = ?
            """,
            (file_id,)
        )

        cursor.execute(
            """
            DELETE FROM files
            WHERE id = ?
            """,
            (file_id,)
        )

        conn.commit()

    except Exception as error:
        conn.rollback()
        conn.close()

        return redirect(
            url_for(
                "dashboard",
                message=(
                    f"Dosya veritabanından silinemedi: "
                    f"{str(error)}"
                )
            )
        )

    conn.close()

    try:
        if os.path.exists(encrypted_path):
            os.remove(encrypted_path)

    except Exception as error:
        return redirect(
            url_for(
                "dashboard",
                message=(
                    "Dosya kaydı silindi ancak şifreli "
                    f"dosya diskten kaldırılamadı: {str(error)}"
                )
            )
        )

    return redirect(
        url_for(
            "dashboard",
            message=(
                f"{filename} dosyası ve dosyaya ait "
                "bütün izinler başarıyla silindi."
            )
        )
    )


if __name__ == "__main__":
    os.makedirs(
        ENCRYPTED_FOLDER,
        exist_ok=True
    )

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )