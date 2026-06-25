import secrets
from crypto_engine import (
    generate_fek,
    derive_master_key,
    encrypt_file,
    decrypt_file,
    wrap_key,
    unwrap_key,
)

password = "123456"

salt = secrets.token_bytes(32)

master_key = derive_master_key(password, salt)

fek = generate_fek()

data = b"Merhaba Tasarim 2"

encrypted_data = encrypt_file(data, fek)

decrypted_data = decrypt_file(encrypted_data, fek)

wrapped_fek = wrap_key(fek, master_key)

unwrapped_fek = unwrap_key(wrapped_fek, master_key)

print("Orijinal veri:", data)

print("Cozulen veri:", decrypted_data)

print("Dosya sifreleme basarili mi:", data == decrypted_data)

print("FEK geri acildi mi:", fek == unwrapped_fek)