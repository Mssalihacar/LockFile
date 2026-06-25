import os
import secrets
import hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

#FEK oluşturur.
def generate_fek():
    return secrets.token_bytes(32)

#kullanıcı parolasından anahtar türetir.Bu anahtar kullanıcının özel anahtarını şifrelemek için kullanılır.
def derive_master_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(password.encode())


def hash_key(master_key):
    return hashlib.sha256(master_key).digest()

#dosyayı şifreler
def encrypt_file(plaintext_bytes, fek):
    nonce = os.urandom(12)
    aesgcm = AESGCM(fek)
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)
    return nonce + ciphertext

#şifreli dosyayı çözer
def decrypt_file(encrypted_bytes, fek):
    nonce = encrypted_bytes[:12]
    ciphertext = encrypted_bytes[12:]
    aesgcm = AESGCM(fek)
    return aesgcm.decrypt(nonce, ciphertext, None)

#kayıtta rsa çifti oluşturur.public private 
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem, public_pem


def encrypt_private_key(private_pem, master_key):
    nonce = os.urandom(12)
    aesgcm = AESGCM(master_key)
    encrypted_private_key = aesgcm.encrypt(nonce, private_pem, None)
    return nonce + encrypted_private_key


def decrypt_private_key(encrypted_private_key, master_key):
    nonce = encrypted_private_key[:12]
    ciphertext = encrypted_private_key[12:]
    aesgcm = AESGCM(master_key)
    return aesgcm.decrypt(nonce, ciphertext, None)


def wrap_fek_with_public_key(fek, public_key_pem):
    public_key = serialization.load_pem_public_key(public_key_pem)

    return public_key.encrypt(
        fek,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def unwrap_fek_with_private_key(encrypted_fek, encrypted_private_key, master_key):
    private_pem = decrypt_private_key(encrypted_private_key, master_key)

    private_key = serialization.load_pem_private_key(
        private_pem,
        password=None
    )

    return private_key.decrypt(
        encrypted_fek,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )