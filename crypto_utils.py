import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def derive_aes_key(shared_secret: bytes) -> bytes:
    """
    Dẫn xuất khóa AES-256 từ bí mật chung ML-KEM-768
    bằng HKDF-SHA256.
    """

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"PQC-Password-Manager-AES-256",
    )

    return hkdf.derive(shared_secret)


def encrypt_data(data: bytes, aes_key: bytes) -> tuple[bytes, bytes]:
    """
    Mã hóa dữ liệu bằng AES-256-GCM.

    Returns:
        nonce: giá trị nonce
        ciphertext: dữ liệu đã mã hóa
    """

    nonce = os.urandom(12)

    aes = AESGCM(aes_key)

    ciphertext = aes.encrypt(
        nonce,
        data,
        None
    )

    return nonce, ciphertext


def decrypt_data(
    ciphertext: bytes,
    nonce: bytes,
    aes_key: bytes
) -> bytes:
    """
    Giải mã dữ liệu bằng AES-256-GCM.
    """

    aes = AESGCM(aes_key)

    return aes.decrypt(
        nonce,
        ciphertext,
        None
    )