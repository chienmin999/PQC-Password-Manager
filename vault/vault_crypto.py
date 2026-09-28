import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class VaultCrypto:
    """
    Các chức năng mật mã của Password Vault.

    K_VAULT:
        Khóa AES-256 ngẫu nhiên dùng để mã hóa toàn bộ Vault.

    ML-KEM Shared Secret:
        Không dùng để mã hóa trực tiếp dữ liệu Vault.
        Shared Secret được đưa qua HKDF để tạo khóa bảo vệ K_VAULT.
    """

    AES_KEY_SIZE = 32
    NONCE_SIZE = 12

    HKDF_INFO = b"PQC-Password-Manager-Vault-Key"

    # ========================================================
    # K_VAULT
    # ========================================================

    @staticmethod
    def generate_vault_key():
        """
        Tạo K_VAULT ngẫu nhiên 256 bit.
        """

        return os.urandom(VaultCrypto.AES_KEY_SIZE)

    # ========================================================
    # DERIVE KEY FROM ML-KEM SHARED SECRET
    # ========================================================

    @staticmethod
    def derive_key_from_shared_secret(shared_secret):
        """
        Dùng ML-KEM Shared Secret để tạo
        khóa AES-256 bảo vệ K_VAULT.

        Shared Secret:
            32 bytes

        Kết quả:
            AES-256 key = 32 bytes
        """

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=VaultCrypto.AES_KEY_SIZE,
            salt=None,
            info=VaultCrypto.HKDF_INFO,
        )

        return hkdf.derive(shared_secret)

    # ========================================================
    # ENCRYPT K_VAULT
    # ========================================================

    @staticmethod
    def wrap_vault_key(vault_key, shared_secret):
        """
        Mã hóa K_VAULT bằng khóa được tạo từ
        ML-KEM Shared Secret.

        Kết quả:
            nonce
            encrypted_vault_key
        """

        encryption_key = \
            VaultCrypto.derive_key_from_shared_secret(
                shared_secret
            )

        nonce = os.urandom(
            VaultCrypto.NONCE_SIZE
        )

        aes = AESGCM(encryption_key)

        encrypted_vault_key = aes.encrypt(
            nonce,
            vault_key,
            None
        )

        return nonce, encrypted_vault_key

    # ========================================================
    # DECRYPT K_VAULT
    # ========================================================

    @staticmethod
    def unwrap_vault_key(
        encrypted_vault_key,
        nonce,
        shared_secret
    ):
        """
        Giải mã K_VAULT bằng ML-KEM Shared Secret.
        """

        encryption_key = \
            VaultCrypto.derive_key_from_shared_secret(
                shared_secret
            )

        aes = AESGCM(encryption_key)

        vault_key = aes.decrypt(
            nonce,
            encrypted_vault_key,
            None
        )

        return vault_key

    # ========================================================
    # ENCRYPT VAULT DATA
    # ========================================================

    @staticmethod
    def encrypt_vault(vault_data, vault_key):
        """
        Mã hóa dữ liệu Vault bằng K_VAULT.

        vault_data:
            bytes

        vault_key:
            AES-256 key
        """

        nonce = os.urandom(
            VaultCrypto.NONCE_SIZE
        )

        aes = AESGCM(vault_key)

        encrypted_vault = aes.encrypt(
            nonce,
            vault_data,
            None
        )

        return nonce, encrypted_vault

    # ========================================================
    # DECRYPT VAULT DATA
    # ========================================================

    @staticmethod
    def decrypt_vault(
        encrypted_vault,
        nonce,
        vault_key
    ):
        """
        Giải mã dữ liệu Vault bằng K_VAULT.
        """

        aes = AESGCM(vault_key)

        vault_data = aes.decrypt(
            nonce,
            encrypted_vault,
            None
        )

        return vault_data