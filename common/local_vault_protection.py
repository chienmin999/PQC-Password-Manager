import os

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class LocalVaultKeyProtection:

    SALT_SIZE = 16
    NONCE_SIZE = 12
    KEY_SIZE = 32

    SCRYPT_N = 2**14
    SCRYPT_R = 8
    SCRYPT_P = 1

    # ========================================================
    # DERIVE KEY
    # ========================================================

    @staticmethod
    def derive_key(
        master_password,
        salt
    ):

        if isinstance(
            master_password,
            str
        ):

            master_password = \
                master_password.encode(
                    "utf-8"
                )

        kdf = Scrypt(
            salt=salt,
            length=LocalVaultKeyProtection.KEY_SIZE,
            n=LocalVaultKeyProtection.SCRYPT_N,
            r=LocalVaultKeyProtection.SCRYPT_R,
            p=LocalVaultKeyProtection.SCRYPT_P
        )

        return kdf.derive(
            master_password
        )

    # ========================================================
    # PROTECT K_VAULT
    # ========================================================

    @staticmethod
    def protect_vault_key(
        vault_key,
        master_password
    ):

        if len(vault_key) != \
                LocalVaultKeyProtection.KEY_SIZE:

            raise ValueError(
                "K_VAULT phải có độ dài 32 bytes."
            )

        salt = os.urandom(
            LocalVaultKeyProtection.SALT_SIZE
        )

        nonce = os.urandom(
            LocalVaultKeyProtection.NONCE_SIZE
        )

        encryption_key = \
            LocalVaultKeyProtection.derive_key(
                master_password,
                salt
            )

        aes = AESGCM(
            encryption_key
        )

        encrypted_vault_key = aes.encrypt(
            nonce,
            vault_key,
            None
        )

        return (
            salt,
            nonce,
            encrypted_vault_key
        )

    # ========================================================
    # RECOVER K_VAULT
    # ========================================================

    @staticmethod
    def recover_vault_key(
        encrypted_vault_key,
        master_password,
        salt,
        nonce
    ):

        encryption_key = \
            LocalVaultKeyProtection.derive_key(
                master_password,
                salt
            )

        aes = AESGCM(
            encryption_key
        )

        vault_key = aes.decrypt(
            nonce,
            encrypted_vault_key,
            None
        )

        if len(vault_key) != \
                LocalVaultKeyProtection.KEY_SIZE:

            raise ValueError(
                "K_VAULT sau khi khôi phục "
                "không hợp lệ."
            )

        return vault_key