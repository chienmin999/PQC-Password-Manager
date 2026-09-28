import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class SecretKeyProtection:

    SALT_SIZE = 16
    NONCE_SIZE = 12
    KEY_SIZE = 32

    SCRYPT_N = 2**14
    SCRYPT_R = 8
    SCRYPT_P = 1

    @staticmethod
    def derive_key(
        master_password,
        salt
    ):
        """
        Dẫn xuất AES-256 key từ Master Password
        bằng Scrypt.
        """

        if isinstance(master_password, str):

            master_password = \
                master_password.encode("utf-8")

        kdf = Scrypt(
            salt=salt,
            length=SecretKeyProtection.KEY_SIZE,
            n=SecretKeyProtection.SCRYPT_N,
            r=SecretKeyProtection.SCRYPT_R,
            p=SecretKeyProtection.SCRYPT_P
        )

        return kdf.derive(master_password)

    @staticmethod
    def protect_secret_key(
        secret_key,
        master_password
    ):
        """
        Mã hóa ML-KEM Secret Key bằng
        khóa dẫn xuất từ Master Password.
        """

        salt = os.urandom(
            SecretKeyProtection.SALT_SIZE
        )

        nonce = os.urandom(
            SecretKeyProtection.NONCE_SIZE
        )

        encryption_key = \
            SecretKeyProtection.derive_key(
                master_password,
                salt
            )

        aes = AESGCM(encryption_key)

        encrypted_secret_key = aes.encrypt(
            nonce,
            secret_key,
            None
        )

        return (
            salt,
            nonce,
            encrypted_secret_key
        )

    @staticmethod
    def recover_secret_key(
        encrypted_secret_key,
        master_password,
        salt,
        nonce
    ):
        """
        Giải mã ML-KEM Secret Key.
        """

        encryption_key = \
            SecretKeyProtection.derive_key(
                master_password,
                salt
            )

        aes = AESGCM(encryption_key)

        secret_key = aes.decrypt(
            nonce,
            encrypted_secret_key,
            None
        )

        return secret_key