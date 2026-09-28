import base64
import os

import oqs

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from mlkem_manager import MLKEMManager
from crypto_utils import derive_aes_key, encrypt_data, decrypt_data


class SecureVault:

    VERSION = 2
    KEM_ALGORITHM = "ML-KEM-768"

    # Scrypt parameters
    SCRYPT_N = 2**14
    SCRYPT_R = 8
    SCRYPT_P = 1

    SECRET_KEY_AAD = b"PQC-Password-Manager:ML-KEM-SecretKey:v2"
    VAULT_AAD = b"PQC-Password-Manager:Vault:v2"

    def __init__(self):
        self.mlkem = MLKEMManager()

    # ==========================================================
    # PASSWORD -> KEY
    # ==========================================================

    def derive_master_key(self, master_password: str, salt: bytes) -> bytes:

        kdf = Scrypt(
            salt=salt,
            length=32,
            n=self.SCRYPT_N,
            r=self.SCRYPT_R,
            p=self.SCRYPT_P,
        )

        return kdf.derive(master_password.encode("utf-8"))

    # ==========================================================
    # PROTECT ML-KEM SECRET KEY
    # ==========================================================

    def protect_secret_key(
        self,
        secret_key: bytes,
        master_password: str
    ):

        salt = os.urandom(16)

        master_key = self.derive_master_key(
            master_password,
            salt
        )

        nonce = os.urandom(12)

        aes = AESGCM(master_key)

        encrypted_secret_key = aes.encrypt(
            nonce,
            secret_key,
            self.SECRET_KEY_AAD
        )

        return {
            "salt": base64.b64encode(salt).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "encrypted_secret_key":
                base64.b64encode(
                    encrypted_secret_key
                ).decode("ascii")
        }

    # ==========================================================
    # RESTORE ML-KEM SECRET KEY
    # ==========================================================

    def restore_secret_key(
        self,
        protected_data: dict,
        master_password: str
    ) -> bytes:

        salt = base64.b64decode(
            protected_data["salt"]
        )

        nonce = base64.b64decode(
            protected_data["nonce"]
        )

        encrypted_secret_key = base64.b64decode(
            protected_data["encrypted_secret_key"]
        )

        master_key = self.derive_master_key(
            master_password,
            salt
        )

        aes = AESGCM(master_key)

        return aes.decrypt(
            nonce,
            encrypted_secret_key,
            self.SECRET_KEY_AAD
        )

    # ==========================================================
    # CREATE NEW VAULT
    # ==========================================================

    def create_vault(self, vault, master_password: str):

        # ------------------------------------------------------
        # 1. Generate ML-KEM key pair
        # ------------------------------------------------------

        public_key, secret_key = self.mlkem.generate_keypair()

        # ------------------------------------------------------
        # 2. Protect ML-KEM secret key with master password
        # ------------------------------------------------------

        protected_secret_key = self.protect_secret_key(
            secret_key,
            master_password
        )

        # ------------------------------------------------------
        # 3. Encapsulate a fresh shared secret
        # ------------------------------------------------------

        kem_ciphertext, shared_secret = \
            self.mlkem.encapsulate(public_key)

        # ------------------------------------------------------
        # 4. Shared secret -> AES key
        # ------------------------------------------------------

        aes_key = derive_aes_key(shared_secret)

        # ------------------------------------------------------
        # 5. Encrypt password vault
        # ------------------------------------------------------

        plaintext = vault.to_json()

        nonce, encrypted_data = encrypt_data(
            plaintext,
            aes_key
        )

        # ------------------------------------------------------
        # 6. Create storage structure
        # ------------------------------------------------------

        result = {
            "version": self.VERSION,

            "kem": self.KEM_ALGORITHM,

            "kdf": "Scrypt",
            "kdf_parameters": {
                "n": self.SCRYPT_N,
                "r": self.SCRYPT_R,
                "p": self.SCRYPT_P
            },

            "vault_kdf": "HKDF-SHA256",

            "cipher": "AES-256-GCM",

            "public_key":
                base64.b64encode(
                    public_key
                ).decode("ascii"),

            "protected_secret_key":
                protected_secret_key,

            "kem_ciphertext":
                base64.b64encode(
                    kem_ciphertext
                ).decode("ascii"),

            "nonce":
                base64.b64encode(
                    nonce
                ).decode("ascii"),

            "encrypted_data":
                base64.b64encode(
                    encrypted_data
                ).decode("ascii")
        }

        return result

    # ==========================================================
    # DECRYPT VAULT
    # ==========================================================

    def decrypt_vault(
        self,
        encrypted_vault: dict,
        master_password: str,
        vault
    ):

        # ------------------------------------------------------
        # 1. Restore ML-KEM secret key
        # ------------------------------------------------------

        secret_key = self.restore_secret_key(
            encrypted_vault["protected_secret_key"],
            master_password
        )

        # ------------------------------------------------------
        # 2. Re-create ML-KEM object
        # ------------------------------------------------------

        kem = oqs.KeyEncapsulation(
            self.KEM_ALGORITHM,
            secret_key=secret_key
        )

        try:

            # --------------------------------------------------
            # 3. Read KEM ciphertext
            # --------------------------------------------------

            kem_ciphertext = base64.b64decode(
                encrypted_vault["kem_ciphertext"]
            )

            # --------------------------------------------------
            # 4. Decapsulate
            # --------------------------------------------------

            shared_secret = kem.decap_secret(
                kem_ciphertext
            )

            # --------------------------------------------------
            # 5. Shared secret -> AES key
            # --------------------------------------------------

            aes_key = derive_aes_key(
                shared_secret
            )

            # --------------------------------------------------
            # 6. Read encrypted vault
            # --------------------------------------------------

            nonce = base64.b64decode(
                encrypted_vault["nonce"]
            )

            encrypted_data = base64.b64decode(
                encrypted_vault["encrypted_data"]
            )

            # --------------------------------------------------
            # 7. Decrypt
            # --------------------------------------------------

            plaintext = decrypt_data(
                encrypted_data,
                nonce,
                aes_key
            )

            # --------------------------------------------------
            # 8. Restore vault
            # --------------------------------------------------

            vault.from_json(plaintext)

            return vault

        finally:
            kem.free()

    # ==========================================================
    # SAVE UPDATED VAULT
    # ==========================================================

    def encrypt_existing_vault(
        self,
        vault,
        encrypted_vault: dict,
        master_password: str
    ):

        # ------------------------------------------------------
        # 1. Restore ML-KEM secret key
        # ------------------------------------------------------

        secret_key = self.restore_secret_key(
            encrypted_vault["protected_secret_key"],
            master_password
        )

        kem = oqs.KeyEncapsulation(
            self.KEM_ALGORITHM,
            secret_key=secret_key
        )

        try:

            # --------------------------------------------------
            # 2. Get public key
            # --------------------------------------------------

            public_key = base64.b64decode(
                encrypted_vault["public_key"]
            )

            # --------------------------------------------------
            # 3. NEW encapsulation every time we save
            # --------------------------------------------------

            kem_ciphertext, shared_secret = \
                kem.encap_secret(public_key)

            # --------------------------------------------------
            # 4. Shared secret -> AES key
            # --------------------------------------------------

            aes_key = derive_aes_key(
                shared_secret
            )

            # --------------------------------------------------
            # 5. Encrypt current vault
            # --------------------------------------------------

            plaintext = vault.to_json()

            nonce, encrypted_data = encrypt_data(
                plaintext,
                aes_key
            )

            # --------------------------------------------------
            # 6. Update storage
            # --------------------------------------------------

            encrypted_vault["kem_ciphertext"] = \
                base64.b64encode(
                    kem_ciphertext
                ).decode("ascii")

            encrypted_vault["nonce"] = \
                base64.b64encode(
                    nonce
                ).decode("ascii")

            encrypted_vault["encrypted_data"] = \
                base64.b64encode(
                    encrypted_data
                ).decode("ascii")

            return encrypted_vault

        finally:
            kem.free()

    def close(self):
        self.mlkem.close()