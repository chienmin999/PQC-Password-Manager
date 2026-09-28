from cryptography.exceptions import InvalidTag

from common.mlkem_manager import MLKEMManager
from common.secret_key_protection import SecretKeyProtection


def main():

    print("=" * 60)
    print("ML-KEM SECRET KEY PROTECTION TEST")
    print("MASTER PASSWORD + SCRYPT + AES-256-GCM")
    print("=" * 60)

    kem = MLKEMManager()

    try:

        # ==================================================
        # 1. ML-KEM KEYGEN
        # ==================================================

        print()
        print("[1] ML-KEM KeyGen()")

        public_key, secret_key = \
            kem.generate_keypair()

        print(
            "    Public Key:",
            len(public_key),
            "bytes"
        )

        print(
            "    Secret Key:",
            len(secret_key),
            "bytes"
        )

        # ==================================================
        # 2. MASTER PASSWORD
        # ==================================================

        print()
        print("[2] MASTER PASSWORD")

        master_password = \
            "MasterPassword123!"

        print(
            "    Password: ********"
        )

        # ==================================================
        # 3. BẢO VỆ SECRET KEY
        # ==================================================

        print()
        print(
            "[3] BẢO VỆ ML-KEM SECRET KEY"
        )

        (
            salt,
            nonce,
            encrypted_secret_key
        ) = SecretKeyProtection.protect_secret_key(
            secret_key,
            master_password
        )

        print(
            "    Salt:",
            len(salt),
            "bytes"
        )

        print(
            "    Nonce:",
            len(nonce),
            "bytes"
        )

        print(
            "    Encrypted Secret Key:",
            len(encrypted_secret_key),
            "bytes"
        )

        # ==================================================
        # 4. KHÔI PHỤC SECRET KEY
        # ==================================================

        print()
        print(
            "[4] KHÔI PHỤC SECRET KEY"
        )

        recovered_secret_key = \
            SecretKeyProtection.recover_secret_key(
                encrypted_secret_key,
                master_password,
                salt,
                nonce
            )

        if recovered_secret_key != \
                secret_key:

            raise RuntimeError(
                "Secret Key khôi phục không đúng."
            )

        print(
            "    Secret Key khôi phục: OK"
        )

        # ==================================================
        # 5. KIỂM TRA PASSWORD SAI
        # ==================================================

        print()
        print(
            "[5] KIỂM TRA MASTER PASSWORD SAI"
        )

        try:

            SecretKeyProtection.recover_secret_key(
                encrypted_secret_key,
                "WrongPassword123!",
                salt,
                nonce
            )

            raise RuntimeError(
                "Password sai nhưng vẫn giải mã được."
            )

        except InvalidTag:

            print(
                "    Password sai bị từ chối: OK"
            )

        # ==================================================
        # 6. TAMPER ENCRYPTED SECRET KEY
        # ==================================================

        print()
        print(
            "[6] KIỂM TRA TAMPER ENCRYPTED SECRET KEY"
        )

        tampered_ciphertext = \
            bytearray(
                encrypted_secret_key
            )

        tampered_ciphertext[0] ^= 0x01

        try:

            SecretKeyProtection.recover_secret_key(
                bytes(tampered_ciphertext),
                master_password,
                salt,
                nonce
            )

            raise RuntimeError(
                "Ciphertext bị sửa nhưng "
                "không phát hiện."
            )

        except InvalidTag:

            print(
                "    Tamper Ciphertext: OK"
            )

        # ==================================================
        # 7. TAMPER NONCE
        # ==================================================

        print()
        print(
            "[7] KIỂM TRA TAMPER NONCE"
        )

        tampered_nonce = \
            bytearray(nonce)

        tampered_nonce[0] ^= 0x01

        try:

            SecretKeyProtection.recover_secret_key(
                encrypted_secret_key,
                master_password,
                salt,
                bytes(tampered_nonce)
            )

            raise RuntimeError(
                "Nonce bị sửa nhưng "
                "không phát hiện."
            )

        except InvalidTag:

            print(
                "    Tamper Nonce: OK"
            )

        # ==================================================
        # 8. TAMPER SALT
        # ==================================================

        print()
        print(
            "[8] KIỂM TRA TAMPER SALT"
        )

        tampered_salt = \
            bytearray(salt)

        tampered_salt[0] ^= 0x01

        try:

            SecretKeyProtection.recover_secret_key(
                encrypted_secret_key,
                master_password,
                bytes(tampered_salt),
                nonce
            )

            raise RuntimeError(
                "Salt bị sửa nhưng "
                "không phát hiện."
            )

        except InvalidTag:

            print(
                "    Tamper Salt: OK"
            )

        # ==================================================
        # 9. KIỂM TRA SECRET KEY THỰC SỰ DÙNG ĐƯỢC
        # ==================================================

        print()
        print(
            "[9] KIỂM TRA SECRET KEY KHÔI PHỤC"
        )

        test_ciphertext, test_shared_secret = \
            kem.encapsulate(public_key)

        recovered_shared_secret = \
            kem.decapsulate(
                test_ciphertext
            )

        if test_shared_secret != \
                recovered_shared_secret:

            raise RuntimeError(
                "Secret Key khôi phục "
                "không hoạt động đúng."
            )

        print(
            "    ML-KEM Decaps(): OK"
        )

        # ==================================================
        # 10. FINAL
        # ==================================================

        print()
        print(
            "[10] KIỂM TRA TOÀN BỘ"
        )

        print()
        print(
            "    ML-KEM Secret Key: OK"
        )

        print(
            "    Scrypt Key Derivation: OK"
        )

        print(
            "    AES-256-GCM Protection: OK"
        )

        print(
            "    Master Password đúng: OK"
        )

        print(
            "    Master Password sai: OK"
        )

        print(
            "    Ciphertext Tamper Detection: OK"
        )

        print(
            "    Nonce Tamper Detection: OK"
        )

        print(
            "    Salt Tamper Detection: OK"
        )

        print(
            "    Secret Key khôi phục hoạt động: OK"
        )

        print()
        print(
            "    RESULT: SUCCESS"
        )

    finally:

        kem.close()


if __name__ == "__main__":
    main()