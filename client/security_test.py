import os

from common.mlkem_manager import MLKEMManager
from common.crypto_utils import encrypt_data, decrypt_data
from common.secret_key_protection import SecretKeyProtection


MASTER_PASSWORD = "correct-master-password"
WRONG_PASSWORD = "wrong-master-password"

TEST_DATA = (
    b"Website: google.com\n"
    b"Username: test1\n"
    b"Password: 12345678\n"
)


def expect_rejection(name, function):

    try:
        function()

        print(f"    {name:<45} FAILED")
        return False

    except Exception:

        print(f"    {name:<45} PASS")
        return True


def main():

    print()
    print("=" * 70)
    print("              PQC PASSWORD MANAGER SECURITY TEST")
    print("=" * 70)

    total = 0
    passed = 0

    # ========================================================
    # 1. AES-256-GCM ORIGINAL DATA
    # ========================================================

    print()
    print("[1] AES-256-GCM ORIGINAL DATA")

    aes_key = os.urandom(32)

    nonce, encrypted_data = encrypt_data(
        TEST_DATA,
        aes_key
    )

    decrypted_data = decrypt_data(
        encrypted_data,
        nonce,
        aes_key
    )

    total += 1

    if decrypted_data == TEST_DATA:

        print(
            "    Original Vault decrypt                 PASS"
        )

        passed += 1

    else:

        print(
            "    Original Vault decrypt                 FAILED"
        )

    # ========================================================
    # 2. WRONG AES KEY
    # ========================================================

    print()
    print("[2] WRONG AES KEY")

    total += 1

    if expect_rejection(
        "Wrong AES key rejected",
        lambda: decrypt_data(
            encrypted_data,
            nonce,
            os.urandom(32)
        )
    ):

        passed += 1

    # ========================================================
    # 3. TAMPER ENCRYPTED DATA
    # ========================================================

    print()
    print("[3] TAMPER ENCRYPTED DATA")

    tampered_data = bytearray(
        encrypted_data
    )

    tampered_data[0] ^= 0x01

    tampered_data = bytes(
        tampered_data
    )

    total += 1

    if expect_rejection(
        "Encrypted data tampering detected",
        lambda: decrypt_data(
            tampered_data,
            nonce,
            aes_key
        )
    ):

        passed += 1

    # ========================================================
    # 4. TAMPER NONCE
    # ========================================================

    print()
    print("[4] TAMPER AES-GCM NONCE")

    tampered_nonce = bytearray(
        nonce
    )

    tampered_nonce[0] ^= 0x01

    tampered_nonce = bytes(
        tampered_nonce
    )

    total += 1

    if expect_rejection(
        "Nonce tampering detected",
        lambda: decrypt_data(
            encrypted_data,
            tampered_nonce,
            aes_key
        )
    ):

        passed += 1

    # ========================================================
    # 5. ML-KEM CIPHERTEXT TAMPERING
    # ========================================================

    print()
    print("[5] ML-KEM CIPHERTEXT TAMPERING")

    kem = MLKEMManager()

    public_key, secret_key = (
        kem.generate_keypair()
    )

    kem_ciphertext, original_shared_secret = (
        kem.encapsulate(
            public_key
        )
    )

    # --------------------------------------------------------
    # Kiểm tra ciphertext gốc
    # --------------------------------------------------------

    recovered_shared_secret = (
        kem.decapsulate(
            kem_ciphertext
        )
    )

    total += 1

    if recovered_shared_secret == original_shared_secret:

        print(
            "    Original ML-KEM ciphertext             PASS"
        )

        passed += 1

    else:

        print(
            "    Original ML-KEM ciphertext             FAILED"
        )

    # --------------------------------------------------------
    # Sửa ciphertext
    # --------------------------------------------------------

    tampered_kem_ciphertext = bytearray(
        kem_ciphertext
    )

    tampered_kem_ciphertext[0] ^= 0x01

    tampered_kem_ciphertext = bytes(
        tampered_kem_ciphertext
    )

    tampered_shared_secret = (
        kem.decapsulate(
            tampered_kem_ciphertext
        )
    )

    total += 1

    if tampered_shared_secret != original_shared_secret:

        print(
            "    Tampered ML-KEM ciphertext detected     PASS"
        )

        passed += 1

    else:

        print(
            "    Tampered ML-KEM ciphertext detected     FAILED"
        )

    kem.close()

    # ========================================================
    # 6. ENCRYPTED ML-KEM SECRET KEY
    # ========================================================

    print()
    print("[6] ENCRYPTED ML-KEM SECRET KEY")

    (
        sk_salt,
        sk_nonce,
        encrypted_secret_key
    ) = SecretKeyProtection.protect_secret_key(
        secret_key,
        MASTER_PASSWORD
    )

    # --------------------------------------------------------
    # Đúng Master Password
    # --------------------------------------------------------

    recovered_secret_key = (
        SecretKeyProtection.recover_secret_key(
            encrypted_secret_key,
            MASTER_PASSWORD,
            sk_salt,
            sk_nonce
        )
    )

    total += 1

    if recovered_secret_key == secret_key:

        print(
            "    Correct Master Password recovery       PASS"
        )

        passed += 1

    else:

        print(
            "    Correct Master Password recovery       FAILED"
        )

    # --------------------------------------------------------
    # Sai Master Password
    # --------------------------------------------------------

    total += 1

    if expect_rejection(
        "Wrong Master Password rejected",
        lambda: SecretKeyProtection.recover_secret_key(
            encrypted_secret_key,
            WRONG_PASSWORD,
            sk_salt,
            sk_nonce
        )
    ):

        passed += 1

    # ========================================================
    # 7. TAMPER ENCRYPTED SECRET KEY
    # ========================================================

    print()
    print("[7] TAMPER ENCRYPTED SECRET KEY")

    tampered_secret_key = bytearray(
        encrypted_secret_key
    )

    tampered_secret_key[0] ^= 0x01

    tampered_secret_key = bytes(
        tampered_secret_key
    )

    total += 1

    if expect_rejection(
        "Encrypted Secret Key tampering detected",
        lambda: SecretKeyProtection.recover_secret_key(
            tampered_secret_key,
            MASTER_PASSWORD,
            sk_salt,
            sk_nonce
        )
    ):

        passed += 1

    # ========================================================
    # 8. TAMPER SCRYPT SALT
    # ========================================================

    print()
    print("[8] TAMPER SCRYPT SALT")

    tampered_salt = bytearray(
        sk_salt
    )

    tampered_salt[0] ^= 0x01

    tampered_salt = bytes(
        tampered_salt
    )

    total += 1

    if expect_rejection(
        "Scrypt salt tampering detected",
        lambda: SecretKeyProtection.recover_secret_key(
            encrypted_secret_key,
            MASTER_PASSWORD,
            tampered_salt,
            sk_nonce
        )
    ):

        passed += 1

    # ========================================================
    # 9. TAMPER SECRET KEY NONCE
    # ========================================================

    print()
    print("[9] TAMPER SECRET KEY NONCE")

    tampered_sk_nonce = bytearray(
        sk_nonce
    )

    tampered_sk_nonce[0] ^= 0x01

    tampered_sk_nonce = bytes(
        tampered_sk_nonce
    )

    total += 1

    if expect_rejection(
        "Secret Key nonce tampering detected",
        lambda: SecretKeyProtection.recover_secret_key(
            encrypted_secret_key,
            MASTER_PASSWORD,
            sk_salt,
            tampered_sk_nonce
        )
    ):

        passed += 1

    # ========================================================
    # SUMMARY
    # ========================================================

    print()
    print("=" * 70)
    print("                         SUMMARY")
    print("=" * 70)

    print()
    print(
        f"    Passed: {passed}/{total}"
    )

    print(
        f"    Failed: {total - passed}/{total}"
    )

    print()

    if passed == total:

        print("=" * 70)
        print("RESULT: SUCCESS")
        print("=" * 70)

        print()
        print(
            "Các kiểm thử tính toàn vẹn đều PASS."
        )

        print(
            "Dữ liệu bị sửa đổi được phát hiện."
        )

        print(
            "Sai Master Password được từ chối."
        )

    else:

        print("=" * 70)
        print("RESULT: FAILED")
        print("=" * 70)

    print()


if __name__ == "__main__":

    main()