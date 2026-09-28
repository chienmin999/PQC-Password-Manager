from common.mlkem_manager import MLKEMManager
from vault.vault_crypto import VaultCrypto


def main():

    print("=" * 60)
    print("VAULT CRYPTO TEST")
    print("ML-KEM + HKDF + AES-256-GCM")
    print("=" * 60)

    kem = MLKEMManager()

    try:

        # ====================================================
        # 1. PHONE KEYGEN
        # ====================================================

        print()
        print("[1] PHONE - ML-KEM KeyGen()")

        phone_public_key, phone_secret_key = \
            kem.generate_keypair()

        print(
            "    Public Key :",
            len(phone_public_key),
            "bytes"
        )

        print(
            "    Secret Key :",
            len(phone_secret_key),
            "bytes"
        )

        # ====================================================
        # 2. TẠO VAULT KEY
        # ====================================================

        print()
        print("[2] TẠO K_VAULT")

        vault_key = VaultCrypto.generate_vault_key()

        print(
            "    K_VAULT:",
            len(vault_key),
            "bytes"
        )

        print(
            "    K_VAULT:",
            vault_key.hex()
        )

        # ====================================================
        # 3. TẠO DỮ LIỆU VAULT
        # ====================================================

        print()
        print("[3] TẠO DỮ LIỆU PASSWORD VAULT")

        vault_data = (
            b'{"accounts":['
            b'{"site":"example.com",'
            b'"username":"sang",'
            b'"password":"MatKhau123!"}'
            b']}'
        )

        print(
            "    Plaintext Vault:",
            vault_data.decode("utf-8")
        )

        # ====================================================
        # 4. AES-256-GCM ENCRYPT VAULT
        # ====================================================

        print()
        print("[4] AES-256-GCM - ENCRYPT VAULT")

        vault_nonce, encrypted_vault = \
            VaultCrypto.encrypt_vault(
                vault_data,
                vault_key
            )

        print(
            "    Nonce:",
            len(vault_nonce),
            "bytes"
        )

        print(
            "    Encrypted Vault:",
            len(encrypted_vault),
            "bytes"
        )

        # ====================================================
        # 5. PC ENCAPS PHONE PUBLIC KEY
        # ====================================================

        print()
        print("[5] PC - ML-KEM Encaps()")

        ciphertext, pc_shared_secret = \
            kem.encapsulate(
                phone_public_key
            )

        print(
            "    Ciphertext:",
            len(ciphertext),
            "bytes"
        )

        print(
            "    Shared Secret:",
            len(pc_shared_secret),
            "bytes"
        )

        # ====================================================
        # 6. PC WRAP K_VAULT
        # ====================================================

        print()
        print("[6] PC - BẢO VỆ K_VAULT")

        key_nonce, encrypted_vault_key = \
            VaultCrypto.wrap_vault_key(
                vault_key,
                pc_shared_secret
            )

        print(
            "    Key Nonce:",
            len(key_nonce),
            "bytes"
        )

        print(
            "    Encrypted K_VAULT:",
            len(encrypted_vault_key),
            "bytes"
        )

        # ====================================================
        # 7. PHONE DECAPS
        # ====================================================

        print()
        print("[7] PHONE - ML-KEM Decaps()")

        phone_shared_secret = \
            kem.decapsulate(
                ciphertext
            )

        print(
            "    Shared Secret:",
            len(phone_shared_secret),
            "bytes"
        )

        if pc_shared_secret != phone_shared_secret:
            raise RuntimeError(
                "PC và Phone không có cùng Shared Secret."
            )

        print(
            "    Shared Secret kiểm tra: OK"
        )

        # ====================================================
        # 8. PHONE UNWRAP K_VAULT
        # ====================================================

        print()
        print("[8] PHONE - KHÔI PHỤC K_VAULT")

        recovered_vault_key = \
            VaultCrypto.unwrap_vault_key(
                encrypted_vault_key,
                key_nonce,
                phone_shared_secret
            )

        print(
            "    K_VAULT khôi phục:",
            len(recovered_vault_key),
            "bytes"
        )

        if recovered_vault_key != vault_key:
            raise RuntimeError(
                "K_VAULT khôi phục không giống "
                "K_VAULT ban đầu."
            )

        print(
            "    K_VAULT kiểm tra: OK"
        )

        # ====================================================
        # 9. PHONE DECRYPT VAULT
        # ====================================================

        print()
        print("[9] PHONE - DECRYPT VAULT")

        recovered_vault_data = \
            VaultCrypto.decrypt_vault(
                encrypted_vault,
                vault_nonce,
                recovered_vault_key
            )

        print(
            "    Plaintext Vault:"
        )

        print(
            "    ",
            recovered_vault_data.decode("utf-8")
        )

        # ====================================================
        # 10. FINAL CHECK
        # ====================================================

        print()
        print("[10] KIỂM TRA TOÀN BỘ")

        if recovered_vault_data != vault_data:

            raise RuntimeError(
                "Dữ liệu Vault khôi phục không giống "
                "dữ liệu ban đầu."
            )

        print()
        print("    RESULT: SUCCESS")
        print()
        print(
            "    ML-KEM Shared Secret: OK"
        )
        print(
            "    K_VAULT protection: OK"
        )
        print(
            "    AES-256-GCM Vault encryption: OK"
        )
        print(
            "    Vault decryption: OK"
        )
        print()
        print(
            "    PHONE đã khôi phục được Vault "
            "mà không cần Server biết K_VAULT."
        )

    finally:

        kem.close()


if __name__ == "__main__":
    main()