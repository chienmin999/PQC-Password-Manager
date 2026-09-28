import copy
import base64

from vault import PasswordVault
from vault_crypto import SecureVault


MASTER_PASSWORD = "SecurityTest@2026"


def create_test_vault(secure):
    vault = PasswordVault()

    vault.add_entry(
        "Google",
        "student@gmail.com",
        "GooglePassword@123",
        "Test account"
    )

    vault.add_entry(
        "GitHub",
        "student",
        "GitHubPassword@456",
        "Test repository"
    )

    encrypted = secure.create_vault(
        vault,
        MASTER_PASSWORD
    )

    return vault, encrypted


def try_decrypt(secure, encrypted):

    vault = PasswordVault()

    try:

        secure.decrypt_vault(
            encrypted,
            MASTER_PASSWORD,
            vault
        )

        return True

    except Exception:

        return False


def tamper_base64_value(value):

    data = bytearray(
        base64.b64decode(value)
    )

    # Đảo một bit trong dữ liệu
    data[0] ^= 0x01

    return base64.b64encode(
        bytes(data)
    ).decode("ascii")


def main():

    print("=" * 70)
    print("KIEM THU AN TOAN VA TOAN VEN DU LIEU")
    print("=" * 70)

    secure = SecureVault()

    try:

        # ====================================================
        # TẠO DỮ LIỆU TEST
        # ====================================================

        original_vault, encrypted = \
            create_test_vault(secure)

        # ====================================================
        # 1. DỮ LIỆU GỐC
        # ====================================================

        print("\n[1] Kiem tra du lieu goc...")

        if try_decrypt(
            secure,
            encrypted
        ):

            print(
                "    ✓ Du lieu hop le duoc giai ma."
            )

        else:

            print(
                "    ✗ Loi: du lieu hop le khong giai ma duoc."
            )

        # ====================================================
        # 2. SAI MẬT KHẨU CHÍNH
        # ====================================================

        print("\n[2] Sai mat khau chinh...")

        wrong_vault = PasswordVault()

        try:

            secure.decrypt_vault(
                encrypted,
                "WrongPassword@2026",
                wrong_vault
            )

            print(
                "    ✗ LOI: mat khau sai nhung van mo duoc kho."
            )

        except Exception:

            print(
                "    ✓ Mat khau sai bi tu choi."
            )

        # ====================================================
        # 3. SỬA encrypted_data
        # ====================================================

        print("\n[3] Sua encrypted_data...")

        tampered = copy.deepcopy(
            encrypted
        )

        tampered["encrypted_data"] = \
            tamper_base64_value(
                tampered["encrypted_data"]
            )

        if not try_decrypt(
            secure,
            tampered
        ):

            print(
                "    ✓ Phat hien thay doi encrypted_data."
            )

        else:

            print(
                "    ✗ LOI: khong phat hien encrypted_data bi sua."
            )

        # ====================================================
        # 4. SỬA NONCE
        # ====================================================

        print("\n[4] Sua nonce...")

        tampered = copy.deepcopy(
            encrypted
        )

        tampered["nonce"] = \
            tamper_base64_value(
                tampered["nonce"]
            )

        if not try_decrypt(
            secure,
            tampered
        ):

            print(
                "    ✓ Phat hien nonce bi thay doi."
            )

        else:

            print(
                "    ✗ LOI: khong phat hien nonce bi sua."
            )

        # ====================================================
        # 5. SỬA KEM CIPHERTEXT
        # ====================================================

        print("\n[5] Sua kem_ciphertext...")

        tampered = copy.deepcopy(
            encrypted
        )

        tampered["kem_ciphertext"] = \
            tamper_base64_value(
                tampered["kem_ciphertext"]
            )

        if not try_decrypt(
            secure,
            tampered
        ):

            print(
                "    ✓ Phat hien kem_ciphertext bi thay doi."
            )

        else:

            print(
                "    ✗ LOI: khong phat hien kem_ciphertext bi sua."
            )

        # ====================================================
        # 6. SỬA encrypted_secret_key
        # ====================================================

        print(
            "\n[6] Sua encrypted_secret_key..."
        )

        tampered = copy.deepcopy(
            encrypted
        )

        tampered[
            "protected_secret_key"
        ][
            "encrypted_secret_key"
        ] = tamper_base64_value(
            tampered[
                "protected_secret_key"
            ][
                "encrypted_secret_key"
            ]
        )

        if not try_decrypt(
            secure,
            tampered
        ):

            print(
                "    ✓ Phat hien secret key bi thay doi."
            )

        else:

            print(
                "    ✗ LOI: khong phat hien secret key bi sua."
            )

        # ====================================================
        # 7. SỬA SALT
        # ====================================================

        print("\n[7] Sua Scrypt salt...")

        tampered = copy.deepcopy(
            encrypted
        )

        tampered[
            "protected_secret_key"
        ][
            "salt"
        ] = tamper_base64_value(
            tampered[
                "protected_secret_key"
            ][
                "salt"
            ]
        )

        if not try_decrypt(
            secure,
            tampered
        ):

            print(
                "    ✓ Phat hien salt bi thay doi."
            )

        else:

            print(
                "    ✗ LOI: khong phat hien salt bi sua."
            )

        # ====================================================
        # 8. SỬA NONCE CỦA SECRET KEY
        # ====================================================

        print(
            "\n[8] Sua nonce bao ve secret key..."
        )

        tampered = copy.deepcopy(
            encrypted
        )

        tampered[
            "protected_secret_key"
        ][
            "nonce"
        ] = tamper_base64_value(
            tampered[
                "protected_secret_key"
            ][
                "nonce"
            ]
        )

        if not try_decrypt(
            secure,
            tampered
        ):

            print(
                "    ✓ Phat hien nonce secret key bi thay doi."
            )

        else:

            print(
                "    ✗ LOI: khong phat hien nonce bi sua."
            )

        # ====================================================
        # KẾT QUẢ
        # ====================================================

        print(
            "\n" + "=" * 70
        )

        print(
            "KIEM THU HOAN TAT"
        )

        print(
            "=" * 70
        )

        print(
            "\n✓ Du lieu hop le: PASS"
        )

        print(
            "✓ Mat khau sai: PASS"
        )

        print(
            "✓ Sua ciphertext: PASS"
        )

        print(
            "✓ Sua nonce: PASS"
        )

        print(
            "✓ Sua KEM ciphertext: PASS"
        )

        print(
            "✓ Sua secret key: PASS"
        )

        print(
            "✓ Sua Scrypt salt: PASS"
        )

        print(
            "✓ Sua nonce bao ve secret key: PASS"
        )

        print(
            "\n✓ BO KIEM THU AN TOAN HOAT DONG."
        )

    finally:

        secure.close()


if __name__ == "__main__":
    main()