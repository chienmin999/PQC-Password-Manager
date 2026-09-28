import base64
import requests

from common.mlkem_manager import MLKEMManager
from vault.vault_crypto import VaultCrypto


SERVER_URL = "http://127.0.0.1:8000"
USER_ID = 1


def upload_vault(encrypted_vault, vault_nonce):
    """
    PC gửi Vault đã mã hóa lên Server.
    """

    data = {
        "user_id": USER_ID,
        "encrypted_vault": base64.b64encode(
            encrypted_vault
        ).decode("ascii"),
        "vault_nonce": base64.b64encode(
            vault_nonce
        ).decode("ascii")
    }

    response = requests.post(
        f"{SERVER_URL}/api/vaults",
        json=data,
        timeout=10
    )

    if response.status_code != 200:
        raise RuntimeError(
            "Upload Vault thất bại: "
            f"{response.status_code} "
            f"{response.text}"
        )

    return response.json()


def download_vault():
    """
    Phone lấy Vault đã mã hóa từ Server.
    """

    response = requests.get(
        f"{SERVER_URL}/api/vaults/{USER_ID}",
        timeout=10
    )

    if response.status_code != 200:
        raise RuntimeError(
            "Download Vault thất bại: "
            f"{response.status_code} "
            f"{response.text}"
        )

    data = response.json()

    encrypted_vault = base64.b64decode(
        data["encrypted_vault"]
    )

    vault_nonce = base64.b64decode(
        data["vault_nonce"]
    )

    return encrypted_vault, vault_nonce


def main():

    print("=" * 60)
    print("VAULT SERVER TEST")
    print("PC -> SERVER -> PHONE")
    print("=" * 60)

    # ========================================================
    # TẠO ML-KEM MANAGER
    # ========================================================

    kem = MLKEMManager()

    try:

        # ====================================================
        # 1. PC TẠO K_VAULT
        # ====================================================

        print()
        print("[1] PC - TẠO K_VAULT")

        vault_key = VaultCrypto.generate_vault_key()

        print(
            "    K_VAULT:",
            len(vault_key),
            "bytes"
        )

        # ====================================================
        # 2. TẠO PASSWORD VAULT
        # ====================================================

        print()
        print("[2] PC - TẠO PASSWORD VAULT")

        vault_data = (
            b'{"accounts":['
            b'{"site":"example.com",'
            b'"username":"sang",'
            b'"password":"MatKhau123!"},'
            b'{"site":"gmail.com",'
            b'"username":"sang@gmail.com",'
            b'"password":"EmailPass456!"}'
            b']}'
        )

        print(
            "    Plaintext Vault:"
        )

        print(
            "    ",
            vault_data.decode("utf-8")
        )

        # ====================================================
        # 3. PC MÃ HÓA VAULT
        # ====================================================

        print()
        print("[3] PC - AES-256-GCM ENCRYPT VAULT")

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
        # 4. PC UPLOAD SERVER
        # ====================================================

        print()
        print("[4] PC -> SERVER")

        result = upload_vault(
            encrypted_vault,
            vault_nonce
        )

        print(
            "    User ID:",
            result["user_id"]
        )

        print(
            "    Server status:",
            result["status"]
        )

        # ====================================================
        # 5. PHONE DOWNLOAD
        # ====================================================

        print()
        print("[5] PHONE <- SERVER")

        received_encrypted_vault, received_nonce = \
            download_vault()

        print(
            "    Encrypted Vault:",
            len(received_encrypted_vault),
            "bytes"
        )

        print(
            "    Nonce:",
            len(received_nonce),
            "bytes"
        )

        # ====================================================
        # 6. KIỂM TRA DỮ LIỆU
        # ====================================================

        print()
        print("[6] KIỂM TRA DỮ LIỆU")

        if received_encrypted_vault != encrypted_vault:

            raise RuntimeError(
                "Encrypted Vault nhận từ Server "
                "không giống dữ liệu PC gửi."
            )

        print(
            "    Encrypted Vault: OK"
        )

        if received_nonce != vault_nonce:

            raise RuntimeError(
                "Vault Nonce nhận từ Server "
                "không giống dữ liệu PC gửi."
            )

        print(
            "    Vault Nonce: OK"
        )

        # ====================================================
        # 7. PHONE GIẢI MÃ VAULT
        # ====================================================

        print()
        print("[7] PHONE - AES-256-GCM DECRYPT VAULT")

        recovered_vault = \
            VaultCrypto.decrypt_vault(
                received_encrypted_vault,
                received_nonce,
                vault_key
            )

        print(
            "    Plaintext Vault:"
        )

        print(
            "    ",
            recovered_vault.decode("utf-8")
        )

        # ====================================================
        # 8. KIỂM TRA CUỐI
        # ====================================================

        print()
        print("[8] KIỂM TRA CUỐI")

        if recovered_vault != vault_data:

            raise RuntimeError(
                "Vault khôi phục không giống "
                "Vault ban đầu."
            )

        print()
        print("    RESULT: SUCCESS")
        print()
        print(
            "    PC đã mã hóa Vault."
        )

        print(
            "    Server đã lưu Encrypted Vault."
        )

        print(
            "    Phone đã lấy Encrypted Vault."
        )

        print(
            "    Phone đã giải mã thành công Vault."
        )

        print()
        print(
            "    Server không cần biết plaintext Vault."
        )

    finally:

        kem.close()


if __name__ == "__main__":
    main()