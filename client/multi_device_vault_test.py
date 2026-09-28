import base64
import requests

from common.mlkem_manager import MLKEMManager
from vault.vault_crypto import VaultCrypto


SERVER_URL = "http://127.0.0.1:8000"

USER_ID = 1


def register_device(device_name, kem):
    """
    Tạo ML-KEM keypair và đăng ký thiết bị với Server.
    """

    public_key, secret_key = kem.generate_keypair()

    data = {
        "user_id": USER_ID,
        "device_name": device_name,
        "kem_public_key": base64.b64encode(
            public_key
        ).decode("ascii")
    }

    response = requests.post(
        f"{SERVER_URL}/api/devices/register",
        json=data,
        timeout=10
    )

    if response.status_code != 201:

        raise RuntimeError(
            f"Đăng ký {device_name} thất bại: "
            f"{response.status_code} "
            f"{response.text}"
        )

    result = response.json()

    return (
        result["device_id"],
        public_key,
        secret_key
    )


def upload_vault(
    encrypted_vault,
    vault_nonce
):
    """
    Upload Vault đã mã hóa lên Server.
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


def get_vault():
    """
    Lấy Vault từ Server.
    """

    response = requests.get(
        f"{SERVER_URL}/api/vaults/{USER_ID}",
        timeout=10
    )

    if response.status_code != 200:

        raise RuntimeError(
            "Không lấy được Vault: "
            f"{response.status_code} "
            f"{response.text}"
        )

    data = response.json()

    return (
        data["vault_id"],

        base64.b64decode(
            data["encrypted_vault"]
        ),

        base64.b64decode(
            data["vault_nonce"]
        )
    )


def upload_vault_key(
    vault_id,
    device_id,
    kem_ciphertext,
    encrypted_vault_key,
    nonce
):
    """
    Lưu Wrapped K_VAULT cho một thiết bị.
    """

    data = {
        "device_id": device_id,

        "kem_ciphertext": base64.b64encode(
            kem_ciphertext
        ).decode("ascii"),

        "encrypted_vault_key": base64.b64encode(
            encrypted_vault_key
        ).decode("ascii"),

        "nonce": base64.b64encode(
            nonce
        ).decode("ascii")
    }

    response = requests.post(
        f"{SERVER_URL}/api/vaults/"
        f"{vault_id}/keys",
        json=data,
        timeout=10
    )

    if response.status_code != 201:

        raise RuntimeError(
            "Lưu Vault Key thất bại: "
            f"{response.status_code} "
            f"{response.text}"
        )

    return response.json()


def download_vault_key(
    vault_id,
    device_id
):
    """
    Lấy Wrapped K_VAULT dành riêng cho thiết bị.
    """

    response = requests.get(
        f"{SERVER_URL}/api/vaults/"
        f"{vault_id}/keys/"
        f"{device_id}",
        timeout=10
    )

    if response.status_code != 200:

        raise RuntimeError(
            "Không lấy được Vault Key: "
            f"{response.status_code} "
            f"{response.text}"
        )

    data = response.json()

    return (
        base64.b64decode(
            data["kem_ciphertext"]
        ),

        base64.b64decode(
            data["encrypted_vault_key"]
        ),

        base64.b64decode(
            data["nonce"]
        )
    )


def main():

    print("=" * 60)
    print("MULTI-DEVICE VAULT TEST")
    print("ONE VAULT - TWO DEVICES")
    print("=" * 60)

    phone1_kem = MLKEMManager()
    phone2_kem = MLKEMManager()
    pc_kem = MLKEMManager()

    try:

        # ====================================================
        # 1. PHONE 1
        # ====================================================

        print()
        print("[1] PHONE-1 - KeyGen()")

        (
            phone1_id,
            phone1_public_key,
            phone1_secret_key
        ) = register_device(
            "PHONE-1",
            phone1_kem
        )

        print(
            "    Device ID:",
            phone1_id
        )

        print(
            "    Public Key:",
            len(phone1_public_key),
            "bytes"
        )

        print(
            "    Secret Key:",
            len(phone1_secret_key),
            "bytes"
        )

        # ====================================================
        # 2. PHONE 2
        # ====================================================

        print()
        print("[2] PHONE-2 - KeyGen()")

        (
            phone2_id,
            phone2_public_key,
            phone2_secret_key
        ) = register_device(
            "PHONE-2",
            phone2_kem
        )

        print(
            "    Device ID:",
            phone2_id
        )

        print(
            "    Public Key:",
            len(phone2_public_key),
            "bytes"
        )

        print(
            "    Secret Key:",
            len(phone2_secret_key),
            "bytes"
        )

        # ====================================================
        # 3. PC TẠO K_VAULT
        # ====================================================

        print()
        print("[3] PC - TẠO K_VAULT")

        vault_key = \
            VaultCrypto.generate_vault_key()

        print(
            "    K_VAULT:",
            len(vault_key),
            "bytes"
        )

        # ====================================================
        # 4. TẠO VAULT MỚI
        # ====================================================

        print()
        print("[4] PC - TẠO PASSWORD VAULT")

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
            "    Vault:"
        )

        print(
            "    ",
            vault_data.decode("utf-8")
        )

        # ====================================================
        # 5. MÃ HÓA VAULT BẰNG K_VAULT
        # ====================================================

        print()
        print(
            "[5] PC - AES-256-GCM ENCRYPT VAULT"
        )

        vault_nonce, encrypted_vault = \
            VaultCrypto.encrypt_vault(
                vault_data,
                vault_key
            )

        print(
            "    Encrypted Vault:",
            len(encrypted_vault),
            "bytes"
        )

        print(
            "    Vault Nonce:",
            len(vault_nonce),
            "bytes"
        )

        # ====================================================
        # 6. UPLOAD VAULT MỚI LÊN SERVER
        # ====================================================

        print()
        print(
            "[6] PC -> SERVER: UPLOAD VAULT"
        )

        result = upload_vault(
            encrypted_vault,
            vault_nonce
        )

        print(
            "    Status:",
            result["status"]
        )

        # ====================================================
        # 7. LẤY VAULT ID
        # ====================================================

        print()
        print(
            "[7] SERVER - LẤY VAULT ID"
        )

        (
            vault_id,
            server_encrypted_vault,
            server_vault_nonce
        ) = get_vault()

        print(
            "    Vault ID:",
            vault_id
        )

        if server_encrypted_vault != \
                encrypted_vault:

            raise RuntimeError(
                "Encrypted Vault trên Server "
                "không đúng."
            )

        if server_vault_nonce != \
                vault_nonce:

            raise RuntimeError(
                "Vault Nonce trên Server "
                "không đúng."
            )

        print(
            "    Encrypted Vault: OK"
        )

        # ====================================================
        # 8. PC -> PHONE 1
        # ====================================================

        print()
        print(
            "[8] PC -> PHONE-1: Encaps()"
        )

        (
            ciphertext1,
            shared_secret1
        ) = pc_kem.encapsulate(
            phone1_public_key
        )

        print(
            "    Ciphertext:",
            len(ciphertext1),
            "bytes"
        )

        print(
            "    Shared Secret:",
            len(shared_secret1),
            "bytes"
        )

        # ====================================================
        # 9. WRAP K_VAULT PHONE 1
        # ====================================================

        print()
        print(
            "[9] WRAP K_VAULT CHO PHONE-1"
        )

        (
            nonce1,
            encrypted_vault_key1
        ) = VaultCrypto.wrap_vault_key(
            vault_key,
            shared_secret1
        )

        print(
            "    Encrypted K_VAULT:",
            len(encrypted_vault_key1),
            "bytes"
        )

        # ====================================================
        # 10. PC -> PHONE 2
        # ====================================================

        print()
        print(
            "[10] PC -> PHONE-2: Encaps()"
        )

        (
            ciphertext2,
            shared_secret2
        ) = pc_kem.encapsulate(
            phone2_public_key
        )

        print(
            "    Ciphertext:",
            len(ciphertext2),
            "bytes"
        )

        print(
            "    Shared Secret:",
            len(shared_secret2),
            "bytes"
        )

        # ====================================================
        # 11. WRAP K_VAULT PHONE 2
        # ====================================================

        print()
        print(
            "[11] WRAP K_VAULT CHO PHONE-2"
        )

        (
            nonce2,
            encrypted_vault_key2
        ) = VaultCrypto.wrap_vault_key(
            vault_key,
            shared_secret2
        )

        print(
            "    Encrypted K_VAULT:",
            len(encrypted_vault_key2),
            "bytes"
        )

        # ====================================================
        # 12. KIỂM TRA WRAPPED KEY
        # ====================================================

        print()
        print(
            "[12] KIỂM TRA WRAPPED K_VAULT"
        )

        if encrypted_vault_key1 == \
                encrypted_vault_key2:

            raise RuntimeError(
                "Wrapped K_VAULT của hai thiết bị "
                "không nên giống nhau."
            )

        print(
            "    PHONE-1 Wrapped Key"
        )

        print(
            "    != PHONE-2 Wrapped Key"
        )

        print(
            "    Kiểm tra: OK"
        )

        # ====================================================
        # 13. UPLOAD PHONE 1 KEY
        # ====================================================

        print()
        print(
            "[13] SERVER <- PHONE-1 VAULT KEY"
        )

        result1 = upload_vault_key(
            vault_id,
            phone1_id,
            ciphertext1,
            encrypted_vault_key1,
            nonce1
        )

        print(
            "    Key ID:",
            result1["key_id"]
        )

        print(
            "    Status:",
            result1["status"]
        )

        # ====================================================
        # 14. UPLOAD PHONE 2 KEY
        # ====================================================

        print()
        print(
            "[14] SERVER <- PHONE-2 VAULT KEY"
        )

        result2 = upload_vault_key(
            vault_id,
            phone2_id,
            ciphertext2,
            encrypted_vault_key2,
            nonce2
        )

        print(
            "    Key ID:",
            result2["key_id"]
        )

        print(
            "    Status:",
            result2["status"]
        )

        # ====================================================
        # 15. PHONE 1 DOWNLOAD
        # ====================================================

        print()
        print(
            "[15] PHONE-1 <- SERVER"
        )

        (
            received_ciphertext1,
            received_encrypted_key1,
            received_nonce1
        ) = download_vault_key(
            vault_id,
            phone1_id
        )

        print(
            "    Ciphertext:",
            len(received_ciphertext1),
            "bytes"
        )

        print(
            "    Encrypted K_VAULT:",
            len(received_encrypted_key1),
            "bytes"
        )

        # ====================================================
        # 16. PHONE 2 DOWNLOAD
        # ====================================================

        print()
        print(
            "[16] PHONE-2 <- SERVER"
        )

        (
            received_ciphertext2,
            received_encrypted_key2,
            received_nonce2
        ) = download_vault_key(
            vault_id,
            phone2_id
        )

        print(
            "    Ciphertext:",
            len(received_ciphertext2),
            "bytes"
        )

        print(
            "    Encrypted K_VAULT:",
            len(received_encrypted_key2),
            "bytes"
        )

        # ====================================================
        # 17. PHONE 1 DECAPS
        # ====================================================

        print()
        print(
            "[17] PHONE-1 - Decaps()"
        )

        recovered_secret1 = \
            phone1_kem.decapsulate(
                received_ciphertext1
            )

        if recovered_secret1 != \
                shared_secret1:

            raise RuntimeError(
                "Phone-1 Shared Secret không đúng."
            )

        print(
            "    Shared Secret: OK"
        )

        # ====================================================
        # 18. PHONE 2 DECAPS
        # ====================================================

        print()
        print(
            "[18] PHONE-2 - Decaps()"
        )

        recovered_secret2 = \
            phone2_kem.decapsulate(
                received_ciphertext2
            )

        if recovered_secret2 != \
                shared_secret2:

            raise RuntimeError(
                "Phone-2 Shared Secret không đúng."
            )

        print(
            "    Shared Secret: OK"
        )

        # ====================================================
        # 19. PHONE 1 UNWRAP
        # ====================================================

        print()
        print(
            "[19] PHONE-1 - UNWRAP K_VAULT"
        )

        recovered_key1 = \
            VaultCrypto.unwrap_vault_key(
                received_encrypted_key1,
                received_nonce1,
                recovered_secret1
            )

        if recovered_key1 != vault_key:

            raise RuntimeError(
                "Phone-1 không khôi phục đúng K_VAULT."
            )

        print(
            "    K_VAULT: OK"
        )

        # ====================================================
        # 20. PHONE 2 UNWRAP
        # ====================================================

        print()
        print(
            "[20] PHONE-2 - UNWRAP K_VAULT"
        )

        recovered_key2 = \
            VaultCrypto.unwrap_vault_key(
                received_encrypted_key2,
                received_nonce2,
                recovered_secret2
            )

        if recovered_key2 != vault_key:

            raise RuntimeError(
                "Phone-2 không khôi phục đúng K_VAULT."
            )

        print(
            "    K_VAULT: OK"
        )

        # ====================================================
        # 21. SO SÁNH K_VAULT
        # ====================================================

        print()
        print(
            "[21] KIỂM TRA K_VAULT"
        )

        if recovered_key1 != \
                recovered_key2:

            raise RuntimeError(
                "Hai thiết bị không có cùng K_VAULT."
            )

        print(
            "    PHONE-1 K_VAULT == PHONE-2 K_VAULT"
        )

        print(
            "    Kiểm tra: OK"
        )

        # ====================================================
        # 22. PHONE 1 DECRYPT VAULT
        # ====================================================

        print()
        print(
            "[22] PHONE-1 - DECRYPT VAULT"
        )

        recovered_vault1 = \
            VaultCrypto.decrypt_vault(
                server_encrypted_vault,
                server_vault_nonce,
                recovered_key1
            )

        print(
            "    Vault:"
        )

        print(
            "    ",
            recovered_vault1.decode("utf-8")
        )

        if recovered_vault1 != \
                vault_data:

            raise RuntimeError(
                "Phone-1 giải mã Vault không đúng."
            )

        print(
            "    Vault kiểm tra: OK"
        )

        # ====================================================
        # 23. PHONE 2 DECRYPT VAULT
        # ====================================================

        print()
        print(
            "[23] PHONE-2 - DECRYPT VAULT"
        )

        recovered_vault2 = \
            VaultCrypto.decrypt_vault(
                server_encrypted_vault,
                server_vault_nonce,
                recovered_key2
            )

        print(
            "    Vault:"
        )

        print(
            "    ",
            recovered_vault2.decode("utf-8")
        )

        if recovered_vault2 != \
                vault_data:

            raise RuntimeError(
                "Phone-2 giải mã Vault không đúng."
            )

        print(
            "    Vault kiểm tra: OK"
        )

        # ====================================================
        # 24. SO SÁNH HAI THIẾT BỊ
        # ====================================================

        print()
        print(
            "[24] KIỂM TRA HAI THIẾT BỊ"
        )

        if recovered_vault1 != \
                recovered_vault2:

            raise RuntimeError(
                "Hai thiết bị không thấy cùng Vault."
            )

        print(
            "    PHONE-1 Vault == PHONE-2 Vault"
        )

        print(
            "    Kiểm tra: OK"
        )

        # ====================================================
        # 25. FINAL
        # ====================================================

        print()
        print(
            "[25] KIỂM TRA TOÀN BỘ"
        )

        print()
        print(
            "    RESULT: SUCCESS"
        )

        print()
        print(
            "    PHONE-1 có K_VAULT: OK"
        )

        print(
            "    PHONE-2 có K_VAULT: OK"
        )

        print(
            "    Wrapped Keys khác nhau: OK"
        )

        print(
            "    PHONE-1 giải mã Vault: OK"
        )

        print(
            "    PHONE-2 giải mã Vault: OK"
        )

        print(
            "    Hai thiết bị thấy cùng Vault: OK"
        )

        print()
        print(
            "    MỘT K_VAULT ĐƯỢC CHIA SẺ AN TOÀN"
        )

        print(
            "    CHO NHIỀU THIẾT BỊ."
        )

    finally:

        pc_kem.close()
        phone1_kem.close()
        phone2_kem.close()


if __name__ == "__main__":
    main()