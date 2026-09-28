import base64
import requests

from common.mlkem_manager import MLKEMManager
from vault.vault_crypto import VaultCrypto


SERVER_URL = "http://127.0.0.1:8000"

USER_ID = 1

# PC đã được đăng ký trước đó.
PC_DEVICE_ID = 3


def register_phone(kem):
    """
    Tạo một Phone mới và đăng ký Public Key với Server.
    """

    public_key, secret_key = kem.generate_keypair()

    data = {
        "user_id": USER_ID,
        "device_name": "PHONE-VAULT",
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
            "Đăng ký Phone thất bại: "
            f"{response.status_code} "
            f"{response.text}"
        )

    result = response.json()

    return (
        result["device_id"],
        public_key,
        secret_key
    )


def get_phone_public_key(device_id):

    response = requests.get(
        f"{SERVER_URL}/api/devices/{device_id}",
        timeout=10
    )

    if response.status_code != 200:

        raise RuntimeError(
            "Không lấy được Public Key Phone: "
            f"{response.status_code} "
            f"{response.text}"
        )

    data = response.json()

    return base64.b64decode(
        data["kem_public_key"]
    )


def upload_vault(
    encrypted_vault,
    vault_nonce
):

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
            "Upload Vault Key thất bại: "
            f"{response.status_code} "
            f"{response.text}"
        )

    return response.json()


def download_vault_key(
    vault_id,
    device_id
):

    response = requests.get(
        f"{SERVER_URL}/api/vaults/"
        f"{vault_id}/keys/"
        f"{device_id}",
        timeout=10
    )

    if response.status_code != 200:

        raise RuntimeError(
            "Download Vault Key thất bại: "
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
    print("VAULT KEY SERVER TEST")
    print("ML-KEM + K_VAULT + SERVER")
    print("=" * 60)

    pc_kem = MLKEMManager()
    phone_kem = MLKEMManager()

    try:

        # ====================================================
        # 1. PHONE KEYGEN
        # ====================================================

        print()
        print("[1] PHONE - KeyGen()")

        (
            phone_device_id,
            phone_public_key,
            phone_secret_key
        ) = register_phone(phone_kem)

        print(
            "    Device ID:",
            phone_device_id
        )

        print(
            "    Public Key:",
            len(phone_public_key),
            "bytes"
        )

        print(
            "    Secret Key:",
            len(phone_secret_key),
            "bytes"
        )

        # ====================================================
        # 2. PC LẤY PUBLIC KEY
        # ====================================================

        print()
        print(
            "[2] PC lấy Public Key PHONE"
        )

        server_public_key = \
            get_phone_public_key(
                phone_device_id
            )

        print(
            "    Public Key:",
            len(server_public_key),
            "bytes"
        )

        if server_public_key != phone_public_key:

            raise RuntimeError(
                "Public Key Server trả về "
                "không giống Public Key Phone."
            )

        print(
            "    Public Key kiểm tra: OK"
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
        # 4. TẠO VAULT
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
            "    Plaintext Vault:"
        )

        print(
            "    ",
            vault_data.decode("utf-8")
        )

        # ====================================================
        # 5. AES ENCRYPT VAULT
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

        # ====================================================
        # 6. PC ENCAPS
        # ====================================================

        print()
        print(
            "[6] PC - ML-KEM Encaps()"
        )

        kem_ciphertext, pc_shared_secret = \
            pc_kem.encapsulate(
                server_public_key
            )

        print(
            "    KEM Ciphertext:",
            len(kem_ciphertext),
            "bytes"
        )

        print(
            "    Shared Secret:",
            len(pc_shared_secret),
            "bytes"
        )

        # ====================================================
        # 7. PC BẢO VỆ K_VAULT
        # ====================================================

        print()
        print(
            "[7] PC - WRAP K_VAULT"
        )

        key_nonce, encrypted_vault_key = \
            VaultCrypto.wrap_vault_key(
                vault_key,
                pc_shared_secret
            )

        print(
            "    Encrypted K_VAULT:",
            len(encrypted_vault_key),
            "bytes"
        )

        print(
            "    Key Nonce:",
            len(key_nonce),
            "bytes"
        )

        # ====================================================
        # 8. UPLOAD VAULT
        # ====================================================

        print()
        print(
            "[8] PC -> SERVER: UPLOAD VAULT"
        )

        vault_result = upload_vault(
            encrypted_vault,
            vault_nonce
        )

        print(
            "    Status:",
            vault_result["status"]
        )

        # ====================================================
        # 9. DOWNLOAD VAULT ĐỂ LẤY VAULT ID
        # ====================================================

        print()
        print(
            "[9] LẤY VAULT ID"
        )

        (
            vault_id,
            server_encrypted_vault,
            server_vault_nonce
        ) = download_vault()

        print(
            "    Vault ID:",
            vault_id
        )

        if server_encrypted_vault != encrypted_vault:

            raise RuntimeError(
                "Encrypted Vault trên Server "
                "không đúng."
            )

        if server_vault_nonce != vault_nonce:

            raise RuntimeError(
                "Vault Nonce trên Server "
                "không đúng."
            )

        print(
            "    Encrypted Vault kiểm tra: OK"
        )

        # ====================================================
        # 10. UPLOAD WRAPPED K_VAULT
        # ====================================================

        print()
        print(
            "[10] PC -> SERVER: "
            "UPLOAD ENCRYPTED K_VAULT"
        )

        key_result = upload_vault_key(
            vault_id,
            phone_device_id,
            kem_ciphertext,
            encrypted_vault_key,
            key_nonce
        )

        print(
            "    Key ID:",
            key_result["key_id"]
        )

        print(
            "    Status:",
            key_result["status"]
        )

        # ====================================================
        # 11. PHONE DOWNLOAD WRAPPED K_VAULT
        # ====================================================

        print()
        print(
            "[11] PHONE <- SERVER: "
            "DOWNLOAD VAULT KEY"
        )

        (
            received_kem_ciphertext,
            received_encrypted_vault_key,
            received_key_nonce
        ) = download_vault_key(
            vault_id,
            phone_device_id
        )

        print(
            "    KEM Ciphertext:",
            len(received_kem_ciphertext),
            "bytes"
        )

        print(
            "    Encrypted K_VAULT:",
            len(received_encrypted_vault_key),
            "bytes"
        )

        print(
            "    Key Nonce:",
            len(received_key_nonce),
            "bytes"
        )

        # ====================================================
        # 12. KIỂM TRA DỮ LIỆU
        # ====================================================

        print()
        print(
            "[12] KIỂM TRA DỮ LIỆU"
        )

        if received_kem_ciphertext != \
                kem_ciphertext:

            raise RuntimeError(
                "KEM Ciphertext bị thay đổi."
            )

        if received_encrypted_vault_key != \
                encrypted_vault_key:

            raise RuntimeError(
                "Encrypted K_VAULT bị thay đổi."
            )

        if received_key_nonce != key_nonce:

            raise RuntimeError(
                "Key Nonce bị thay đổi."
            )

        print(
            "    KEM Ciphertext: OK"
        )

        print(
            "    Encrypted K_VAULT: OK"
        )

        print(
            "    Key Nonce: OK"
        )

        # ====================================================
        # 13. PHONE DECAPS
        # ====================================================

        print()
        print(
            "[13] PHONE - ML-KEM Decaps()"
        )

        phone_shared_secret = \
            phone_kem.decapsulate(
                received_kem_ciphertext
            )

        print(
            "    Shared Secret:",
            len(phone_shared_secret),
            "bytes"
        )

        if phone_shared_secret != \
                pc_shared_secret:

            raise RuntimeError(
                "PC và Phone không có cùng "
                "Shared Secret."
            )

        print(
            "    Shared Secret: OK"
        )

        # ====================================================
        # 14. PHONE UNWRAP K_VAULT
        # ====================================================

        print()
        print(
            "[14] PHONE - UNWRAP K_VAULT"
        )

        recovered_vault_key = \
            VaultCrypto.unwrap_vault_key(
                received_encrypted_vault_key,
                received_key_nonce,
                phone_shared_secret
            )

        print(
            "    K_VAULT:",
            len(recovered_vault_key),
            "bytes"
        )

        if recovered_vault_key != vault_key:

            raise RuntimeError(
                "K_VAULT khôi phục không giống "
                "K_VAULT ban đầu."
            )

        print(
            "    K_VAULT: OK"
        )

        # ====================================================
        # 15. PHONE DECRYPT VAULT
        # ====================================================

        print()
        print(
            "[15] PHONE - DECRYPT VAULT"
        )

        recovered_vault = \
            VaultCrypto.decrypt_vault(
                server_encrypted_vault,
                server_vault_nonce,
                recovered_vault_key
            )

        print(
            "    Plaintext Vault:"
        )

        print(
            "    ",
            recovered_vault.decode("utf-8")
        )

        # ====================================================
        # 16. FINAL
        # ====================================================

        print()
        print(
            "[16] KIỂM TRA TOÀN BỘ"
        )

        if recovered_vault != vault_data:

            raise RuntimeError(
                "Vault khôi phục không giống "
                "Vault ban đầu."
            )

        print()
        print(
            "    RESULT: SUCCESS"
        )

        print()
        print(
            "    ML-KEM End-to-End: OK"
        )

        print(
            "    K_VAULT Protection: OK"
        )

        print(
            "    Encrypted Vault Server: OK"
        )

        print(
            "    Encrypted K_VAULT Server: OK"
        )

        print(
            "    Phone khôi phục K_VAULT: OK"
        )

        print(
            "    Phone giải mã Vault: OK"
        )

        print()
        print(
            "    SERVER KHÔNG CẦN BIẾT K_VAULT."
        )

    finally:

        pc_kem.close()
        phone_kem.close()


if __name__ == "__main__":
    main()