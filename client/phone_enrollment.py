import base64
import json
from pathlib import Path

import requests

from common.mlkem_manager import MLKEMManager
from common.crypto_utils import derive_aes_key, encrypt_data
from common.local_vault_protection import LocalVaultKeyProtection


# ============================================================
# PATH
# ============================================================

PROJECT_DIR = Path(__file__).resolve().parent.parent

LOCAL_DATA_DIR = (
    PROJECT_DIR
    / "data"
)

LOCAL_CONFIG_FILE = (
    LOCAL_DATA_DIR
    / "client_config.json"
)


# ============================================================
# SERVER
# ============================================================

SERVER_URL = "http://127.0.0.1:8000"

USER_ID = 2

PHONE_DEVICE_ID = 13


# ============================================================
# HTTP
# ============================================================

def get_json(path):

    response = requests.get(
        SERVER_URL + path,
        timeout=10,
    )

    if response.status_code >= 400:

        raise RuntimeError(
            f"HTTP {response.status_code}: "
            f"{response.text}"
        )

    return response.json()


def post_json(path, payload):

    response = requests.post(
        SERVER_URL + path,
        json=payload,
        timeout=10,
    )

    if response.status_code >= 400:

        raise RuntimeError(
            f"HTTP {response.status_code}: "
            f"{response.text}"
        )

    return response.json()


# ============================================================
# LOAD PC CONFIG
# ============================================================

def load_pc_config():

    if not LOCAL_CONFIG_FILE.exists():

        raise RuntimeError(
            "Không tìm thấy client_config.json."
        )

    with open(
        LOCAL_CONFIG_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        return json.load(file)


# ============================================================
# MAIN
# ============================================================

def main():

    print()
    print("=" * 60)
    print("       PC CẤP K_VAULT CHO PHONE")
    print("=" * 60)

    # --------------------------------------------------------
    # 1. SERVER
    # --------------------------------------------------------

    print()
    print("[1] KIỂM TRA SERVER")

    health = get_json(
        "/api/health"
    )

    print(
        "    Server: ONLINE"
    )

    print(
        "    Response:",
        health
    )

    # --------------------------------------------------------
    # 2. PC CONFIG
    # --------------------------------------------------------

    print()
    print("[2] ĐỌC PC CONFIG")

    config = load_pc_config()

    print(
        "    Config:",
        LOCAL_CONFIG_FILE
    )

    # --------------------------------------------------------
    # 3. KHÔI PHỤC K_VAULT
    # --------------------------------------------------------

    print()
    print("[3] KHÔI PHỤC K_VAULT TRÊN PC")

    vault_key_data = config.get(
        "vault_key_protection"
    )

    if not vault_key_data:

        raise RuntimeError(
            "Không tìm thấy vault_key_protection "
            "trong client_config.json."
        )

    # --------------------------------------------------------
    # LẤY SALT
    # --------------------------------------------------------

    try:

        vault_key_salt = base64.b64decode(
            vault_key_data["salt"]
        )

    except Exception as error:

        raise RuntimeError(
            "vault_key_protection.salt không hợp lệ."
        ) from error

    # --------------------------------------------------------
    # LẤY NONCE
    # --------------------------------------------------------

    try:

        vault_key_nonce = base64.b64decode(
            vault_key_data["nonce"]
        )

    except Exception as error:

        raise RuntimeError(
            "vault_key_protection.nonce không hợp lệ."
        ) from error

    # --------------------------------------------------------
    # LẤY ENCRYPTED K_VAULT
    # --------------------------------------------------------

    try:

        encrypted_vault_key = base64.b64decode(
            vault_key_data[
                "encrypted_vault_key"
            ]
        )

    except Exception as error:

        raise RuntimeError(
            "vault_key_protection.encrypted_vault_key "
            "không hợp lệ."
        ) from error

    print(
        "    Scrypt Salt:",
        len(vault_key_salt),
        "bytes"
    )

    print(
        "    AES-GCM Nonce:",
        len(vault_key_nonce),
        "bytes"
    )

    print(
        "    Encrypted K_VAULT:",
        len(encrypted_vault_key),
        "bytes"
    )

    # --------------------------------------------------------
    # MASTER PASSWORD
    # --------------------------------------------------------

    import getpass

    password = getpass.getpass(
        "    Nhập Master Password của PC: "
    )

    # --------------------------------------------------------
    # RECOVER
    # --------------------------------------------------------

    try:

        k_vault = (
            LocalVaultKeyProtection
            .recover_vault_key(
                encrypted_vault_key,
                password,
                vault_key_salt,
                vault_key_nonce
            )
        )

    except Exception as error:

        raise RuntimeError(
            "Không thể khôi phục K_VAULT. "
            "Kiểm tra Master Password hoặc "
            "dữ liệu vault_key_protection."
        ) from error

    if len(k_vault) != 32:

        raise RuntimeError(
            "K_VAULT khôi phục không có độ dài 32 bytes."
        )

    print(
        "    K_VAULT:",
        len(k_vault),
        "bytes"
    )

    print(
        "    K_VAULT: OK"
    )

    # --------------------------------------------------------
    # 4. LẤY PHONE DEVICE
    # --------------------------------------------------------

    print()
    print("[4] LẤY PHONE DEVICE")

    devices = get_json(
        f"/api/users/{USER_ID}/devices"
    )

    if isinstance(devices, dict):

        device_list = devices.get(
            "devices",
            []
        )

    elif isinstance(devices, list):

        device_list = devices

    else:

        device_list = []

    phone = None

    for device in device_list:

        device_id = device.get(
            "device_id",
            device.get("id")
        )

        if int(device_id) == PHONE_DEVICE_ID:

            phone = device

            break

    if phone is None:

        raise RuntimeError(
            f"Không tìm thấy Phone Device ID "
            f"{PHONE_DEVICE_ID}."
        )

    print(
        "    Phone Device ID:",
        PHONE_DEVICE_ID
    )

    print(
        "    Device Name:",
        phone.get("device_name")
    )

    # --------------------------------------------------------
    # 5. PHONE PUBLIC KEY
    # --------------------------------------------------------

    print()
    print("[5] LẤY PHONE ML-KEM PUBLIC KEY")

    encoded_public_key = phone.get(
        "kem_public_key"
    )

    if not encoded_public_key:

        raise RuntimeError(
            "Phone không có ML-KEM Public Key."
        )

    phone_public_key = base64.b64decode(
        encoded_public_key
    )

    print(
        "    Phone Public Key:",
        len(phone_public_key),
        "bytes"
    )

    if len(phone_public_key) != 1184:

        raise RuntimeError(
            "Public Key không đúng kích thước "
            "ML-KEM-768."
        )

    print(
        "    Public Key: OK"
    )

    # --------------------------------------------------------
    # 6. PC ENCAPS
    # --------------------------------------------------------

    print()
    print("[6] PC ML-KEM Encaps()")

    kem = MLKEMManager()

    try:

        (
            kem_ciphertext,
            shared_secret
        ) = kem.encapsulate(
            phone_public_key
        )

    finally:

        kem.close()

    print(
        "    KEM Ciphertext:",
        len(kem_ciphertext),
        "bytes"
    )

    print(
        "    Shared Secret:",
        len(shared_secret),
        "bytes"
    )

    print(
        "    Encaps(): OK"
    )

    # --------------------------------------------------------
    # 7. HKDF
    # --------------------------------------------------------

    print()
    print("[7] DERIVE KEY BẢO VỆ K_VAULT")

    wrap_key = derive_aes_key(
        shared_secret
    )

    print(
        "    HKDF-AES Key:",
        len(wrap_key),
        "bytes"
    )

    print(
        "    HKDF-SHA256: OK"
    )

    # --------------------------------------------------------
    # 8. WRAP K_VAULT
    # --------------------------------------------------------

    print()
    print("[8] WRAP K_VAULT CHO PHONE")

    (
        wrap_nonce,
        encrypted_vault_key
    ) = encrypt_data(
        k_vault,
        wrap_key
    )

    print(
        "    K_VAULT plaintext:",
        len(k_vault),
        "bytes"
    )

    print(
        "    Encrypted K_VAULT:",
        len(encrypted_vault_key),
        "bytes"
    )

    print(
        "    Wrap Nonce:",
        len(wrap_nonce),
        "bytes"
    )

    print(
        "    K_VAULT plaintext: KHÔNG GỬI SERVER"
    )

    # --------------------------------------------------------
    # 9. LẤY VAULT ID
    # --------------------------------------------------------

    print()
    print("[9] LẤY VAULT ID")

    server_vault = get_json(
        f"/api/vaults/{USER_ID}"
    )

    vault_id = int(
        server_vault["vault_id"]
    )

    print(
        "    Vault ID:",
        vault_id
    )

    # --------------------------------------------------------
    # 10. LƯU WRAPPED K_VAULT
    # --------------------------------------------------------

    print()
    print("[10] LƯU WRAPPED K_VAULT LÊN SERVER")

    result = post_json(
        f"/api/vaults/{vault_id}/keys",
        {
            "device_id":
                PHONE_DEVICE_ID,

            "kem_ciphertext":
                base64.b64encode(
                    kem_ciphertext
                ).decode("ascii"),

            "encrypted_vault_key":
                base64.b64encode(
                    encrypted_vault_key
                ).decode("ascii"),

            "nonce":
                base64.b64encode(
                    wrap_nonce
                ).decode("ascii")
        }
    )

    print(
        "    Key ID:",
        result.get(
            "key_id",
            result.get("id")
        )
    )

    print(
        "    Server Storage: OK"
    )

    # --------------------------------------------------------
    # 11. KIỂM TRA LẠI DỮ LIỆU SERVER
    # --------------------------------------------------------

    print()
    print("[11] KIỂM TRA WRAPPED K_VAULT")

    stored = get_json(
        f"/api/vaults/{vault_id}/keys/{PHONE_DEVICE_ID}"
    )

    stored_ciphertext = base64.b64decode(
        stored["kem_ciphertext"]
    )

    stored_encrypted_key = base64.b64decode(
        stored["encrypted_vault_key"]
    )

    stored_nonce = base64.b64decode(
        stored["nonce"]
    )

    print(
        "    KEM Ciphertext:",
        len(stored_ciphertext),
        "bytes"
    )

    print(
        "    Encrypted K_VAULT:",
        len(stored_encrypted_key),
        "bytes"
    )

    print(
        "    Nonce:",
        len(stored_nonce),
        "bytes"
    )

    if stored_ciphertext != kem_ciphertext:

        raise RuntimeError(
            "KEM Ciphertext lưu trên Server không khớp."
        )

    if stored_encrypted_key != encrypted_vault_key:

        raise RuntimeError(
            "Encrypted K_VAULT lưu trên Server không khớp."
        )

    if stored_nonce != wrap_nonce:

        raise RuntimeError(
            "Nonce lưu trên Server không khớp."
        )

    print(
        "    Server Data Integrity: OK"
    )

    # --------------------------------------------------------
    # RESULT
    # --------------------------------------------------------

    print()
    print("=" * 60)
    print("RESULT: SUCCESS")
    print("=" * 60)

    print()
    print(
        "PC đã cấp K_VAULT cho Phone."
    )

    print(
        "Phone Device ID:",
        PHONE_DEVICE_ID
    )

    print(
        "ML-KEM Ciphertext:",
        len(kem_ciphertext),
        "bytes"
    )

    print(
        "Wrapped K_VAULT:",
        len(encrypted_vault_key),
        "bytes"
    )

    print()
    print(
        "Server chỉ lưu:"
    )

    print(
        "    - KEM Ciphertext"
    )

    print(
        "    - Encrypted K_VAULT"
    )

    print(
        "    - Nonce"
    )

    print()
    print(
        "K_VAULT plaintext không được gửi lên Server."
    )


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":

    try:

        main()

    except KeyboardInterrupt:

        print()
        print("Đã hủy.")

    except Exception as error:

        print()
        print("=" * 60)
        print("RESULT: FAILED")
        print("=" * 60)

        print(
            "Chi tiết:",
            error
        )