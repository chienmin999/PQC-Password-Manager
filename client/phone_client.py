import base64
import getpass
import json
from pathlib import Path

import requests

from common.mlkem_manager import MLKEMManager
from common.secret_key_protection import SecretKeyProtection
from common.crypto_utils import (
    derive_aes_key,
    decrypt_data,
)
from vault.vault_crypto import VaultCrypto


# ============================================================
# PATH
# ============================================================

PROJECT_DIR = Path(__file__).resolve().parent.parent

LOCAL_DATA_DIR = (
    PROJECT_DIR
    / "data"
)

PHONE_CONFIG_FILE = (
    LOCAL_DATA_DIR
    / "phone_config.json"
)


# ============================================================
# SERVER
# ============================================================

SERVER_URL = "http://127.0.0.1:8000"


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


# ============================================================
# LOAD PHONE CONFIG
# ============================================================

def load_phone_config():

    if not PHONE_CONFIG_FILE.exists():

        raise RuntimeError(
            "Không tìm thấy phone_config.json."
        )

    with open(
        PHONE_CONFIG_FILE,
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
    print("        PHONE PASSWORD VAULT")
    print("=" * 60)

    # --------------------------------------------------------
    # 1. LOAD PHONE CONFIG
    # --------------------------------------------------------

    print()
    print("[1] ĐỌC PHONE CONFIG")

    config = load_phone_config()

    device_config = config.get(
        "device"
    )

    secret_key_config = config.get(
        "secret_key"
    )

    if not device_config:

        raise RuntimeError(
            "Thiếu device trong phone_config.json."
        )

    if not secret_key_config:

        raise RuntimeError(
            "Thiếu secret_key trong phone_config.json."
        )

    phone_device_id = int(
        device_config["device_id"]
    )

    user_id = int(
        device_config["user_id"]
    )

    print(
        "    Device:",
        device_config["device_name"]
    )

    print(
        "    Device ID:",
        phone_device_id
    )

    print(
        "    User ID:",
        user_id
    )

    print(
        "    Algorithm:",
        config.get(
            "algorithm"
        )
    )

    # --------------------------------------------------------
    # 2. KIỂM TRA SERVER
    # --------------------------------------------------------

    print()
    print("[2] KIỂM TRA SERVER")

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
    # 3. LẤY ENCRYPTED VAULT
    # --------------------------------------------------------

    print()
    print("[3] LẤY ENCRYPTED VAULT")

    server_vault = get_json(
        f"/api/vaults/{user_id}"
    )

    vault_id = int(
        server_vault["vault_id"]
    )

    encrypted_vault = base64.b64decode(
        server_vault["encrypted_vault"]
    )

    vault_nonce = base64.b64decode(
        server_vault["vault_nonce"]
    )

    server_version = int(
        server_vault["version"]
    )

    print(
        "    Vault ID:",
        vault_id
    )

    print(
        "    Server Version:",
        server_version
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

    # --------------------------------------------------------
    # 4. PHONE MASTER PASSWORD
    # --------------------------------------------------------

    print()
    print("[4] NHẬP PHONE MASTER PASSWORD")

    password = getpass.getpass(
        "    Phone Master Password: "
    )

    # --------------------------------------------------------
    # 5. KHÔI PHỤC ML-KEM SECRET KEY
    # --------------------------------------------------------

    print()
    print("[5] KHÔI PHỤC ML-KEM SECRET KEY")

    try:

        salt = base64.b64decode(
            secret_key_config["salt"]
        )

        nonce = base64.b64decode(
            secret_key_config["nonce"]
        )

        encrypted_secret_key = base64.b64decode(
            secret_key_config[
                "encrypted_secret_key"
            ]
        )

        secret_key = (
            SecretKeyProtection
            .recover_secret_key(
                encrypted_secret_key,
                password,
                salt,
                nonce
            )
        )

    except Exception as error:

        raise RuntimeError(
            "Không thể khôi phục ML-KEM Secret Key. "
            "Kiểm tra Phone Master Password."
        ) from error

    print(
        "    Secret Key:",
        len(secret_key),
        "bytes"
    )

    if len(secret_key) != 2400:

        raise RuntimeError(
            "ML-KEM-768 Secret Key không đúng "
            "2400 bytes."
        )

    print(
        "    Secret Key: OK"
    )

    # --------------------------------------------------------
    # 6. KHỞI TẠO ML-KEM VỚI SECRET KEY CỦA PHONE
    # --------------------------------------------------------

    print()
    print("[6] KHỞI TẠO PHONE ML-KEM")

    phone_kem = MLKEMManager(
        secret_key
    )

    print(
        "    ML-KEM-768: OK"
    )

    # --------------------------------------------------------
    # 7. LẤY WRAPPED K_VAULT
    # --------------------------------------------------------

    print()
    print("[7] LẤY WRAPPED K_VAULT")

    wrapped_key = get_json(
        f"/api/vaults/{vault_id}/keys/{phone_device_id}"
    )

    kem_ciphertext = base64.b64decode(
        wrapped_key["kem_ciphertext"]
    )

    encrypted_vault_key = base64.b64decode(
        wrapped_key["encrypted_vault_key"]
    )

    wrap_nonce = base64.b64decode(
        wrapped_key["nonce"]
    )

    print(
        "    KEM Ciphertext:",
        len(kem_ciphertext),
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

    # --------------------------------------------------------
    # 8. ML-KEM DECAPS
    # --------------------------------------------------------

    print()
    print("[8] PHONE ML-KEM Decaps()")

    try:

        shared_secret = (
            phone_kem.decapsulate(
                kem_ciphertext
            )
        )

    except Exception as error:

        phone_kem.close()

        raise RuntimeError(
            "ML-KEM Decaps() thất bại."
        ) from error

    print(
        "    Shared Secret:",
        len(shared_secret),
        "bytes"
    )

    if len(shared_secret) != 32:

        phone_kem.close()

        raise RuntimeError(
            "Shared Secret không đúng 32 bytes."
        )

    print(
        "    Decaps(): OK"
    )

    # --------------------------------------------------------
    # 9. HKDF
    # --------------------------------------------------------

    print()
    print("[9] DERIVE AES KEY")

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
    # 10. GIẢI MÃ K_VAULT
    # --------------------------------------------------------

    print()
    print("[10] PHONE KHÔI PHỤC K_VAULT")

    try:

        k_vault = decrypt_data(
            encrypted_vault_key,
            wrap_nonce,
            wrap_key
        )

    except Exception as error:

        phone_kem.close()

        raise RuntimeError(
            "Không thể giải mã K_VAULT."
        ) from error

    print(
        "    K_VAULT:",
        len(k_vault),
        "bytes"
    )

    if len(k_vault) != 32:

        phone_kem.close()

        raise RuntimeError(
            "K_VAULT không đúng 32 bytes."
        )

    print(
        "    K_VAULT: OK"
    )

    # --------------------------------------------------------
    # 11. GIẢI MÃ PASSWORD VAULT
    # --------------------------------------------------------

    print()
    print("[11] GIẢI MÃ PASSWORD VAULT")

    try:

        plaintext = VaultCrypto.decrypt_vault(
            encrypted_vault,
            vault_nonce,
            k_vault
        )

    except Exception as error:

        phone_kem.close()

        raise RuntimeError(
            "Không thể giải mã Password Vault."
        ) from error

    print(
        "    AES-256-GCM Decrypt: OK"
    )

    # --------------------------------------------------------
    # 12. JSON
    # --------------------------------------------------------

    try:

        vault = json.loads(
            plaintext.decode(
                "utf-8"
            )
        )

    except Exception as error:

        phone_kem.close()

        raise RuntimeError(
            "Password Vault không phải JSON hợp lệ."
        ) from error

    print(
        "    Vault JSON: OK"
    )

    # --------------------------------------------------------
    # 13. HIỂN THỊ PASSWORD
    # --------------------------------------------------------

    print()
    print(
        "    PASSWORD VAULT"
    )

    accounts = vault.get(
        "accounts",
        []
    )

    if not accounts:

        print()
        print(
            "        Không có tài khoản."
        )

    else:

        for index, account in enumerate(
            accounts,
            start=1
        ):

            print()
            print(
                f"        [{index}]"
            )

            print(
                "            Website:",
                account.get(
                    "website",
                    ""
                )
            )

            print(
                "            Username:",
                account.get(
                    "username",
                    ""
                )
            )

            print(
                "            Password:",
                account.get(
                    "password",
                    ""
                )
            )

    # --------------------------------------------------------
    # CLEANUP
    # --------------------------------------------------------

    phone_kem.close()

    # --------------------------------------------------------
    # RESULT
    # --------------------------------------------------------

    print()
    print("=" * 60)
    print("RESULT: SUCCESS")
    print("=" * 60)

    print()
    print(
        "Phone đã độc lập khôi phục Password Vault."
    )

    print(
        "Phone Device ID:",
        phone_device_id
    )

    print(
        "ML-KEM Decaps(): OK"
    )

    print(
        "K_VAULT: OK"
    )

    print(
        "AES-256-GCM Decrypt: OK"
    )

    print()
    print(
        "Phone không cần K_VAULT plaintext từ PC."
    )

    print(
        "Phone không cần Secret Key plaintext lưu trên disk."
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