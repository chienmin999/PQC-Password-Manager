import base64
import getpass
import json
from pathlib import Path

import requests

from common.mlkem_manager import MLKEMManager
from common.local_vault_protection import LocalVaultKeyProtection
from common.crypto_utils import derive_aes_key, encrypt_data, decrypt_data
from vault.vault_crypto import VaultCrypto


# ============================================================
# PATH
# ============================================================

# phone_vault_test.py nằm trong:
# D:\PQC\PQC-Password-Manager\client
#
# client_config.json nằm trong:
# D:\PQC\PQC-Password-Manager\data

PROJECT_DIR = Path(__file__).resolve().parent.parent

LOCAL_CONFIG_FILE = (
    PROJECT_DIR
    / "data"
    / "client_config.json"
)

SERVER_URL = "http://127.0.0.1:8000"

# User đang sử dụng trên Server
USER_ID = 2


# ============================================================
# HTTP
# ============================================================

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
# MAIN
# ============================================================

def main():

    print()
    print("=" * 60)
    print("      PHONE VAULT / ML-KEM E2E TEST")
    print("=" * 60)

    # --------------------------------------------------------
    # KIỂM TRA FILE CONFIG
    # --------------------------------------------------------

    print()
    print("[0] KIỂM TRA CLIENT CONFIG")

    print(
        "    Config:",
        LOCAL_CONFIG_FILE
    )

    if not LOCAL_CONFIG_FILE.exists():

        raise RuntimeError(
            "Không tìm thấy client_config.json tại:\n"
            f"{LOCAL_CONFIG_FILE}"
        )

    with open(
        LOCAL_CONFIG_FILE,
        "r",
        encoding="utf-8",
    ) as file:

        config = json.load(file)

    print(
        "    client_config.json: OK"
    )

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
    # 2. LẤY VAULT TRÊN SERVER
    # --------------------------------------------------------

    print()
    print("[2] LẤY ENCRYPTED VAULT")

    server_vault = get_json(
        f"/api/vaults/{USER_ID}"
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
    # 3. KHÔI PHỤC K_VAULT TRÊN PC
    # --------------------------------------------------------

    print()
    print("[3] KHÔI PHỤC K_VAULT TRÊN PC")

    password = getpass.getpass(
        "    Master Password: "
    )

    vault_key_data = config[
        "vault_key_protection"
    ]

    vault_key_salt = base64.b64decode(
        vault_key_data["salt"]
    )

    vault_key_nonce = base64.b64decode(
        vault_key_data["nonce"]
    )

    encrypted_local_vault_key = (
        base64.b64decode(
            vault_key_data[
                "encrypted_vault_key"
            ]
        )
    )

    try:

        vault_key = (
            LocalVaultKeyProtection
            .recover_vault_key(
                encrypted_local_vault_key,
                password,
                vault_key_salt,
                vault_key_nonce,
            )
        )

    except Exception as error:

        raise RuntimeError(
            "Không thể khôi phục K_VAULT. "
            "Kiểm tra Master Password."
        ) from error

    if len(vault_key) != 32:

        raise RuntimeError(
            "K_VAULT không có độ dài 32 bytes."
        )

    print(
        "    K_VAULT:",
        len(vault_key),
        "bytes"
    )

    print(
        "    K_VAULT: OK"
    )

    # --------------------------------------------------------
    # 4. TẠO PHONE ML-KEM KEYPAIR
    # --------------------------------------------------------

    print()
    print("[4] PHONE ML-KEM-768 KEYGEN()")

    phone_kem = MLKEMManager()

    (
        phone_public_key,
        phone_secret_key
    ) = phone_kem.generate_keypair()

    print(
        "    Phone Public Key:",
        len(phone_public_key),
        "bytes"
    )

    print(
        "    Phone Secret Key:",
        len(phone_secret_key),
        "bytes"
    )

    # --------------------------------------------------------
    # 5. ĐĂNG KÝ PHONE
    # --------------------------------------------------------

    print()
    print("[5] ĐĂNG KÝ PHONE")

    device_result = post_json(
        "/api/devices/register",
        {
            "user_id": USER_ID,

            "device_name": "PHONE",

            "kem_public_key":
                base64.b64encode(
                    phone_public_key
                ).decode("ascii"),
        },
    )

    phone_device_id = (
        device_result.get(
            "device_id"
        )
    )

    if phone_device_id is None:

        raise RuntimeError(
            "Server không trả về Device ID: "
            f"{device_result}"
        )

    print(
        "    Phone Device ID:",
        phone_device_id
    )

    print(
        "    Registration: OK"
    )

    # --------------------------------------------------------
    # 6. PC ENCAPSULATE PHONE PUBLIC KEY
    # --------------------------------------------------------

    print()
    print("[6] PC ML-KEM Encaps()")

    (
        kem_ciphertext,
        shared_secret_pc
    ) = phone_kem.encapsulate(
        phone_public_key
    )

    print(
        "    KEM Ciphertext:",
        len(kem_ciphertext),
        "bytes"
    )

    print(
        "    Shared Secret:",
        len(shared_secret_pc),
        "bytes"
    )

    print(
        "    Encaps(): OK"
    )

    # --------------------------------------------------------
    # 7. WRAP K_VAULT
    # --------------------------------------------------------

    print()
    print("[7] BẢO VỆ K_VAULT CHO PHONE")

    wrap_key = derive_aes_key(
        shared_secret_pc
    )

    (
        wrap_nonce,
        encrypted_vault_key
    ) = encrypt_data(
        vault_key,
        wrap_key,
    )

    print(
        "    HKDF-AES Key:",
        len(wrap_key),
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
        "    K_VAULT: KHÔNG GỬI PLAINTEXT"
    )

    # --------------------------------------------------------
    # 8. LƯU WRAPPED K_VAULT LÊN SERVER
    # --------------------------------------------------------

    print()
    print("[8] LƯU WRAPPED K_VAULT LÊN SERVER")

    key_result = post_json(
        f"/api/vaults/{vault_id}/keys",
        {
            "device_id":
                phone_device_id,

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
                ).decode("ascii"),
        },
    )

    print(
        "    Key ID:",
        key_result.get("key_id")
    )

    print(
        "    Server Storage: OK"
    )

    # --------------------------------------------------------
    # 9. PHONE LẤY WRAPPED K_VAULT
    # --------------------------------------------------------

    print()
    print("[9] PHONE LẤY WRAPPED K_VAULT")

    stored_key = get_json(
        f"/api/vaults/{vault_id}/keys/"
        f"{phone_device_id}"
    )

    received_ciphertext = (
        base64.b64decode(
            stored_key[
                "kem_ciphertext"
            ]
        )
    )

    received_encrypted_vault_key = (
        base64.b64decode(
            stored_key[
                "encrypted_vault_key"
            ]
        )
    )

    received_nonce = (
        base64.b64decode(
            stored_key["nonce"]
        )
    )

    print(
        "    KEM Ciphertext:",
        len(received_ciphertext),
        "bytes"
    )

    print(
        "    Encrypted K_VAULT:",
        len(received_encrypted_vault_key),
        "bytes"
    )

    print(
        "    Nonce:",
        len(received_nonce),
        "bytes"
    )

    print(
        "    Download: OK"
    )

    # --------------------------------------------------------
    # 10. PHONE DECAPSULATE
    # --------------------------------------------------------

    print()
    print("[10] PHONE ML-KEM Decaps()")

    phone_kem.close()

    phone_kem = MLKEMManager(
        phone_secret_key
    )

    shared_secret_phone = (
        phone_kem.decapsulate(
            received_ciphertext
        )
    )

    if (
        shared_secret_phone
        != shared_secret_pc
    ):

        raise RuntimeError(
            "Shared Secret của PC "
            "và Phone không khớp."
        )

    print(
        "    Decaps(): OK"
    )

    print(
        "    Shared Secret: MATCH"
    )

    # --------------------------------------------------------
    # 11. PHONE KHÔI PHỤC K_VAULT
    # --------------------------------------------------------

    print()
    print("[11] PHONE KHÔI PHỤC K_VAULT")

    phone_wrap_key = derive_aes_key(
        shared_secret_phone
    )

    recovered_vault_key = (
        decrypt_data(
            received_encrypted_vault_key,
            received_nonce,
            phone_wrap_key,
        )
    )

    if (
        recovered_vault_key
        != vault_key
    ):

        raise RuntimeError(
            "K_VAULT khôi phục trên Phone "
            "không khớp PC."
        )

    print(
        "    K_VAULT:",
        len(recovered_vault_key),
        "bytes"
    )

    print(
        "    K_VAULT: MATCH"
    )

    # --------------------------------------------------------
    # 12. PHONE GIẢI MÃ PASSWORD VAULT
    # --------------------------------------------------------

    print()
    print(
        "[12] PHONE GIẢI MÃ PASSWORD VAULT"
    )

    plaintext = (
        VaultCrypto.decrypt_vault(
            encrypted_vault,
            vault_nonce,
            recovered_vault_key,
        )
    )

    vault = json.loads(
        plaintext.decode("utf-8")
    )

    print(
        "    AES-256-GCM Decrypt: OK"
    )

    print(
        "    Vault JSON: OK"
    )

    print()
    print(
        "    PASSWORD VAULT"
    )

    accounts = vault.get(
        "accounts",
        []
    )

    if not accounts:

        print(
            "        Vault hiện đang rỗng."
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
                    "site",
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
    # RESULT
    # --------------------------------------------------------

    print()
    print("=" * 60)
    print("RESULT: SUCCESS")
    print("=" * 60)

    print()

    print(
        "PC và Phone sử dụng cùng một K_VAULT."
    )

    print(
        "Server chỉ lưu Encrypted Vault "
        "và Wrapped K_VAULT."
    )

    print(
        "K_VAULT plaintext không được gửi lên Server."
    )

    phone_kem.close()


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