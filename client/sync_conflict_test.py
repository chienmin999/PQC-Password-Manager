import base64
import json
import getpass
from pathlib import Path

import requests

from common.local_vault_protection import (
    LocalVaultKeyProtection
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

LOCAL_CONFIG_FILE = (
    LOCAL_DATA_DIR
    / "client_config.json"
)


# ============================================================
# SERVER
# ============================================================

SERVER_URL = "http://127.0.0.1:8000"

USER_ID = 2


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


def post_raw(path, payload):

    return requests.post(
        SERVER_URL + path,
        json=payload,
        timeout=10,
    )


# ============================================================
# LOAD CONFIG
# ============================================================

def load_config():

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
# RECOVER K_VAULT
# ============================================================

def recover_k_vault(config):

    vault_key_data = config[
        "vault_key_protection"
    ]

    salt = base64.b64decode(
        vault_key_data["salt"]
    )

    nonce = base64.b64decode(
        vault_key_data["nonce"]
    )

    encrypted_vault_key = base64.b64decode(
        vault_key_data[
            "encrypted_vault_key"
        ]
    )

    password = getpass.getpass(
        "    PC Master Password: "
    )

    try:

        k_vault = (
            LocalVaultKeyProtection
            .recover_vault_key(
                encrypted_vault_key,
                password,
                salt,
                nonce
            )
        )

    except Exception as error:

        raise RuntimeError(
            "Không thể khôi phục K_VAULT."
        ) from error

    if len(k_vault) != 32:

        raise RuntimeError(
            "K_VAULT không đúng 32 bytes."
        )

    return k_vault


# ============================================================
# MAIN
# ============================================================

def main():

    print()
    print("=" * 60)
    print("       KIỂM THỬ VERSION CONFLICT")
    print("=" * 60)

    # --------------------------------------------------------
    # 1. LOAD CONFIG
    # --------------------------------------------------------

    print()
    print("[1] ĐỌC PC CONFIG")

    config = load_config()

    print(
        "    Config: OK"
    )

    # --------------------------------------------------------
    # 2. SERVER
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
    # 3. PC ĐỌC VERSION HIỆN TẠI
    # --------------------------------------------------------

    print()
    print("[3] PC ĐỌC VERSION HIỆN TẠI")

    current = get_json(
        f"/api/vaults/{USER_ID}"
    )

    vault_id = int(
        current["vault_id"]
    )

    original_version = int(
        current["version"]
    )

    encrypted_vault = base64.b64decode(
        current["encrypted_vault"]
    )

    vault_nonce = base64.b64decode(
        current["vault_nonce"]
    )

    print(
        "    Vault ID:",
        vault_id
    )

    print(
        "    Server Version:",
        original_version
    )

    # --------------------------------------------------------
    # 4. KHÔI PHỤC K_VAULT
    # --------------------------------------------------------

    print()
    print("[4] KHÔI PHỤC K_VAULT")

    k_vault = recover_k_vault(
        config
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
    # 5. PC GIẢ LẬP BẢN VAULT CŨ
    # --------------------------------------------------------

    print()
    print("[5] TẠO BẢN VAULT TỪ VERSION",
          original_version)

    plaintext = VaultCrypto.decrypt_vault(
        encrypted_vault,
        vault_nonce,
        k_vault
    )

    vault = json.loads(
        plaintext.decode("utf-8")
    )

    print(
        "    AES-256-GCM Decrypt: OK"
    )

    # --------------------------------------------------------
    # 6. TẠO THAY ĐỔI CỦA THIẾT BỊ KHÁC
    # --------------------------------------------------------

    print()
    print("[6] THIẾT BỊ KHÁC CẬP NHẬT VAULT")

    other_vault = json.loads(
        json.dumps(
            vault,
            ensure_ascii=False
        )
    )

    other_vault.setdefault(
        "accounts",
        []
    )

    other_vault["accounts"].append(
        {
            "website": "conflict-device.local",
            "username": "device2",
            "password": "conflict-test"
        }
    )

    other_plaintext = json.dumps(
        other_vault,
        ensure_ascii=False,
        separators=(",", ":")
    ).encode("utf-8")

    other_nonce, other_encrypted = (
        VaultCrypto.encrypt_vault(
            other_plaintext,
            k_vault
        )
    )

    response = post_raw(
        "/api/vaults",
        {
            "user_id":
                USER_ID,

            "encrypted_vault":
                base64.b64encode(
                    other_encrypted
                ).decode("ascii"),

            "vault_nonce":
                base64.b64encode(
                    other_nonce
                ).decode("ascii"),

            "base_version":
                original_version
        }
    )

    if response.status_code >= 400:

        raise RuntimeError(
            "Thiết bị khác cập nhật Vault thất bại:\n"
            + response.text
        )

    updated = response.json()

    updated_version = int(
        updated["version"]
    )

    print(
        "    Base Version:",
        original_version
    )

    print(
        "    Server Version mới:",
        updated_version
    )

    if updated_version != original_version + 1:

        raise RuntimeError(
            "Server không tăng Version đúng."
        )

    print(
        "    Device-2 Update: OK"
    )

    # --------------------------------------------------------
    # 7. PC CỐ TÌNH GỬI BẢN CŨ
    # --------------------------------------------------------

    print()
    print("[7] PC GỬI VAULT CŨ")

    stale_plaintext = json.dumps(
        vault,
        ensure_ascii=False,
        separators=(",", ":")
    ).encode("utf-8")

    stale_nonce, stale_encrypted = (
        VaultCrypto.encrypt_vault(
            stale_plaintext,
            k_vault
        )
    )

    stale_response = post_raw(
        "/api/vaults",
        {
            "user_id":
                USER_ID,

            "encrypted_vault":
                base64.b64encode(
                    stale_encrypted
                ).decode("ascii"),

            "vault_nonce":
                base64.b64encode(
                    stale_nonce
                ).decode("ascii"),

            "base_version":
                original_version
        }
    )

    print(
        "    HTTP Status:",
        stale_response.status_code
    )

    # --------------------------------------------------------
    # 8. KIỂM TRA CONFLICT
    # --------------------------------------------------------

    if stale_response.status_code != 409:

        raise RuntimeError(
            "Server không phát hiện Version Conflict."
        )

    conflict = stale_response.json()

    print(
        "    Version Conflict: DETECTED"
    )

    print(
        "    Server Version:",
        conflict.get(
            "server_version"
        )
    )

    print(
        "    Client Base Version:",
        conflict.get(
            "client_base_version"
        )
    )

    # --------------------------------------------------------
    # 9. KIỂM TRA SERVER KHÔNG BỊ GHI ĐÈ
    # --------------------------------------------------------

    print()
    print("[8] KIỂM TRA SERVER SAU CONFLICT")

    final_data = get_json(
        f"/api/vaults/{USER_ID}"
    )

    final_version = int(
        final_data["version"]
    )

    final_encrypted = base64.b64decode(
        final_data["encrypted_vault"]
    )

    if final_version != updated_version:

        raise RuntimeError(
            "Server Version bị thay đổi ngoài dự kiến."
        )

    if final_encrypted != other_encrypted:

        raise RuntimeError(
            "Dữ liệu Server đã bị ghi đè "
            "bởi Client cũ."
        )

    print(
        "    Server Version:",
        final_version
    )

    print(
        "    Device-2 Data: PRESERVED"
    )

    print(
        "    Stale Client Data: REJECTED"
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
        "Version Conflict đã được phát hiện."
    )

    print(
        "Server không cho Client cũ ghi đè Vault."
    )

    print(
        "Dữ liệu của thiết bị cập nhật trước "
        "được bảo toàn."
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