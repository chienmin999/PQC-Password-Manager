import base64
import getpass
import json
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


# ============================================================
# LOAD PC CONFIG
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
# MAIN
# ============================================================

def main():

    print()
    print("=" * 60)
    print("        PC ĐỒNG BỘ PASSWORD VAULT")
    print("=" * 60)

    # --------------------------------------------------------
    # 1. LOAD CONFIG
    # --------------------------------------------------------

    print()
    print("[1] ĐỌC PC CONFIG")

    config = load_config()

    print(
        "    Config:",
        LOCAL_CONFIG_FILE
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
    # 3. LẤY VAULT
    # --------------------------------------------------------

    print()
    print("[3] LẤY VAULT TỪ SERVER")

    server_vault = get_json(
        f"/api/vaults/{USER_ID}"
    )

    vault_id = int(
        server_vault["vault_id"]
    )

    server_version = int(
        server_vault["version"]
    )

    encrypted_vault = base64.b64decode(
        server_vault["encrypted_vault"]
    )

    vault_nonce = base64.b64decode(
        server_vault["vault_nonce"]
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
    # 4. MASTER PASSWORD
    # --------------------------------------------------------

    print()
    print("[4] NHẬP PC MASTER PASSWORD")

    password = getpass.getpass(
        "    Master Password: "
    )

    # --------------------------------------------------------
    # 5. KHÔI PHỤC K_VAULT
    # --------------------------------------------------------

    print()
    print("[5] KHÔI PHỤC K_VAULT LOCAL")

    vault_key_data = config.get(
        "vault_key_protection"
    )

    if not vault_key_data:

        raise RuntimeError(
            "Không tìm thấy vault_key_protection."
        )

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
            "Không thể khôi phục K_VAULT. "
            "Kiểm tra Master Password."
        ) from error

    print(
        "    K_VAULT:",
        len(k_vault),
        "bytes"
    )

    if len(k_vault) != 32:

        raise RuntimeError(
            "K_VAULT không đúng 32 bytes."
        )

    print(
        "    K_VAULT: OK"
    )

    # --------------------------------------------------------
    # 6. GIẢI MÃ VAULT
    # --------------------------------------------------------

    print()
    print("[6] GIẢI MÃ VAULT MỚI")

    try:

        plaintext = VaultCrypto.decrypt_vault(
            encrypted_vault,
            vault_nonce,
            k_vault
        )

    except Exception as error:

        raise RuntimeError(
            "Không thể giải mã Vault từ Server."
        ) from error

    print(
        "    AES-256-GCM Decrypt: OK"
    )

    # --------------------------------------------------------
    # 7. PARSE JSON
    # --------------------------------------------------------

    try:

        vault = json.loads(
            plaintext.decode("utf-8")
        )

    except Exception as error:

        raise RuntimeError(
            "Vault không phải JSON hợp lệ."
        ) from error

    print(
        "    Vault JSON: OK"
    )

    # --------------------------------------------------------
    # 8. HIỂN THỊ
    # --------------------------------------------------------

    accounts = vault.get(
        "accounts",
        []
    )

    print()
    print(
        "    PASSWORD VAULT ĐỒNG BỘ"
    )

    print(
        "    Số tài khoản:",
        len(accounts)
    )

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
    # 9. KIỂM TRA TÀI KHOẢN TEST TỪ PHONE
    # --------------------------------------------------------

    print()
    print("[7] KIỂM TRA DỮ LIỆU PHONE ĐÃ ĐỒNG BỘ")

    phone_test_found = False

    for account in accounts:

        if (
            account.get("website")
            == "github.com"
            and
            account.get("username")
            == "misuha"
        ):

            phone_test_found = True

            break

    if phone_test_found:

        print(
            "    github.com / misuha: FOUND"
        )

        print(
            "    Phone → Server → PC: OK"
        )

    else:

        print(
            "    Không tìm thấy tài khoản "
            "github.com / misuha."
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
        "PC đã lấy được Vault mới từ Server."
    )

    print(
        "Server Version:",
        server_version
    )

    print(
        "K_VAULT local:",
        len(k_vault),
        "bytes"
    )

    print(
        "AES-256-GCM Decrypt: OK"
    )

    if phone_test_found:

        print(
            "Phone → Server → PC: SUCCESS"
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