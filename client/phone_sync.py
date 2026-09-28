import base64
import getpass
import json
from pathlib import Path

import requests

from common.mlkem_manager import MLKEMManager
from common.secret_key_protection import SecretKeyProtection
from common.crypto_utils import derive_aes_key, decrypt_data
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


def post_json(path, payload):

    response = requests.post(
        SERVER_URL + path,
        json=payload,
        timeout=10,
    )

    return response


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
    print("       PHONE ĐỒNG BỘ PASSWORD VAULT")
    print("=" * 60)

    # --------------------------------------------------------
    # 1. PHONE CONFIG
    # --------------------------------------------------------

    print()
    print("[1] ĐỌC PHONE CONFIG")

    config = load_phone_config()

    device_config = config["device"]

    secret_key_config = config["secret_key"]

    phone_device_id = int(
        device_config["device_id"]
    )

    user_id = int(
        device_config["user_id"]
    )

    print(
        "    Phone Device ID:",
        phone_device_id
    )

    print(
        "    User ID:",
        user_id
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
    print("[3] LẤY ENCRYPTED VAULT")

    server_vault = get_json(
        f"/api/vaults/{user_id}"
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

    # --------------------------------------------------------
    # 4. PHONE MASTER PASSWORD
    # --------------------------------------------------------

    print()
    print("[4] NHẬP PHONE MASTER PASSWORD")

    password = getpass.getpass(
        "    Phone Master Password: "
    )

    # --------------------------------------------------------
    # 5. KHÔI PHỤC PHONE SECRET KEY
    # --------------------------------------------------------

    print()
    print("[5] KHÔI PHỤC ML-KEM SECRET KEY")

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

    try:

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
            "Không thể khôi phục Phone Secret Key. "
            "Kiểm tra Phone Master Password."
        ) from error

    print(
        "    Secret Key:",
        len(secret_key),
        "bytes"
    )

    print(
        "    Secret Key: OK"
    )

    # --------------------------------------------------------
    # 6. PHONE ML-KEM
    # --------------------------------------------------------

    print()
    print("[6] PHONE ML-KEM")

    kem = MLKEMManager(
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

    # --------------------------------------------------------
    # 8. DECAPS
    # --------------------------------------------------------

    print()
    print("[8] ML-KEM Decaps()")

    shared_secret = kem.decapsulate(
        kem_ciphertext
    )

    print(
        "    Shared Secret:",
        len(shared_secret),
        "bytes"
    )

    print(
        "    Decaps(): OK"
    )

    # --------------------------------------------------------
    # 9. DERIVE WRAP KEY
    # --------------------------------------------------------

    print()
    print("[9] HKDF-SHA256")

    wrap_key = derive_aes_key(
        shared_secret
    )

    print(
        "    AES Key:",
        len(wrap_key),
        "bytes"
    )

    print(
        "    HKDF: OK"
    )

    # --------------------------------------------------------
    # 10. RECOVER K_VAULT
    # --------------------------------------------------------

    print()
    print("[10] KHÔI PHỤC K_VAULT")

    k_vault = decrypt_data(
        encrypted_vault_key,
        wrap_nonce,
        wrap_key
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
    # 11. DECRYPT VAULT
    # --------------------------------------------------------

    print()
    print("[11] GIẢI MÃ PASSWORD VAULT")

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

    print(
        "    Vault JSON: OK"
    )

    # --------------------------------------------------------
    # 12. HIỂN THỊ TÀI KHOẢN
    # --------------------------------------------------------

    print()
    print(
        "    PASSWORD VAULT HIỆN TẠI"
    )

    accounts = vault.get(
        "accounts",
        []
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
            account.get("website", "")
        )

        print(
            "            Username:",
            account.get("username", "")
        )

        print(
            "            Password:",
            account.get("password", "")
        )

    # --------------------------------------------------------
    # 13. THÊM TÀI KHOẢN
    # --------------------------------------------------------

    print()
    print("[12] THÊM TÀI KHOẢN")

    website = input(
        "    Website: "
    ).strip()

    username = input(
        "    Username: "
    ).strip()

    new_password = getpass.getpass(
        "    Password: "
    )

    if not website:

        raise RuntimeError(
            "Website không được để trống."
        )

    if not username:

        raise RuntimeError(
            "Username không được để trống."
        )

    if not new_password:

        raise RuntimeError(
            "Password không được để trống."
        )

    new_account = {

        "website": website,

        "username": username,

        "password": new_password
    }

    vault.setdefault(
        "accounts",
        []
    )

    vault["accounts"].append(
        new_account
    )

    print()
    print(
        "    Đã thêm tài khoản vào Vault."
    )

    # --------------------------------------------------------
    # 14. MÃ HÓA VAULT MỚI
    # --------------------------------------------------------

    print()
    print("[13] MÃ HÓA VAULT MỚI")

    new_plaintext = json.dumps(
        vault,
        ensure_ascii=False,
        separators=(",", ":")
    ).encode("utf-8")

    new_vault_nonce, new_encrypted_vault = (
        VaultCrypto.encrypt_vault(
            new_plaintext,
            k_vault
        )
    )

    print(
        "    Plaintext Vault:",
        len(new_plaintext),
        "bytes"
    )

    print(
        "    Encrypted Vault:",
        len(new_encrypted_vault),
        "bytes"
    )

    print(
        "    Nonce:",
        len(new_vault_nonce),
        "bytes"
    )

    print(
        "    AES-256-GCM Encrypt: OK"
    )

    # --------------------------------------------------------
    # 15. UPLOAD SERVER
    # --------------------------------------------------------

    print()
    print("[14] ĐỒNG BỘ LÊN SERVER")

    response = post_json(
        f"/api/vaults",
        {
            "user_id":
                user_id,

            "encrypted_vault":
                base64.b64encode(
                    new_encrypted_vault
                ).decode("ascii"),

            "vault_nonce":
                base64.b64encode(
                    new_vault_nonce
                ).decode("ascii"),

            "base_version":
                server_version
        }
    )

    if response.status_code == 409:

        data = response.json()

        print()
        print(
            "    VERSION CONFLICT"
        )

        print(
            "    Server Version:",
            data.get(
                "server_version"
            )
        )

        print(
            "    Phone Base Version:",
            data.get(
                "client_base_version"
            )
        )

        kem.close()

        print()
        print("=" * 60)
        print("RESULT: CONFLICT")
        print("=" * 60)

        print()
        print(
            "Vault trên Server đã được thiết bị khác "
            "cập nhật trước."
        )

        return

    if response.status_code >= 400:

        kem.close()

        raise RuntimeError(
            f"Server từ chối cập nhật: "
            f"HTTP {response.status_code}\n"
            f"{response.text}"
        )

    result = response.json()

    new_version = int(
        result.get(
            "version"
        )
    )

    print(
        "    Server Version cũ:",
        server_version
    )

    print(
        "    Server Version mới:",
        new_version
    )

    print(
        "    Upload Vault: OK"
    )

    # --------------------------------------------------------
    # 16. KIỂM TRA LẠI SERVER
    # --------------------------------------------------------

    print()
    print("[15] KIỂM TRA DỮ LIỆU SERVER")

    verify = get_json(
        f"/api/vaults/{user_id}"
    )

    verify_version = int(
        verify["version"]
    )

    verify_encrypted = base64.b64decode(
        verify["encrypted_vault"]
    )

    if verify_version != new_version:

        kem.close()

        raise RuntimeError(
            "Version Server không khớp."
        )

    if verify_encrypted != new_encrypted_vault:

        kem.close()

        raise RuntimeError(
            "Encrypted Vault trên Server "
            "không khớp."
        )

    print(
        "    Version:",
        verify_version
    )

    print(
        "    Encrypted Vault: MATCH"
    )

    print(
        "    Server Data Integrity: OK"
    )

    # --------------------------------------------------------
    # CLEANUP
    # --------------------------------------------------------

    kem.close()

    # --------------------------------------------------------
    # RESULT
    # --------------------------------------------------------

    print()
    print("=" * 60)
    print("RESULT: SUCCESS")
    print("=" * 60)

    print()
    print(
        "Phone đã cập nhật Password Vault lên Server."
    )

    print(
        "Version:",
        server_version,
        "->",
        new_version
    )

    print()
    print(
        "K_VAULT không thay đổi."
    )

    print(
        "Chỉ Encrypted Vault được cập nhật."
    )

    print(
        "K_VAULT plaintext không được gửi Server."
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