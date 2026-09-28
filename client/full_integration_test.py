import json
import base64
from pathlib import Path
from getpass import getpass

from client.server_client import ServerClient
from common.mlkem_manager import MLKEMManager
from common.crypto_utils import (
    derive_aes_key,
    decrypt_data,
)
from common.secret_key_protection import (
    SecretKeyProtection,
)


PROJECT_DIR = Path(__file__).resolve().parent.parent

PC_CONFIG = PROJECT_DIR / "data" / "client_config.json"
PHONE_CONFIG = PROJECT_DIR / "data" / "phone_config.json"


def load_json(path):

    if not path.exists():
        raise FileNotFoundError(
            f"Không tìm thấy file:\n{path}"
        )

    with open(
        path,
        "r",
        encoding="utf-8"
    ) as file:
        return json.load(file)


def decode_base64(value):

    if isinstance(value, bytes):
        return value

    return base64.b64decode(value)


def main():

    print()
    print("=" * 75)
    print("              FULL PQC PASSWORD MANAGER TEST")
    print("=" * 75)

    # ========================================================
    # 1. PC CONFIG
    # ========================================================

    print()
    print("[1] PC CONFIG")

    pc_config = load_json(
        PC_CONFIG
    )

    pc_server = pc_config["server"]

    user_id = pc_server["user_id"]
    pc_device_id = pc_server["device_id"]
    server_url = pc_server["base_url"]

    print(
        "    Config:",
        PC_CONFIG
    )

    print(
        "    User ID:",
        user_id
    )

    print(
        "    PC Device ID:",
        pc_device_id
    )

    print(
        "    Server:",
        server_url
    )

    print(
        "    PC config: PASS"
    )

    # ========================================================
    # 2. PHONE CONFIG
    # ========================================================

    print()
    print("[2] PHONE CONFIG")

    phone_config = load_json(
        PHONE_CONFIG
    )

    phone_device = phone_config["device"]
    phone_secret = phone_config["secret_key"]

    phone_device_id = phone_device["device_id"]
    phone_user_id = phone_device["user_id"]

    print(
        "    Config:",
        PHONE_CONFIG
    )

    print(
        "    Phone User ID:",
        phone_user_id
    )

    print(
        "    Phone Device ID:",
        phone_device_id
    )

    if phone_user_id != user_id:
        raise RuntimeError(
            "PC và Phone không thuộc cùng User ID."
        )

    print(
        "    User ID consistency: PASS"
    )

    print(
        "    Phone config: PASS"
    )

    # ========================================================
    # 3. SERVER
    # ========================================================

    print()
    print("[3] SERVER")

    client = ServerClient(
        server_url
    )

    health = client.health()

    print(
        "    Server:",
        health
    )

    if health.get("status") != "ok":
        raise RuntimeError(
            "Server không ở trạng thái OK."
        )

    print(
        "    Server connection: PASS"
    )

    # ========================================================
    # 4. GET VAULT
    # ========================================================

    print()
    print("[4] SERVER VAULT")

    server_vault = client.get_vault(
        user_id
    )

    vault_id = server_vault["vault_id"]
    server_version = server_vault["version"]

    encrypted_vault = decode_base64(
        server_vault["encrypted_vault"]
    )

    vault_nonce = decode_base64(
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

    print(
        "    Server Vault: PASS"
    )

    # ========================================================
    # 5. GET WRAPPED K_VAULT
    # ========================================================

    print()
    print("[5] PHONE WRAPPED K_VAULT")

    wrapped_key = client.get_vault_key(
        vault_id,
        phone_device_id
    )

    kem_ciphertext = decode_base64(
        wrapped_key["kem_ciphertext"]
    )

    encrypted_vault_key = decode_base64(
        wrapped_key["encrypted_vault_key"]
    )

    wrap_nonce = decode_base64(
        wrapped_key["nonce"]
    )

    print(
        "    Phone Device ID:",
        phone_device_id
    )

    print(
        "    KEM Ciphertext:",
        len(kem_ciphertext),
        "bytes"
    )

    print(
        "    Wrapped K_VAULT:",
        len(encrypted_vault_key),
        "bytes"
    )

    print(
        "    Wrap Nonce:",
        len(wrap_nonce),
        "bytes"
    )

    print(
        "    Wrapped K_VAULT: PASS"
    )

    # ========================================================
    # 6. PHONE SECRET KEY
    # ========================================================

    print()
    print("[6] PHONE ML-KEM SECRET KEY")

    encrypted_phone_secret_key = decode_base64(
        phone_secret["encrypted_secret_key"]
    )

    phone_salt = decode_base64(
        phone_secret["salt"]
    )

    phone_nonce = decode_base64(
        phone_secret["nonce"]
    )

    print(
        "    Encrypted Secret Key:",
        len(encrypted_phone_secret_key),
        "bytes"
    )

    print(
        "    Scrypt Salt:",
        len(phone_salt),
        "bytes"
    )

    print(
        "    AES-GCM Nonce:",
        len(phone_nonce),
        "bytes"
    )

    # --------------------------------------------------------
    # NHẬP MASTER PASSWORD
    # --------------------------------------------------------

    phone_master_password = getpass(
        "    Nhập Master Password của Phone: "
    )

    phone_secret_key = (
        SecretKeyProtection.recover_secret_key(
            encrypted_phone_secret_key,
            phone_master_password,
            phone_salt,
            phone_nonce
        )
    )

    print(
        "    Recovered Secret Key:",
        len(phone_secret_key),
        "bytes"
    )

    if len(phone_secret_key) != 2400:
        raise RuntimeError(
            "ML-KEM-768 Secret Key không có độ dài 2400 bytes."
        )

    print(
        "    Secret Key recovery: PASS"
    )

    # ========================================================
    # 7. ML-KEM DECAPS
    # ========================================================

    print()
    print("[7] PHONE ML-KEM DECAPS()")

    phone_kem = MLKEMManager(
        secret_key=phone_secret_key
    )

    shared_secret = phone_kem.decapsulate(
        kem_ciphertext
    )

    print(
        "    Shared Secret:",
        len(shared_secret),
        "bytes"
    )

    if len(shared_secret) != 32:
        raise RuntimeError(
            "Shared Secret không có độ dài 32 bytes."
        )

    print(
        "    ML-KEM Decaps(): PASS"
    )

    # ========================================================
    # 8. HKDF
    # ========================================================

    print()
    print("[8] HKDF-SHA256")

    wrap_key = derive_aes_key(
        shared_secret
    )

    print(
        "    Derived AES Key:",
        len(wrap_key),
        "bytes"
    )

    print(
        "    HKDF-SHA256: PASS"
    )

    # ========================================================
    # 9. RECOVER K_VAULT
    # ========================================================

    print()
    print("[9] RECOVER K_VAULT")

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

    if len(k_vault) != 32:
        raise RuntimeError(
            "K_VAULT không có độ dài 32 bytes."
        )

    print(
        "    K_VAULT recovery: PASS"
    )

    # ========================================================
    # 10. DECRYPT VAULT
    # ========================================================

    print()
    print("[10] PHONE DECRYPT VAULT")

    vault_plaintext = decrypt_data(
        encrypted_vault,
        vault_nonce,
        k_vault
    )

    print(
        "    Plaintext Vault:",
        len(vault_plaintext),
        "bytes"
    )

    vault_data = json.loads(
        vault_plaintext.decode("utf-8")
    )

    entries = vault_data.get(
        "entries",
        []
    )

    print(
        "    Password entries:",
        len(entries)
    )

    print(
        "    AES-256-GCM Decrypt: PASS"
    )

    # ========================================================
    # 11. DISPLAY VAULT
    # ========================================================

    print()
    print("[11] VAULT DATA")

    for index, entry in enumerate(
        entries,
        start=1
    ):

        print()
        print(
            f"    Entry {index}:"
        )

        print(
            "        Website :",
            entry.get("website")
        )

        print(
            "        Username:",
            entry.get("username")
        )

        print(
            "        Password:",
            entry.get("password")
        )

    print()
    print(
        "    Vault data recovery: PASS"
    )

    phone_kem.close()

    # ========================================================
    # RESULT
    # ========================================================

    print()
    print("=" * 75)
    print("                         RESULT")
    print("=" * 75)

    print()
    print(
        "PC Config: SUCCESS"
    )

    print(
        "Phone Config: SUCCESS"
    )

    print(
        "User ID Consistency: SUCCESS"
    )

    print(
        "Server Connection: SUCCESS"
    )

    print(
        "Server Vault: SUCCESS"
    )

    print(
        "Phone Secret Key Recovery: SUCCESS"
    )

    print(
        "ML-KEM Decaps(): SUCCESS"
    )

    print(
        "K_VAULT Recovery: SUCCESS"
    )

    print(
        "AES-256-GCM Vault Decrypt: SUCCESS"
    )

    print(
        "Password Vault Recovery: SUCCESS"
    )

    print()
    print(
        "PC → Server → Phone: SUCCESS"
    )

    print()
    print("=" * 75)
    print("RESULT: SUCCESS")
    print("=" * 75)


if __name__ == "__main__":
    main()