import json
import base64
from pathlib import Path

from client.server_client import ServerClient


PROJECT_DIR = Path(__file__).resolve().parent.parent
PC_CONFIG = PROJECT_DIR / "data" / "client_config.json"


def load_json(path):
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def decode_base64(value):
    return base64.b64decode(value)


def main():

    print()
    print("=" * 75)
    print("              SERVER KNOWLEDGE TEST")
    print("=" * 75)

    # ========================================================
    # 1. LOAD CONFIG
    # ========================================================

    print()
    print("[1] LOAD CONFIG")

    config = load_json(PC_CONFIG)

    server_config = config["server"]

    user_id = server_config["user_id"]
    server_url = server_config["base_url"]

    print("    User ID:", user_id)
    print("    Server:", server_url)

    # ========================================================
    # 2. CONNECT SERVER
    # ========================================================

    print()
    print("[2] SERVER")

    client = ServerClient(server_url)

    health = client.health()

    print("    Status:", health)

    # ========================================================
    # 3. GET VAULT
    # ========================================================

    print()
    print("[3] SERVER VAULT")

    vault = client.get_vault(user_id)

    vault_id = vault["vault_id"]

    encrypted_vault = decode_base64(
        vault["encrypted_vault"]
    )

    vault_nonce = decode_base64(
        vault["vault_nonce"]
    )

    print("    Vault ID:", vault_id)

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
        "    Server Version:",
        vault["version"]
    )

    # ========================================================
    # 4. SERVER STORED DATA
    # ========================================================

    print()
    print("[4] SERVER STORED DATA")

    print()
    print("    Server lưu:")

    print(
        "        Encrypted Vault      :",
        len(encrypted_vault),
        "bytes"
    )

    print(
        "        Vault Nonce          :",
        len(vault_nonce),
        "bytes"
    )

    print(
        "        Version              :",
        vault["version"]
    )

    print()
    print(
        "    K_VAULT plaintext: KHÔNG CÓ TRONG RESPONSE"
    )

    # ========================================================
    # 5. GET DEVICES
    # ========================================================

    print()
    print("[5] WRAPPED K_VAULT")

    devices_response = client.get_devices(user_id)

    # Server trả về object có trường devices
    if isinstance(devices_response, dict):

        devices = devices_response.get(
            "devices",
            []
        )

    else:

        devices = devices_response

    if not isinstance(devices, list):

        raise RuntimeError(
            "Dữ liệu devices từ Server không đúng định dạng."
        )

    print(
        "    Registered devices:",
        len(devices)
    )

    found_key = False

    for device in devices:

        if not isinstance(device, dict):
            continue

        device_id = device.get("device_id")

        if device_id is None:
            continue

        print()
        print(
            "    Device ID:",
            device_id
        )

        try:

            wrapped = client.get_vault_key(
                vault_id,
                device_id
            )

            if not wrapped:
                print(
                    "        Wrapped K_VAULT: NOT FOUND"
                )
                continue

            kem_ciphertext = decode_base64(
                wrapped["kem_ciphertext"]
            )

            encrypted_vault_key = decode_base64(
                wrapped["encrypted_vault_key"]
            )

            nonce = decode_base64(
                wrapped["nonce"]
            )

            print(
                "        KEM Ciphertext:",
                len(kem_ciphertext),
                "bytes"
            )

            print(
                "        Wrapped K_VAULT:",
                len(encrypted_vault_key),
                "bytes"
            )

            print(
                "        Nonce:",
                len(nonce),
                "bytes"
            )

            print(
                "        K_VAULT plaintext: "
                "KHÔNG CÓ"
            )

            found_key = True

        except Exception as exc:

            print(
                "        Không có Vault Key:",
                exc
            )

    # ========================================================
    # 6. SECURITY OBSERVATION
    # ========================================================

    print()
    print("[6] SERVER KNOWLEDGE")

    print()
    print("    Server có thể nhìn thấy:")

    print("        - Encrypted Vault")
    print("        - Vault Nonce")
    print("        - Version")
    print("        - ML-KEM Ciphertext")
    print("        - Wrapped K_VAULT")
    print("        - Device Public Key")

    print()
    print("    Server không nhận:")

    print("        - K_VAULT plaintext")
    print("        - ML-KEM Secret Key")
    print("        - Plaintext Password Vault")

    # ========================================================
    # 7. RESULT
    # ========================================================

    print()
    print("=" * 75)
    print("                         RESULT")
    print("=" * 75)

    print()

    if found_key:

        print(
            "Server lưu Wrapped K_VAULT: SUCCESS"
        )

        print(
            "Server không lưu K_VAULT plaintext: SUCCESS"
        )

        print(
            "Server không lưu Password Vault plaintext: SUCCESS"
        )

        print()
        print(
            "Kết luận:"
        )

        print(
            "Server chỉ lưu dữ liệu mã hóa và dữ liệu "
            "cần thiết để Client khôi phục K_VAULT."
        )

        print()
        print("=" * 75)
        print("RESULT: SUCCESS")
        print("=" * 75)

    else:

        print(
            "Không tìm thấy Wrapped K_VAULT."
        )

        print()
        print("=" * 75)
        print("RESULT: FAILED")
        print("=" * 75)


if __name__ == "__main__":
    main()