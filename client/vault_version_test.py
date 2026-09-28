import base64
import requests

from vault.vault_crypto import VaultCrypto


SERVER_URL = "http://127.0.0.1:8000"
USER_ID = 1


def upload_vault(encrypted_vault, vault_nonce):

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
            f"Upload Vault thất bại: "
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
            f"Download Vault thất bại: "
            f"{response.status_code} "
            f"{response.text}"
        )

    data = response.json()

    return data


def main():

    print("=" * 60)
    print("VAULT VERSION TEST")
    print("=" * 60)

    # ==================================================
    # 1. TẠO K_VAULT
    # ==================================================

    print()
    print("[1] TẠO K_VAULT")

    vault_key = \
        VaultCrypto.generate_vault_key()

    print(
        "    K_VAULT:",
        len(vault_key),
        "bytes"
    )

    # ==================================================
    # 2. VAULT VERSION 1
    # ==================================================

    print()
    print("[2] TẠO VAULT VERSION 1")

    vault_data_v1 = (
        b'{"accounts":['
        b'{"site":"example.com",'
        b'"username":"sang",'
        b'"password":"Password_V1"}'
        b']}'
    )

    nonce_v1, encrypted_vault_v1 = \
        VaultCrypto.encrypt_vault(
            vault_data_v1,
            vault_key
        )

    result_v1 = upload_vault(
        encrypted_vault_v1,
        nonce_v1
    )

    print(
        "    Server Version:",
        result_v1["version"]
    )

    version_v1 = result_v1["version"]

    # ==================================================
    # 3. DOWNLOAD VERSION 1
    # ==================================================

    print()
    print("[3] DOWNLOAD VERSION 1")

    server_v1 = download_vault()

    print(
        "    Vault ID:",
        server_v1["vault_id"]
    )

    print(
        "    Version:",
        server_v1["version"]
    )

    if server_v1["version"] != version_v1:

        raise RuntimeError(
            "Version 1 không đúng."
        )

    # ==================================================
    # 4. THAY ĐỔI PASSWORD
    # ==================================================

    print()
    print(
        "[4] PHONE-1 THAY ĐỔI PASSWORD"
    )

    vault_data_v2 = (
        b'{"accounts":['
        b'{"site":"example.com",'
        b'"username":"sang",'
        b'"password":"Password_V2"}'
        b']}'
    )

    nonce_v2, encrypted_vault_v2 = \
        VaultCrypto.encrypt_vault(
            vault_data_v2,
            vault_key
        )

    result_v2 = upload_vault(
        encrypted_vault_v2,
        nonce_v2
    )

    print(
        "    Server Version:",
        result_v2["version"]
    )

    version_v2 = result_v2["version"]

    # ==================================================
    # 5. KIỂM TRA VERSION
    # ==================================================

    print()
    print(
        "[5] KIỂM TRA VERSION"
    )

    print(
        "    Version trước:",
        version_v1
    )

    print(
        "    Version sau:",
        version_v2
    )

    if version_v2 != version_v1 + 1:

        raise RuntimeError(
            "Server không tăng Version đúng."
        )

    print(
        "    Version tăng: OK"
    )

    # ==================================================
    # 6. PHONE-2 ĐỒNG BỘ
    # ==================================================

    print()
    print(
        "[6] PHONE-2 DOWNLOAD VAULT"
    )

    server_v2 = download_vault()

    print(
        "    Version nhận được:",
        server_v2["version"]
    )

    encrypted_vault = base64.b64decode(
        server_v2["encrypted_vault"]
    )

    nonce = base64.b64decode(
        server_v2["vault_nonce"]
    )

    # ==================================================
    # 7. PHONE-2 GIẢI MÃ
    # ==================================================

    print()
    print(
        "[7] PHONE-2 DECRYPT VAULT"
    )

    recovered_vault = \
        VaultCrypto.decrypt_vault(
            encrypted_vault,
            nonce,
            vault_key
        )

    print(
        "    Vault:"
    )

    print(
        "    ",
        recovered_vault.decode("utf-8")
    )

    if recovered_vault != \
            vault_data_v2:

        raise RuntimeError(
            "PHONE-2 không nhận được "
            "Vault Version 2."
        )

    print(
        "    Password mới: OK"
    )

    # ==================================================
    # 8. FINAL
    # ==================================================

    print()
    print(
        "[8] KIỂM TRA TOÀN BỘ"
    )

    print()
    print(
        "    Version 1: OK"
    )

    print(
        "    PHONE-1 cập nhật Vault: OK"
    )

    print(
        "    Server tăng Version: OK"
    )

    print(
        "    PHONE-2 đồng bộ Version 2: OK"
    )

    print(
        "    PHONE-2 thấy Password mới: OK"
    )

    print()
    print(
        "    RESULT: SUCCESS"
    )


if __name__ == "__main__":
    main()