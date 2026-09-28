import base64
import requests

from vault.vault_crypto import VaultCrypto


SERVER_URL = "http://127.0.0.1:8000"
USER_ID = 1


def get_vault():

    response = requests.get(
        f"{SERVER_URL}/api/vaults/{USER_ID}",
        timeout=10
    )

    if response.status_code != 200:

        raise RuntimeError(
            f"Không lấy được Vault: "
            f"{response.status_code} "
            f"{response.text}"
        )

    return response.json()


def upload_vault(
    vault_data,
    vault_key,
    base_version
):

    nonce, encrypted_vault = \
        VaultCrypto.encrypt_vault(
            vault_data,
            vault_key
        )

    data = {
        "user_id": USER_ID,

        "encrypted_vault": base64.b64encode(
            encrypted_vault
        ).decode("ascii"),

        "vault_nonce": base64.b64encode(
            nonce
        ).decode("ascii"),

        "base_version": base_version
    }

    response = requests.post(
        f"{SERVER_URL}/api/vaults",
        json=data,
        timeout=10
    )

    return response


def main():

    print("=" * 60)
    print("VAULT CONFLICT TEST")
    print("TWO DEVICES - SAME BASE VERSION")
    print("=" * 60)

    # ==================================================
    # 1. LẤY VAULT HIỆN TẠI
    # ==================================================

    print()
    print("[1] LẤY VAULT HIỆN TẠI TỪ SERVER")

    current_vault = get_vault()

    current_version = \
        current_vault["version"]

    vault_id = \
        current_vault["vault_id"]

    print(
        "    Vault ID:",
        vault_id
    )

    print(
        "    Server Version:",
        current_version
    )

    # ==================================================
    # 2. TẠO K_VAULT
    # ==================================================

    print()
    print("[2] TẠO K_VAULT")

    vault_key = \
        VaultCrypto.generate_vault_key()

    print(
        "    K_VAULT:",
        len(vault_key),
        "bytes"
    )

    # ==================================================
    # 3. TẠO VAULT KIỂM THỬ MỚI
    # ==================================================

    print()
    print(
        "[3] TẠO DỮ LIỆU VAULT KIỂM THỬ"
    )

    initial_data = (
        b'{"accounts":['
        b'{"site":"example.com",'
        b'"username":"sang",'
        b'"password":"InitialPassword"}'
        b']}'
    )

    # ==================================================
    # 4. CẢ HAI THIẾT BỊ ĐỌC CÙNG VERSION
    # ==================================================

    print()
    print(
        "[4] PHONE-1 VÀ PHONE-2 ĐỌC CÙNG VERSION"
    )

    phone1_base_version = \
        current_version

    phone2_base_version = \
        current_version

    print(
        "    PHONE-1 Base Version:",
        phone1_base_version
    )

    print(
        "    PHONE-2 Base Version:",
        phone2_base_version
    )

    if phone1_base_version != \
            phone2_base_version:

        raise RuntimeError(
            "Hai thiết bị không có cùng Base Version."
        )

    print(
        "    Base Version giống nhau: OK"
    )

    # ==================================================
    # 5. PHONE-1 CẬP NHẬT
    # ==================================================

    print()
    print(
        "[5] PHONE-1 CẬP NHẬT VAULT"
    )

    phone1_data = (
        b'{"accounts":['
        b'{"site":"example.com",'
        b'"username":"sang",'
        b'"password":"PHONE1_PASSWORD"}'
        b']}'
    )

    response1 = upload_vault(
        phone1_data,
        vault_key,
        phone1_base_version
    )

    if response1.status_code != 200:

        raise RuntimeError(
            "PHONE-1 cập nhật thất bại: "
            f"{response1.status_code} "
            f"{response1.text}"
        )

    result1 = response1.json()

    phone1_new_version = \
        result1["version"]

    print(
        "    PHONE-1 cập nhật: OK"
    )

    print(
        "    Server Version:",
        phone1_new_version
    )

    if phone1_new_version != \
            phone1_base_version + 1:

        raise RuntimeError(
            "Server không tăng Version đúng."
        )

    # ==================================================
    # 6. PHONE-2 GỬI BẢN DỰA TRÊN VERSION CŨ
    # ==================================================

    print()
    print(
        "[6] PHONE-2 GỬI BẢN DỰA TRÊN VERSION CŨ"
    )

    phone2_data = (
        b'{"accounts":['
        b'{"site":"example.com",'
        b'"username":"sang",'
        b'"password":"PHONE2_PASSWORD"}'
        b']}'
    )

    response2 = upload_vault(
        phone2_data,
        vault_key,
        phone2_base_version
    )

    print(
        "    HTTP Status:",
        response2.status_code
    )

    # ==================================================
    # 7. KIỂM TRA CONFLICT
    # ==================================================

    print()
    print(
        "[7] KIỂM TRA XUNG ĐỘT"
    )

    if response2.status_code != 409:

        raise RuntimeError(
            "Server không phát hiện xung đột."
        )

    conflict = response2.json()

    print(
        "    Error:",
        conflict["error"]
    )

    print(
        "    Message:",
        conflict["message"]
    )

    print(
        "    Server Version:",
        conflict["server_version"]
    )

    print(
        "    Client Base Version:",
        conflict["client_base_version"]
    )

    if conflict["server_version"] != \
            phone1_new_version:

        raise RuntimeError(
            "Server Version trong Conflict "
            "không đúng."
        )

    if conflict["client_base_version"] != \
            phone2_base_version:

        raise RuntimeError(
            "Client Base Version trong Conflict "
            "không đúng."
        )

    print(
        "    Conflict Detection: OK"
    )

    # ==================================================
    # 8. KIỂM TRA SERVER KHÔNG BỊ GHI ĐÈ
    # ==================================================

    print()
    print(
        "[8] KIỂM TRA DỮ LIỆU SERVER"
    )

    final_data = get_vault()

    final_version = \
        final_data["version"]

    print(
        "    Server Version:",
        final_version
    )

    if final_version != \
            phone1_new_version:

        raise RuntimeError(
            "Server Version đã bị thay đổi "
            "sai sau Conflict."
        )

    # --------------------------------------------------
    # Lấy encrypted Vault
    # --------------------------------------------------

    encrypted_vault = base64.b64decode(
        final_data["encrypted_vault"]
    )

    nonce = base64.b64decode(
        final_data["vault_nonce"]
    )

    # --------------------------------------------------
    # Giải mã bằng K_VAULT
    # --------------------------------------------------

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

    # ==================================================
    # 9. KIỂM TRA PHONE-1 DATA VẪN CÒN
    # ==================================================

    print()
    print(
        "[9] KIỂM TRA PHONE-1 DATA"
    )

    if recovered_vault != \
            phone1_data:

        raise RuntimeError(
            "Server đã bị PHONE-2 ghi đè."
        )

    print(
        "    PHONE-1 Data vẫn còn: OK"
    )

    # ==================================================
    # 10. KIỂM TRA PHONE-2 DATA KHÔNG ĐƯỢC GHI
    # ==================================================

    print()
    print(
        "[10] KIỂM TRA PHONE-2 DATA"
    )

    if recovered_vault == \
            phone2_data:

        raise RuntimeError(
            "PHONE-2 đã ghi đè được Vault."
        )

    print(
        "    PHONE-2 Data không ghi đè: OK"
    )

    # ==================================================
    # 11. FINAL
    # ==================================================

    print()
    print(
        "[11] KIỂM TRA TOÀN BỘ"
    )

    print()
    print(
        "    PHONE-1 cập nhật: OK"
    )

    print(
        "    PHONE-2 dùng Version cũ: OK"
    )

    print(
        "    Server phát hiện Conflict: OK"
    )

    print(
        "    HTTP 409: OK"
    )

    print(
        "    Server không ghi đè dữ liệu mới: OK"
    )

    print(
        "    PHONE-1 Data vẫn được bảo toàn: OK"
    )

    print()
    print(
        "    RESULT: SUCCESS"
    )


if __name__ == "__main__":
    main()