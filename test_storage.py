from vault import PasswordVault
from vault_crypto import SecureVault
from storage import save_vault, load_vault


def main():

    print("=" * 70)
    print("KIỂM TRA LƯU KHO MẬT KHẨU ĐÃ MÃ HÓA")
    print("=" * 70)

    # --------------------------------------------------
    # 1. Tạo kho
    # --------------------------------------------------

    print("\n[1] Tạo kho mật khẩu")

    vault = PasswordVault()

    vault.add_entry(
        service="Google",
        username="nguyenvana@gmail.com",
        password="Google@123456",
        note="Tài khoản cá nhân"
    )

    vault.add_entry(
        service="GitHub",
        username="nguyenvana",
        password="GitHub@123456",
        note="Tài khoản lập trình"
    )

    vault.add_entry(
        service="Router",
        username="admin",
        password="Admin@123456",
        note="Thiết bị mạng"
    )

    original = vault.get_entries().copy()

    print(
        "Số tài khoản:",
        len(original)
    )

    # --------------------------------------------------
    # 2. Mã hóa
    # --------------------------------------------------

    print("\n[2] Mã hóa")

    secure = SecureVault()

    encrypted = secure.encrypt_vault(
        vault
    )

    # --------------------------------------------------
    # 3. Lưu file
    # --------------------------------------------------

    print("\n[3] Lưu file")

    save_vault(encrypted)

    print(
        "Đã lưu:",
        "data/vault.json"
    )

    # --------------------------------------------------
    # 4. Đọc file
    # --------------------------------------------------

    print("\n[4] Đọc file")

    loaded = load_vault()

    if loaded is None:
        print("✗ Không tìm thấy file")
        return

    print(
        "KEM:",
        loaded["kem"]
    )

    print(
        "KDF:",
        loaded["kdf"]
    )

    print(
        "Cipher:",
        loaded["cipher"]
    )

    # --------------------------------------------------
    # 5. Giải mã
    # --------------------------------------------------

    print("\n[5] Giải mã")

    restored = PasswordVault()

    secure.decrypt_vault(
        loaded,
        restored
    )

    # --------------------------------------------------
    # 6. Kiểm tra
    # --------------------------------------------------

    restored_entries = (
        restored.get_entries()
    )

    print(
        "Số tài khoản sau giải mã:",
        len(restored_entries)
    )

    if restored_entries == original:

        print(
            "\n✓ THÀNH CÔNG"
        )

        print(
            "✓ Dữ liệu lưu trên file "
            "được đọc và giải mã chính xác."
        )

    else:

        print(
            "\n✗ THẤT BẠI"
        )

    secure.close()

    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()