from vault import PasswordVault
from vault_crypto import SecureVault


def main():

    print("=" * 70)
    print("KIỂM TRA MÃ HÓA KHO MẬT KHẨU")
    print("=" * 70)

    # ==================================================
    # 1. Tạo kho mật khẩu
    # ==================================================

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

    print(
        "Số tài khoản:",
        len(vault.get_entries())
    )

    # Lưu bản gốc để so sánh
    original_entries = vault.get_entries().copy()

    # ==================================================
    # 2. Mã hóa
    # ==================================================

    print("\n[2] Mã hóa kho")

    secure_vault = SecureVault()

    encrypted_vault = (
        secure_vault.encrypt_vault(vault)
    )

    print(
        "Thuật toán KEM:",
        encrypted_vault["kem"]
    )

    print(
        "KDF:",
        encrypted_vault["kdf"]
    )

    print(
        "Mã hóa dữ liệu:",
        encrypted_vault["cipher"]
    )

    print(
        "Độ dài KEM ciphertext:",
        len(
            encrypted_vault["kem_ciphertext"]
        ),
        "ký tự Base64"
    )

    print(
        "Độ dài dữ liệu mã hóa:",
        len(
            encrypted_vault["encrypted_data"]
        ),
        "ký tự Base64"
    )

    # ==================================================
    # 3. Kiểm tra dữ liệu đã mã hóa
    # ==================================================

    print("\n[3] Dữ liệu sau mã hóa")

    print(
        encrypted_vault["encrypted_data"][:100]
        + "..."
    )

    # ==================================================
    # 4. Giải mã
    # ==================================================

    print("\n[4] Giải mã")

    restored_vault = PasswordVault()

    secure_vault.decrypt_vault(
        encrypted_vault,
        restored_vault
    )

    # ==================================================
    # 5. Kiểm tra
    # ==================================================

    print(
        "\nSố tài khoản sau giải mã:",
        len(restored_vault.get_entries())
    )

    if (
        restored_vault.get_entries()
        == original_entries
    ):
        print(
            "\n✓ THÀNH CÔNG"
        )

        print(
            "✓ Kho mật khẩu sau giải mã "
            "giống hoàn toàn dữ liệu ban đầu."
        )
    else:
        print(
            "\n✗ THẤT BẠI"
        )

    secure_vault.close()

    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()