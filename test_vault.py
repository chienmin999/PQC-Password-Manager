from vault import PasswordVault


def main():

    print("=" * 60)
    print("KIỂM TRA KHO MẬT KHẨU")
    print("=" * 60)

    vault = PasswordVault()

    print("\n[1] Thêm tài khoản")

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

    print("Số lượng tài khoản:",
          len(vault.get_entries()))

    print("\n[2] Nội dung kho")

    for index, entry in enumerate(
        vault.get_entries(),
        start=1
    ):
        print(
            f"{index}. "
            f"{entry['service']} - "
            f"{entry['username']}"
        )

    print("\n[3] Chuyển thành JSON")

    data = vault.to_json()

    print(data.decode("utf-8"))

    print("\n[4] Khôi phục từ JSON")

    vault2 = PasswordVault()

    vault2.from_json(data)

    print(
        "Số lượng tài khoản sau khôi phục:",
        len(vault2.get_entries())
    )

    if vault2.get_entries() == vault.get_entries():
        print("\n✓ KHO MẬT KHẨU HOẠT ĐỘNG ĐÚNG")
    else:
        print("\n✗ KHO MẬT KHẨU CÓ LỖI")

    print("\n" + "=" * 60)


if __name__ == "__main__":
    main()