import getpass
import secrets
import string

from vault import PasswordVault
from vault_crypto import SecureVault
from storage import save_vault, load_vault


VAULT_FILE = "data/vault.json"


# ============================================================
# HIỂN THỊ
# ============================================================

def print_header(title):
    print("\n" + "=" * 60)
    print(title)
    print("=" * 60)


def mask_password(password):
    return "*" * max(8, len(password))


# ============================================================
# SINH MẬT KHẨU NGẪU NHIÊN
# ============================================================

def generate_password(length=16):

    characters = (
        string.ascii_letters
        + string.digits
        + "!@#$%^&*()-_=+"
    )

    while True:

        password = "".join(
            secrets.choice(characters)
            for _ in range(length)
        )

        # Đảm bảo có chữ thường
        has_lower = any(
            c.islower() for c in password
        )

        # Đảm bảo có chữ hoa
        has_upper = any(
            c.isupper() for c in password
        )

        # Đảm bảo có số
        has_digit = any(
            c.isdigit() for c in password
        )

        # Đảm bảo có ký tự đặc biệt
        has_special = any(
            c in "!@#$%^&*()-_=+"
            for c in password
        )

        if (
            has_lower
            and has_upper
            and has_digit
            and has_special
        ):
            return password


# ============================================================
# TẠO KHO MỚI
# ============================================================

def create_new_vault(secure):

    print_header("TAO KHO MAT KHAU MOI")

    password1 = getpass.getpass(
        "Nhap mat khau chinh: "
    )

    password2 = getpass.getpass(
        "Nhap lai mat khau chinh: "
    )

    if password1 != password2:

        print(
            "\n✗ Hai mat khau khong trung khop."
        )

        return None, None

    if len(password1) < 8:

        print(
            "\n✗ Mat khau chinh phai co it nhat 8 ky tu."
        )

        return None, None

    vault = PasswordVault()

    encrypted_vault = secure.create_vault(
        vault,
        password1
    )

    save_vault(encrypted_vault)

    print(
        "\n✓ Da tao kho mat khau."
    )

    print(
        f"✓ Da luu tai: {VAULT_FILE}"
    )

    return vault, password1


# ============================================================
# MỞ KHO
# ============================================================

def open_existing_vault(
    secure,
    encrypted_vault
):

    print_header("MO KHO MAT KHAU")

    password = getpass.getpass(
        "Nhap mat khau chinh: "
    )

    vault = PasswordVault()

    try:

        secure.decrypt_vault(
            encrypted_vault,
            password,
            vault
        )

        print(
            "\n✓ Mo kho thanh cong."
        )

        return vault, password

    except Exception:

        print(
            "\n✗ Mat khau sai "
            "hoac kho du lieu bi loi."
        )

        return None, None


# ============================================================
# HIỂN THỊ DANH SÁCH
# ============================================================

def show_entries(
    vault,
    show_password=False
):

    entries = vault.get_entries()

    print_header(
        "DANH SACH TAI KHOAN"
    )

    if not entries:

        print(
            "Kho dang rong."
        )

        return

    for i, entry in enumerate(
        entries,
        start=1
    ):

        password = entry["password"]

        if not show_password:

            password = mask_password(
                password
            )

        print(
            f"\n[{i}] {entry['service']}"
        )

        print(
            f"    Tai khoan : "
            f"{entry['username']}"
        )

        print(
            f"    Mat khau  : "
            f"{password}"
        )

        if entry.get("note"):

            print(
                f"    Ghi chu   : "
                f"{entry['note']}"
            )


# ============================================================
# TÌM KIẾM
# ============================================================

def search_entries(vault):

    keyword = input(
        "\nNhap tu khoa tim kiem: "
    ).strip().lower()

    if not keyword:

        print(
            "\n✗ Tu khoa khong duoc de trong."
        )

        return

    entries = vault.get_entries()

    found = []

    for index, entry in enumerate(
        entries
    ):

        service = (
            entry["service"]
            .lower()
        )

        username = (
            entry["username"]
            .lower()
        )

        note = (
            entry.get("note", "")
            .lower()
        )

        if (
            keyword in service
            or keyword in username
            or keyword in note
        ):

            found.append(
                (index, entry)
            )

    print_header(
        "KET QUA TIM KIEM"
    )

    if not found:

        print(
            "Khong tim thay tai khoan."
        )

        return

    for index, entry in found:

        print(
            f"\n[{index + 1}] "
            f"{entry['service']}"
        )

        print(
            f"    Tai khoan : "
            f"{entry['username']}"
        )

        print(
            f"    Mat khau  : "
            f"{mask_password(entry['password'])}"
        )

        if entry.get("note"):

            print(
                f"    Ghi chu   : "
                f"{entry['note']}"
            )


# ============================================================
# THÊM TÀI KHOẢN
# ============================================================

def add_entry(vault):

    print_header(
        "THEM TAI KHOAN"
    )

    service = input(
        "Dich vu/Website: "
    ).strip()

    username = input(
        "Ten tai khoan: "
    ).strip()

    print()
    print(
        "1. Tu nhap mat khau"
    )
    print(
        "2. Sinh mat khau ngau nhien"
    )

    choice = input(
        "Chon [1]: "
    ).strip() or "1"

    if choice == "2":

        try:

            length = int(
                input(
                    "Do dai mat khau [16]: "
                ) or "16"
            )

            if length < 8:

                print(
                    "\n✗ Do dai toi thieu la 8."
                )

                return

            password = generate_password(
                length
            )

            print(
                "\n✓ Mat khau duoc sinh:"
            )

            print(
                f"  {password}"
            )

        except ValueError:

            print(
                "\n✗ Do dai khong hop le."
            )

            return

    else:

        password = getpass.getpass(
            "Mat khau: "
        )

    note = input(
        "Ghi chu: "
    ).strip()

    if (
        not service
        or not username
        or not password
    ):

        print(
            "\n✗ Dich vu, tai khoan "
            "va mat khau khong duoc de trong."
        )

        return

    vault.add_entry(
        service,
        username,
        password,
        note
    )

    print(
        "\n✓ Da them tai khoan."
    )


# ============================================================
# SỬA TÀI KHOẢN
# ============================================================

def edit_entry(vault):

    entries = vault.get_entries()

    if not entries:

        print(
            "\nKho dang rong."
        )

        return

    show_entries(vault)

    try:

        index = int(
            input(
                "\nNhap so tai khoan muon sua: "
            )
        ) - 1

        if (
            index < 0
            or index >= len(entries)
        ):

            print(
                "\n✗ So tai khoan khong hop le."
            )

            return

    except ValueError:

        print(
            "\n✗ Vui long nhap so."
        )

        return

    entry = entries[index]

    print(
        "\n" + "-" * 60
    )

    print(
        f"Dang sua tai khoan: "
        f"{entry['service']}"
    )

    print(
        "-" * 60
    )

    print(
        "\nNhan Enter de giu nguyen "
        "gia tri hien tai."
    )

    # --------------------------------------------------------
    # DỊCH VỤ
    # --------------------------------------------------------

    service = input(
        f"Dich vu [{entry['service']}]: "
    ).strip()

    # --------------------------------------------------------
    # TÀI KHOẢN
    # --------------------------------------------------------

    username = input(
        f"Tai khoan [{entry['username']}]: "
    ).strip()

    # --------------------------------------------------------
    # MẬT KHẨU
    # --------------------------------------------------------

    print(
        "\nMat khau:"
    )

    print(
        "1. Tu nhap mat khau moi"
    )

    print(
        "2. Sinh mat khau ngau nhien"
    )

    print(
        "3. Giu nguyen mat khau hien tai"
    )

    password_choice = input(
        "Chon [3]: "
    ).strip() or "3"

    # --------------------------------------------------------
    # TỰ NHẬP
    # --------------------------------------------------------

    if password_choice == "1":

        password = getpass.getpass(
            "Nhap mat khau moi: "
        )

        if not password:

            print(
                "\n✗ Mat khau khong duoc de trong."
            )

            return

    # --------------------------------------------------------
    # SINH NGẪU NHIÊN
    # --------------------------------------------------------

    elif password_choice == "2":

        try:

            length = int(
                input(
                    "Do dai mat khau [16]: "
                ) or "16"
            )

            if length < 8:

                print(
                    "\n✗ Do dai toi thieu "
                    "la 8 ky tu."
                )

                return

            password = generate_password(
                length
            )

            print(
                "\n✓ Mat khau moi duoc sinh:"
            )

            print(
                f"  {password}"
            )

        except ValueError:

            print(
                "\n✗ Do dai khong hop le."
            )

            return

    # --------------------------------------------------------
    # GIỮ NGUYÊN
    # --------------------------------------------------------

    elif password_choice == "3":

        password = entry["password"]

        print(
            "\n✓ Giu nguyen mat khau hien tai."
        )

    else:

        print(
            "\n✗ Lua chon khong hop le."
        )

        return

    # --------------------------------------------------------
    # GHI CHÚ
    # --------------------------------------------------------

    note = input(
        f"Ghi chu [{entry.get('note', '')}]: "
    ).strip()

    # --------------------------------------------------------
    # CẬP NHẬT
    # --------------------------------------------------------

    if service:

        entry["service"] = service

    if username:

        entry["username"] = username

    entry["password"] = password

    if note:

        entry["note"] = note

    print(
        "\n✓ Da cap nhat tai khoan."
    )


# ============================================================
# XÓA TÀI KHOẢN
# ============================================================

def delete_entry(vault):

    entries = vault.get_entries()

    if not entries:

        print(
            "\nKho dang rong."
        )

        return

    show_entries(vault)

    try:

        index = int(
            input(
                "\nNhap so tai khoan muon xoa: "
            )
        ) - 1

        if (
            index < 0
            or index >= len(entries)
        ):

            print(
                "\n✗ So tai khoan khong hop le."
            )

            return

    except ValueError:

        print(
            "\n✗ Vui long nhap so."
        )

        return

    entry = entries[index]

    confirm = input(
        f"Xoa '{entry['service']}'? (y/n): "
    ).strip().lower()

    if confirm != "y":

        print(
            "\nDa huy."
        )

        return

    removed = entries.pop(index)

    print(
        f"\n✓ Da xoa tai khoan: "
        f"{removed['service']}"
    )


# ============================================================
# XEM MẬT KHẨU
# ============================================================

def show_password(vault):

    entries = vault.get_entries()

    if not entries:

        print(
            "\nKho dang rong."
        )

        return

    show_entries(vault)

    try:

        index = int(
            input(
                "\nNhap so tai khoan "
                "muon xem mat khau: "
            )
        ) - 1

        if (
            index < 0
            or index >= len(entries)
        ):

            print(
                "\n✗ So tai khoan khong hop le."
            )

            return

    except ValueError:

        print(
            "\n✗ Vui long nhap so."
        )

        return

    entry = entries[index]

    print(
        "\n" + "-" * 40
    )

    print(
        f"Dich vu   : "
        f"{entry['service']}"
    )

    print(
        f"Tai khoan : "
        f"{entry['username']}"
    )

    print(
        f"Mat khau  : "
        f"{entry['password']}"
    )

    if entry.get("note"):

        print(
            f"Ghi chu   : "
            f"{entry['note']}"
        )

    print(
        "-" * 40
    )


# ============================================================
# LƯU KHO
# ============================================================

def save_current_vault(
    secure,
    vault,
    encrypted_vault,
    master_password
):

    try:

        encrypted_vault = \
            secure.encrypt_existing_vault(
                vault,
                encrypted_vault,
                master_password
            )

        save_vault(
            encrypted_vault
        )

        print(
            "\n✓ Da luu kho an toan."
        )

        return encrypted_vault

    except Exception as e:

        print(
            "\n✗ Khong the luu kho."
        )

        print(
            f"Chi tiet: {e}"
        )

        return encrypted_vault


# ============================================================
# MENU QUẢN LÝ
# ============================================================

def vault_menu(
    secure,
    vault,
    encrypted_vault,
    master_password
):

    while True:

        print_header(
            "QUAN LY MAT KHAU"
        )

        print(
            "1. Xem danh sach"
        )

        print(
            "2. Tim kiem"
        )

        print(
            "3. Xem mat khau"
        )

        print(
            "4. Them tai khoan"
        )

        print(
            "5. Sua tai khoan"
        )

        print(
            "6. Xoa tai khoan"
        )

        print(
            "7. Sinh mat khau"
        )

        print(
            "8. Luu kho"
        )

        print(
            "9. Khoa kho"
        )

        print()

        choice = input(
            "Chon chuc nang: "
        ).strip()

        # ----------------------------------------------------
        # XEM DANH SÁCH
        # ----------------------------------------------------

        if choice == "1":

            show_entries(vault)

        # ----------------------------------------------------
        # TÌM KIẾM
        # ----------------------------------------------------

        elif choice == "2":

            search_entries(vault)

        # ----------------------------------------------------
        # XEM MẬT KHẨU
        # ----------------------------------------------------

        elif choice == "3":

            show_password(vault)

        # ----------------------------------------------------
        # THÊM
        # ----------------------------------------------------

        elif choice == "4":

            add_entry(vault)

        # ----------------------------------------------------
        # SỬA
        # ----------------------------------------------------

        elif choice == "5":

            edit_entry(vault)

        # ----------------------------------------------------
        # XÓA
        # ----------------------------------------------------

        elif choice == "6":

            delete_entry(vault)

        # ----------------------------------------------------
        # SINH MẬT KHẨU
        # ----------------------------------------------------

        elif choice == "7":

            try:

                length = int(
                    input(
                        "Do dai mat khau [16]: "
                    ) or "16"
                )

                if length < 8:

                    print(
                        "\n✗ Do dai toi thieu "
                        "la 8 ky tu."
                    )

                else:

                    print(
                        "\nMat khau:"
                    )

                    print(
                        generate_password(
                            length
                        )
                    )

            except ValueError:

                print(
                    "\n✗ Do dai khong hop le."
                )

        # ----------------------------------------------------
        # LƯU
        # ----------------------------------------------------

        elif choice == "8":

            encrypted_vault = \
                save_current_vault(
                    secure,
                    vault,
                    encrypted_vault,
                    master_password
                )

        # ----------------------------------------------------
        # KHÓA
        # ----------------------------------------------------

        elif choice == "9":

            print(
                "\n✓ Da khoa kho."
            )

            return

        else:

            print(
                "\n✗ Lua chon khong hop le."
            )


# ============================================================
# MAIN
# ============================================================

def main():

    secure = SecureVault()

    try:

        print_header(
            "PQC PASSWORD MANAGER"
        )

        encrypted_vault = load_vault()

        # ----------------------------------------------------
        # CHƯA CÓ VAULT
        # ----------------------------------------------------

        if encrypted_vault is None:

            print(
                "Chua tim thay kho mat khau."
            )

            print(
                "Chuong trinh se tao kho moi."
            )

            vault, master_password = \
                create_new_vault(
                    secure
                )

            if vault is None:

                return

            encrypted_vault = load_vault()

        # ----------------------------------------------------
        # ĐÃ CÓ VAULT
        # ----------------------------------------------------

        else:

            print(
                f"Da tim thay kho: "
                f"{VAULT_FILE}"
            )

            vault, master_password = \
                open_existing_vault(
                    secure,
                    encrypted_vault
                )

            if vault is None:

                return

        # ----------------------------------------------------
        # MỞ MENU
        # ----------------------------------------------------

        vault_menu(
            secure,
            vault,
            encrypted_vault,
            master_password
        )

    finally:

        secure.close()


# ============================================================
# CHẠY CHƯƠNG TRÌNH
# ============================================================

if __name__ == "__main__":

    main()