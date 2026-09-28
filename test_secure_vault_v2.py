from vault import PasswordVault
from vault_crypto import SecureVault
from storage import save_vault


MASTER_PASSWORD = "MatKhauChinh@2026"


def main():

    print("=" * 60)
    print("TEST SECURE VAULT V2")
    print("=" * 60)

    vault = PasswordVault()

    vault.add_entry(
        "Google",
        "student@gmail.com",
        "GooglePassword@123",
        "Tai khoan hoc tap"
    )

    vault.add_entry(
        "GitHub",
        "student",
        "GitHubPassword@456",
        "Kho ma nguon"
    )

    vault.add_entry(
        "Router",
        "admin",
        "RouterPassword@789",
        "Thiet bi mang"
    )

    secure = SecureVault()

    try:

        # ======================================================
        # 1. TAO KHO MAT KHAU
        # ======================================================

        print("\n[1] Tao kho mat khau...")

        encrypted = secure.create_vault(
            vault,
            MASTER_PASSWORD
        )

        print("    ✓ Tao thanh cong")

        # ======================================================
        # 2. LUU VAO data/vault.json
        # ======================================================

        print("\n[2] Luu kho mat khau...")

        save_vault(encrypted)

        print("    ✓ Da luu data\\vault.json")

        # ======================================================
        # 3. KIEM TRA SECRET KEY
        # ======================================================

        print("\n[3] Kiem tra secret key...")

        assert "secret_key" not in encrypted

        assert "protected_secret_key" in encrypted

        print("    ✓ Secret key khong nam truc tiep trong vault")

        # ======================================================
        # 4. GIAI MA
        # ======================================================

        print("\n[4] Giai ma...")

        restored = PasswordVault()

        secure.decrypt_vault(
            encrypted,
            MASTER_PASSWORD,
            restored
        )

        print("    ✓ Giai ma thanh cong")

        # ======================================================
        # 5. KIEM TRA DU LIEU
        # ======================================================

        print("\n[5] Kiem tra du lieu...")

        original = vault.get_entries()
        recovered = restored.get_entries()

        assert original == recovered

        print("    ✓ Du lieu trung khop")

        # ======================================================
        # 6. KIEM TRA MAT KHAU SAI
        # ======================================================

        print("\n[6] Kiem tra mat khau sai...")

        wrong_vault = PasswordVault()

        try:

            secure.decrypt_vault(
                encrypted,
                "SaiMatKhau@2026",
                wrong_vault
            )

            print(
                "    ✗ LOI: mat khau sai "
                "nhung van giai ma duoc"
            )

        except Exception:

            print("    ✓ Mat khau sai bi tu choi")

        # ======================================================
        # KET QUA
        # ======================================================

        print("\n" + "=" * 60)
        print("✓ SECURE VAULT V2 HOAT DONG DUNG")
        print("=" * 60)

    finally:

        secure.close()


if __name__ == "__main__":
    main()