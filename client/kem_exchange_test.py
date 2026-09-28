from common.mlkem_manager import MLKEMManager


def main():

    print("=" * 60)
    print("ML-KEM-768 KEY EXCHANGE TEST")
    print("=" * 60)

    pc = MLKEMManager()
    phone = MLKEMManager()

    try:

        # ==================================================
        # 1. PHONE - KeyGen()
        # ==================================================

        phone_public_key, phone_secret_key = \
            phone.generate_keypair()

        print("\n[1] PHONE - KeyGen()")

        print(
            "    Public Key :",
            len(phone_public_key),
            "bytes"
        )

        print(
            "    Secret Key :",
            len(phone_secret_key),
            "bytes"
        )

        # ==================================================
        # 2. PC - Encaps()
        # ==================================================

        pc_ciphertext, pc_shared_secret = \
            pc.encapsulate(phone_public_key)

        print("\n[2] PC - Encaps()")

        print(
            "    Ciphertext :",
            len(pc_ciphertext),
            "bytes"
        )

        print(
            "    Shared Secret:",
            len(pc_shared_secret),
            "bytes"
        )

        # ==================================================
        # 3. PHONE - Decaps()
        # ==================================================

        phone_shared_secret = \
            phone.decapsulate(pc_ciphertext)

        print("\n[3] PHONE - Decaps()")

        print(
            "    Shared Secret:",
            len(phone_shared_secret),
            "bytes"
        )

        # ==================================================
        # 4. So sánh Shared Secret
        # ==================================================

        matched = (
            pc_shared_secret ==
            phone_shared_secret
        )

        print("\n[4] KIỂM TRA SHARED SECRET")

        print(
            "    PC Shared Secret    :",
            pc_shared_secret.hex()
        )

        print(
            "    PHONE Shared Secret :",
            phone_shared_secret.hex()
        )

        print()

        if matched:

            print("    RESULT: SUCCESS")
            print(
                "    PC và PHONE có cùng Shared Secret."
            )

        else:

            print("    RESULT: FAILED")
            print(
                "    Shared Secret không giống nhau."
            )

    finally:

        pc.close()
        phone.close()


if __name__ == "__main__":
    main()