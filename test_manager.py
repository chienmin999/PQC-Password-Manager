from mlkem_manager import MLKEMManager


def main():

    print("=" * 60)
    print("KIỂM TRA ML-KEM MANAGER")
    print("=" * 60)

    mlkem = MLKEMManager()

    details = mlkem.get_details()

    print("\nThuật toán:", details["name"])
    print("Phiên bản:", details["version"])
    print("Mức NIST:", details["claimed_nist_level"])

    print("\n[1] KeyGen")

    public_key, secret_key = mlkem.generate_keypair()

    print("Khóa công khai:", len(public_key), "bytes")
    print("Khóa bí mật:", len(secret_key), "bytes")

    print("\n[2] Encaps")

    ciphertext, shared_secret_1 = mlkem.encapsulate(
        public_key
    )

    print("Ciphertext:", len(ciphertext), "bytes")
    print("Shared secret:", len(shared_secret_1), "bytes")

    print("\n[3] Decaps")

    shared_secret_2 = mlkem.decapsulate(ciphertext)

    print(
        "Shared secret sau Decaps:",
        len(shared_secret_2),
        "bytes"
    )

    print("\n[4] Kiểm tra")

    if shared_secret_1 == shared_secret_2:
        print("✓ ML-KEM MANAGER HOẠT ĐỘNG ĐÚNG")
    else:
        print("✗ LỖI: Shared secret không khớp")

    mlkem.close()


if __name__ == "__main__":
    main()