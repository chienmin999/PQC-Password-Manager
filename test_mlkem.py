import oqs

ALGORITHM = "ML-KEM-768"

print("=" * 60)
print("KIỂM TRA ML-KEM-768")
print("=" * 60)

print("\n[1] Kiểm tra thuật toán")
print("Thuật toán:", ALGORITHM)
print("Được kích hoạt:", oqs.is_kem_enabled(ALGORITHM))

with oqs.KeyEncapsulation(ALGORITHM) as kem:

    print("\n[2] Thông tin ML-KEM-768")
    print("Tên:", kem.details["name"])
    print("Phiên bản:", kem.details["version"])
    print("Mức NIST:", kem.details["claimed_nist_level"])
    print("IND-CCA:", kem.details["is_ind_cca"])

    print("\n[3] KeyGen")
    public_key = kem.generate_keypair()
    secret_key = kem.export_secret_key()

    print("Public key :", len(public_key), "bytes")
    print("Secret key :", len(secret_key), "bytes")

    print("\n[4] Encaps")
    ciphertext, shared_secret_enc = kem.encap_secret(public_key)

    print("Ciphertext :", len(ciphertext), "bytes")
    print("Shared secret:", len(shared_secret_enc), "bytes")

    print("\n[5] Decaps")
    shared_secret_dec = kem.decap_secret(ciphertext)

    print("Shared secret sau Decaps:",
          len(shared_secret_dec), "bytes")

    print("\n[6] Kiểm tra bí mật chung")

    if shared_secret_enc == shared_secret_dec:
        print("✓ THÀNH CÔNG")
        print("✓ Encaps và Decaps tạo cùng một bí mật chung.")
    else:
        print("✗ THẤT BẠI")
        print("✗ Hai bí mật chung không giống nhau.")

print("\n" + "=" * 60)
print("HOÀN TẤT KIỂM TRA ML-KEM-768")
print("=" * 60)