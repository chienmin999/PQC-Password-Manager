from mlkem_manager import MLKEMManager
from crypto_utils import (
    derive_aes_key,
    encrypt_data,
    decrypt_data
)


def main():

    print("=" * 60)
    print("KIỂM TRA ML-KEM + HKDF + AES-GCM")
    print("=" * 60)

    # -------------------------------------------------
    # 1. ML-KEM
    # -------------------------------------------------

    print("\n[1] Tạo khóa ML-KEM-768")

    mlkem = MLKEMManager()

    public_key, secret_key = mlkem.generate_keypair()

    print("Public key:", len(public_key), "bytes")
    print("Secret key:", len(secret_key), "bytes")

    # -------------------------------------------------
    # 2. Encaps
    # -------------------------------------------------

    print("\n[2] Encaps")

    ciphertext, shared_secret_enc = (
        mlkem.encapsulate(public_key)
    )

    print("Ciphertext:", len(ciphertext), "bytes")
    print("Shared secret:", len(shared_secret_enc), "bytes")

    # -------------------------------------------------
    # 3. Decaps
    # -------------------------------------------------

    print("\n[3] Decaps")

    shared_secret_dec = (
        mlkem.decapsulate(ciphertext)
    )

    if shared_secret_enc != shared_secret_dec:
        raise RuntimeError(
            "Shared secret không khớp!"
        )

    print("✓ Shared secret khớp")

    # -------------------------------------------------
    # 4. HKDF
    # -------------------------------------------------

    print("\n[4] Dẫn xuất khóa AES-256")

    aes_key = derive_aes_key(
        shared_secret_enc
    )

    print("AES key:", len(aes_key), "bytes")

    # -------------------------------------------------
    # 5. Dữ liệu thử nghiệm
    # -------------------------------------------------

    original_data = (
        b"Tai khoan: nguyenvana\n"
        b"Mat khau: MatKhau@123\n"
    )

    print("\n[5] Dữ liệu gốc")
    print(original_data.decode())

    # -------------------------------------------------
    # 6. AES-GCM Encrypt
    # -------------------------------------------------

    print("[6] Mã hóa AES-256-GCM")

    nonce, encrypted_data = encrypt_data(
        original_data,
        aes_key
    )

    print("Nonce:", len(nonce), "bytes")
    print("Ciphertext:", len(encrypted_data), "bytes")

    # -------------------------------------------------
    # 7. AES-GCM Decrypt
    # -------------------------------------------------

    print("\n[7] Giải mã AES-256-GCM")

    decrypted_data = decrypt_data(
        encrypted_data,
        nonce,
        aes_key
    )

    print("Dữ liệu sau giải mã:")
    print(decrypted_data.decode())

    # -------------------------------------------------
    # 8. Kiểm tra
    # -------------------------------------------------

    print("\n[8] Kiểm tra")

    if decrypted_data == original_data:
        print("✓ THÀNH CÔNG")
        print(
            "✓ ML-KEM → HKDF → AES-GCM "
            "hoạt động chính xác."
        )
    else:
        print("✗ THẤT BẠI")

    mlkem.close()

    print("\n" + "=" * 60)


if __name__ == "__main__":
    main()