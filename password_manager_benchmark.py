import time
import statistics
import csv
import base64
from pathlib import Path

import oqs

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


ALGORITHM = "ML-KEM-768"
ROUNDS = 100

MASTER_PASSWORD = "BenchmarkPassword@2026"

TEST_DATA = (
    b'{"service":"Google",'
    b'"username":"student@example.com",'
    b'"password":"ExamplePassword@123",'
    b'"note":"Benchmark data"}'
)


# ============================================================
# ĐO THỜI GIAN
# ============================================================

def measure(function, rounds=ROUNDS):

    times = []
    last_result = None

    for _ in range(rounds):

        start = time.perf_counter()

        last_result = function()

        end = time.perf_counter()

        times.append(
            (end - start) * 1000
        )

    return times, last_result


def calculate_statistics(times):

    return {
        "min": min(times),
        "max": max(times),
        "average": statistics.mean(times),
        "median": statistics.median(times)
    }


def print_result(name, result):

    print(f"\n{name}")

    print(
        f"  Min     : {result['min']:.4f} ms"
    )

    print(
        f"  Max     : {result['max']:.4f} ms"
    )

    print(
        f"  Average : {result['average']:.4f} ms"
    )

    print(
        f"  Median  : {result['median']:.4f} ms"
    )


# ============================================================
# SCRYPT
# ============================================================

def derive_scrypt_key(password, salt):

    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1
    )

    return kdf.derive(
        password.encode("utf-8")
    )


# ============================================================
# HKDF
# ============================================================

def derive_hkdf_key(shared_secret):

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"PQC-Password-Manager-AES-256"
    )

    return hkdf.derive(
        shared_secret
    )


# ============================================================
# AES-GCM ENCRYPT
# ============================================================

def aes_encrypt(data, key):

    nonce = b"\x01" * 12

    aes = AESGCM(key)

    ciphertext = aes.encrypt(
        nonce,
        data,
        None
    )

    return nonce, ciphertext


# ============================================================
# AES-GCM DECRYPT
# ============================================================

def aes_decrypt(
    ciphertext,
    nonce,
    key
):

    aes = AESGCM(key)

    return aes.decrypt(
        nonce,
        ciphertext,
        None
    )


# ============================================================
# LƯU CSV
# ============================================================

def save_results(results):

    output_dir = Path("results")

    output_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    output_file = (
        output_dir
        / "password_manager_benchmark.csv"
    )

    with open(
        output_file,
        "w",
        newline="",
        encoding="utf-8"
    ) as f:

        writer = csv.writer(f)

        writer.writerow([
            "Component",
            "Operation",
            "Min_ms",
            "Max_ms",
            "Average_ms",
            "Median_ms"
        ])

        for component, operations in results.items():

            for operation, result in operations.items():

                writer.writerow([
                    component,
                    operation,
                    f"{result['min']:.6f}",
                    f"{result['max']:.6f}",
                    f"{result['average']:.6f}",
                    f"{result['median']:.6f}"
                ])

    print(
        f"\n✓ Da luu ket qua: "
        f"{output_file}"
    )


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 70)
    print("BENCHMARK TOAN BO PASSWORD MANAGER")
    print("=" * 70)

    print(
        f"\nSo lan lap: {ROUNDS}"
    )

    print(
        f"Thuat toan KEM: {ALGORITHM}"
    )

    results = {}

    # ========================================================
    # 1. SCRYPT
    # ========================================================

    print(
        "\n" + "-" * 70
    )

    print(
        "1. SCRYPT"
    )

    print(
        "-" * 70
    )

    salt = b"\x02" * 16

    scrypt_times, master_key = measure(
        lambda: derive_scrypt_key(
            MASTER_PASSWORD,
            salt
        )
    )

    scrypt_result = calculate_statistics(
        scrypt_times
    )

    print_result(
        "Scrypt",
        scrypt_result
    )

    results["Scrypt"] = {
        "DeriveKey": scrypt_result
    }

    # ========================================================
    # 2. ML-KEM KEYGEN
    # ========================================================

    print(
        "\n" + "-" * 70
    )

    print(
        "2. ML-KEM-768"
    )

    print(
        "-" * 70
    )

    if not oqs.is_kem_enabled(ALGORITHM):

        print(
            "\n✗ ML-KEM-768 chua duoc kich hoat."
        )

        return

    with oqs.KeyEncapsulation(
        ALGORITHM
    ) as kem:

        keygen_times, public_key = measure(
            lambda: kem.generate_keypair()
        )

        keygen_result = calculate_statistics(
            keygen_times
        )

        print_result(
            "KeyGen",
            keygen_result
        )

        # ----------------------------------------------------
        # Lấy secret key tương ứng với public key
        # ----------------------------------------------------

        secret_key = kem.export_secret_key()

        # ----------------------------------------------------
        # Encaps
        # ----------------------------------------------------

        encaps_times, encaps_result = measure(
            lambda: kem.encap_secret(
                public_key
            )
        )

        encaps_statistics = calculate_statistics(
            encaps_times
        )

        print_result(
            "Encaps",
            encaps_statistics
        )

        ciphertext, shared_secret = encaps_result

        # ----------------------------------------------------
        # Decaps
        # ----------------------------------------------------

        decaps_times, decaps_shared_secret = measure(
            lambda: kem.decap_secret(
                ciphertext
            )
        )

        decaps_statistics = calculate_statistics(
            decaps_times
        )

        print_result(
            "Decaps",
            decaps_statistics
        )

        # ----------------------------------------------------
        # Kiểm tra
        # ----------------------------------------------------

        if shared_secret == decaps_shared_secret:

            print(
                "\n✓ Shared secret trung khop."
            )

        else:

            print(
                "\n✗ Shared secret khong trung khop."
            )

    results["ML-KEM-768"] = {

        "KeyGen":
            keygen_result,

        "Encaps":
            encaps_statistics,

        "Decaps":
            decaps_statistics
    }

    # ========================================================
    # 3. HKDF
    # ========================================================

    print(
        "\n" + "-" * 70
    )

    print(
        "3. HKDF-SHA256"
    )

    print(
        "-" * 70
    )

    hkdf_times, aes_key = measure(
        lambda: derive_hkdf_key(
            shared_secret
        )
    )

    hkdf_result = calculate_statistics(
        hkdf_times
    )

    print_result(
        "HKDF-SHA256",
        hkdf_result
    )

    results["HKDF-SHA256"] = {

        "DeriveKey":
            hkdf_result
    }

    # ========================================================
    # 4. AES-256-GCM ENCRYPT
    # ========================================================

    print(
        "\n" + "-" * 70
    )

    print(
        "4. AES-256-GCM"
    )

    print(
        "-" * 70
    )

    encrypt_times, encrypt_result = measure(
        lambda: aes_encrypt(
            TEST_DATA,
            aes_key
        )
    )

    encrypt_statistics = calculate_statistics(
        encrypt_times
    )

    print_result(
        "Encrypt",
        encrypt_statistics
    )

    nonce, ciphertext_aes = encrypt_result

    # ========================================================
    # 5. AES-256-GCM DECRYPT
    # ========================================================

    decrypt_times, decrypted_data = measure(
        lambda: aes_decrypt(
            ciphertext_aes,
            nonce,
            aes_key
        )
    )

    decrypt_statistics = calculate_statistics(
        decrypt_times
    )

    print_result(
        "Decrypt",
        decrypt_statistics
    )

    if decrypted_data == TEST_DATA:

        print(
            "\n✓ AES-GCM giai ma dung."
        )

    else:

        print(
            "\n✗ AES-GCM giai ma sai."
        )

    results["AES-256-GCM"] = {

        "Encrypt":
            encrypt_statistics,

        "Decrypt":
            decrypt_statistics
    }

    # ========================================================
    # 6. TỔNG KẾT
    # ========================================================

    print(
        "\n" + "=" * 70
    )

    print(
        "TONG KET"
    )

    print(
        "=" * 70
    )

    print(
        f"\nScrypt trung binh     : "
        f"{scrypt_result['average']:.4f} ms"
    )

    print(
        f"ML-KEM KeyGen         : "
        f"{keygen_result['average']:.4f} ms"
    )

    print(
        f"ML-KEM Encaps         : "
        f"{encaps_statistics['average']:.4f} ms"
    )

    print(
        f"ML-KEM Decaps         : "
        f"{decaps_statistics['average']:.4f} ms"
    )

    print(
        f"HKDF-SHA256           : "
        f"{hkdf_result['average']:.4f} ms"
    )

    print(
        f"AES-GCM Encrypt       : "
        f"{encrypt_statistics['average']:.4f} ms"
    )

    print(
        f"AES-GCM Decrypt       : "
        f"{decrypt_statistics['average']:.4f} ms"
    )

    # --------------------------------------------------------
    # Tổng phần KEM
    # --------------------------------------------------------

    kem_total = (
        keygen_result["average"]
        + encaps_statistics["average"]
        + decaps_statistics["average"]
    )

    print(
        f"\nTong ML-KEM           : "
        f"{kem_total:.4f} ms"
    )

    # --------------------------------------------------------
    # Lưu CSV
    # --------------------------------------------------------

    save_results(results)

    print(
        "\n" + "=" * 70
    )

    print(
        "BENCHMARK HOAN TAT"
    )

    print(
        "=" * 70
    )


if __name__ == "__main__":

    main()