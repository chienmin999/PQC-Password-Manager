import os
import time
import statistics

from common.mlkem_manager import MLKEMManager
from common.crypto_utils import (
    derive_aes_key,
    encrypt_data,
    decrypt_data,
)
from common.secret_key_protection import (
    SecretKeyProtection,
)


# ============================================================
# CONFIG
# ============================================================

ITERATIONS = 100

MASTER_PASSWORD = "benchmark-password"

TEST_DATA = (
    b"This is a benchmark test payload "
    b"for the PQC Password Manager."
)


# ============================================================
# MEASURE
# ============================================================

def measure(function, iterations=ITERATIONS):

    times = []

    for _ in range(iterations):

        start = time.perf_counter()

        function()

        end = time.perf_counter()

        times.append(
            (end - start) * 1000
        )

    return {
        "min": min(times),
        "max": max(times),
        "avg": statistics.mean(times),
        "median": statistics.median(times),
    }


# ============================================================
# FORMAT
# ============================================================

def print_result(name, result):

    print(
        f"    {name:<30}"
        f"AVG: {result['avg']:>10.4f} ms    "
        f"MIN: {result['min']:>10.4f} ms    "
        f"MAX: {result['max']:>10.4f} ms"
    )


# ============================================================
# MAIN
# ============================================================

def main():

    print()
    print("=" * 75)
    print("              PQC PASSWORD MANAGER BENCHMARK")
    print("=" * 75)

    print()
    print(
        "Iterations:",
        ITERATIONS
    )

    # --------------------------------------------------------
    # ML-KEM KEYGEN
    # --------------------------------------------------------

    print()
    print("[1] ML-KEM-768 KEYGEN()")

    kem = MLKEMManager()

    keygen_result = measure(
        lambda: kem.generate_keypair()
    )

    print_result(
        "ML-KEM KeyGen()",
        keygen_result
    )

    # --------------------------------------------------------
    # TẠO KEYPAIR DÙNG CHO ENCAP/DECAP
    # --------------------------------------------------------

    public_key, secret_key = (
        kem.generate_keypair()
    )

    # --------------------------------------------------------
    # ML-KEM ENCAP
    # --------------------------------------------------------

    print()
    print("[2] ML-KEM-768 Encaps()")

    encaps_result = measure(
        lambda: kem.encapsulate(
            public_key
        )
    )

    print_result(
        "ML-KEM Encaps()",
        encaps_result
    )

    # --------------------------------------------------------
    # TẠO CIPHERTEXT
    # --------------------------------------------------------

    ciphertext, shared_secret = (
        kem.encapsulate(
            public_key
        )
    )

    # --------------------------------------------------------
    # ML-KEM DECAP
    # --------------------------------------------------------

    print()
    print("[3] ML-KEM-768 Decaps()")

    decaps_result = measure(
        lambda: kem.decapsulate(
            ciphertext
        )
    )

    print_result(
        "ML-KEM Decaps()",
        decaps_result
    )

    kem.close()

    # --------------------------------------------------------
    # HKDF
    # --------------------------------------------------------

    print()
    print("[4] HKDF-SHA256")

    hkdf_result = measure(
        lambda: derive_aes_key(
            shared_secret
        )
    )

    print_result(
        "HKDF-SHA256",
        hkdf_result
    )

    aes_key = derive_aes_key(
        shared_secret
    )

    # --------------------------------------------------------
    # AES ENCRYPT
    # --------------------------------------------------------

    print()
    print("[5] AES-256-GCM ENCRYPT")

    aes_encrypt_result = measure(
        lambda: encrypt_data(
            TEST_DATA,
            aes_key
        )
    )

    print_result(
        "AES-256-GCM Encrypt",
        aes_encrypt_result
    )

    nonce, ciphertext_aes = encrypt_data(
        TEST_DATA,
        aes_key
    )

    # --------------------------------------------------------
    # AES DECRYPT
    # --------------------------------------------------------

    print()
    print("[6] AES-256-GCM DECRYPT")

    aes_decrypt_result = measure(
        lambda: decrypt_data(
            ciphertext_aes,
            nonce,
            aes_key
        )
    )

    print_result(
        "AES-256-GCM Decrypt",
        aes_decrypt_result
    )

    # --------------------------------------------------------
    # SCRYPT + AES-GCM SECRET KEY PROTECTION
    # --------------------------------------------------------

    print()
    print("[7] SECRET KEY PROTECTION")

    (
        salt,
        sk_nonce,
        encrypted_secret_key
    ) = SecretKeyProtection.protect_secret_key(
        secret_key,
        MASTER_PASSWORD
    )

    protect_result = measure(
        lambda: SecretKeyProtection.protect_secret_key(
            secret_key,
            MASTER_PASSWORD
        ),
        iterations=20
    )

    recover_result = measure(
        lambda: SecretKeyProtection.recover_secret_key(
            encrypted_secret_key,
            MASTER_PASSWORD,
            salt,
            sk_nonce
        ),
        iterations=20
    )

    print_result(
        "Scrypt + AES Protect",
        protect_result
    )

    print_result(
        "Scrypt + AES Recover",
        recover_result
    )

    # --------------------------------------------------------
    # TỔNG ML-KEM
    # --------------------------------------------------------

    kem_total = (
        keygen_result["avg"]
        + encaps_result["avg"]
        + decaps_result["avg"]
    )

    # --------------------------------------------------------
    # TỔNG CORE CRYPTO
    # --------------------------------------------------------

    core_crypto = (
        encaps_result["avg"]
        + decaps_result["avg"]
        + hkdf_result["avg"]
        + aes_encrypt_result["avg"]
        + aes_decrypt_result["avg"]
    )

    # --------------------------------------------------------
    # RESULT
    # --------------------------------------------------------

    print()
    print("=" * 75)
    print("                         SUMMARY")
    print("=" * 75)

    print()

    print(
        f"    ML-KEM KeyGen()              "
        f"{keygen_result['avg']:.4f} ms"
    )

    print(
        f"    ML-KEM Encaps()              "
        f"{encaps_result['avg']:.4f} ms"
    )

    print(
        f"    ML-KEM Decaps()              "
        f"{decaps_result['avg']:.4f} ms"
    )

    print(
        f"    HKDF-SHA256                  "
        f"{hkdf_result['avg']:.4f} ms"
    )

    print(
        f"    AES-256-GCM Encrypt          "
        f"{aes_encrypt_result['avg']:.4f} ms"
    )

    print(
        f"    AES-256-GCM Decrypt          "
        f"{aes_decrypt_result['avg']:.4f} ms"
    )

    print(
        f"    Scrypt + AES Protect         "
        f"{protect_result['avg']:.4f} ms"
    )

    print(
        f"    Scrypt + AES Recover         "
        f"{recover_result['avg']:.4f} ms"
    )

    print()
    print(
        f"    ML-KEM tổng                  "
        f"{kem_total:.4f} ms"
    )

    print(
        f"    Core Crypto tổng            "
        f"{core_crypto:.4f} ms"
    )

    print()
    print("=" * 75)
    print("RESULT: SUCCESS")
    print("=" * 75)


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":

    try:

        main()

    except Exception as error:

        print()
        print("=" * 75)
        print("RESULT: FAILED")
        print("=" * 75)

        print(
            "Chi tiết:",
            error
        )