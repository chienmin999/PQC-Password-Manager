import time
import statistics
import csv
from pathlib import Path

import oqs


ALGORITHM = "ML-KEM-768"
ROUNDS = 100


def benchmark_keygen(kem):

    times = []

    for _ in range(ROUNDS):

        start = time.perf_counter()

        public_key = kem.generate_keypair()

        end = time.perf_counter()

        times.append(
            (end - start) * 1000
        )

    return times, public_key


def benchmark_encaps(kem, public_key):

    times = []
    last_ciphertext = None
    last_shared_secret = None

    for _ in range(ROUNDS):

        start = time.perf_counter()

        ciphertext, shared_secret = \
            kem.encap_secret(public_key)

        end = time.perf_counter()

        times.append(
            (end - start) * 1000
        )

        last_ciphertext = ciphertext
        last_shared_secret = shared_secret

    return (
        times,
        last_ciphertext,
        last_shared_secret
    )


def benchmark_decaps(
    kem,
    ciphertext
):

    times = []

    for _ in range(ROUNDS):

        start = time.perf_counter()

        shared_secret = \
            kem.decap_secret(ciphertext)

        end = time.perf_counter()

        times.append(
            (end - start) * 1000
        )

    return times, shared_secret


def statistics_result(times):

    return {
        "min": min(times),
        "max": max(times),
        "average": statistics.mean(times),
        "median": statistics.median(times)
    }


def print_result(name, result):

    print(
        f"\n{name}"
    )

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


def save_csv(results, details):

    output_dir = Path("results")

    output_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    output_file = (
        output_dir
        / "mlkem_768_benchmark.csv"
    )

    with open(
        output_file,
        "w",
        newline="",
        encoding="utf-8"
    ) as f:

        writer = csv.writer(f)

        writer.writerow([
            "Algorithm",
            "Operation",
            "Min_ms",
            "Max_ms",
            "Average_ms",
            "Median_ms"
        ])

        for operation, result in results.items():

            writer.writerow([
                details["name"],
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


def main():

    print("=" * 70)
    print("BENCHMARK ML-KEM-768")
    print("=" * 70)

    print(
        f"\nSo lan lap: {ROUNDS}"
    )

    print(
        f"Thuat toan: {ALGORITHM}"
    )

    if not oqs.is_kem_enabled(ALGORITHM):

        print(
            "\n✗ ML-KEM-768 chua duoc kich hoat."
        )

        return

    with oqs.KeyEncapsulation(
        ALGORITHM
    ) as kem:

        details = kem.details

        # ====================================================
        # THÔNG TIN THUẬT TOÁN
        # ====================================================

        print(
            "\n" + "-" * 70
        )

        print(
            "THONG TIN ML-KEM"
        )

        print(
            "-" * 70
        )

        print(
            f"Algorithm       : "
            f"{details['name']}"
        )

        print(
            f"Version         : "
            f"{details['version']}"
        )

        print(
            f"NIST level      : "
            f"{details['claimed_nist_level']}"
        )

        print(
            f"IND-CCA         : "
            f"{details['is_ind_cca']}"
        )

        print(
            f"Public key      : "
            f"{details['length_public_key']} bytes"
        )

        print(
            f"Secret key      : "
            f"{details['length_secret_key']} bytes"
        )

        print(
            f"Ciphertext      : "
            f"{details['length_ciphertext']} bytes"
        )

        print(
            f"Shared secret   : "
            f"{details['length_shared_secret']} bytes"
        )

        # ====================================================
        # KEYGEN
        # ====================================================

        print(
            "\nDang do KeyGen..."
        )

        keygen_times, public_key = \
            benchmark_keygen(kem)

        keygen_result = \
            statistics_result(
                keygen_times
            )

        print_result(
            "KeyGen",
            keygen_result
        )

        # ====================================================
        # ENCAPS
        # ====================================================

        print(
            "\nDang do Encaps..."
        )

        encaps_times, ciphertext, \
            shared_secret_encaps = \
            benchmark_encaps(
                kem,
                public_key
            )

        encaps_result = \
            statistics_result(
                encaps_times
            )

        print_result(
            "Encaps",
            encaps_result
        )

        # ====================================================
        # DECAPS
        # ====================================================

        print(
            "\nDang do Decaps..."
        )

        decaps_times, \
            shared_secret_decaps = \
            benchmark_decaps(
                kem,
                ciphertext
            )

        decaps_result = \
            statistics_result(
                decaps_times
            )

        print_result(
            "Decaps",
            decaps_result
        )

        # ====================================================
        # KIỂM TRA SHARED SECRET
        # ====================================================

        print(
            "\n" + "-" * 70
        )

        print(
            "KIEM TRA TINH DUNG CUA KEM"
        )

        print(
            "-" * 70
        )

        if (
            shared_secret_encaps
            == shared_secret_decaps
        ):

            print(
                "✓ Shared secret Encaps/Decaps trung khop."
            )

        else:

            print(
                "✗ Shared secret khong trung khop."
            )

        # ====================================================
        # LƯU KẾT QUẢ
        # ====================================================

        results = {

            "KeyGen":
                keygen_result,

            "Encaps":
                encaps_result,

            "Decaps":
                decaps_result
        }

        save_csv(
            results,
            details
        )

        # ====================================================
        # TỔNG KẾT
        # ====================================================

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