import base64
import requests

from common.mlkem_manager import MLKEMManager


SERVER_URL = "http://127.0.0.1:8000"

PHONE_DEVICE_ID = 4


def get_phone_public_key():

    response = requests.get(
        f"{SERVER_URL}/api/devices/{PHONE_DEVICE_ID}",
        timeout=10
    )

    if response.status_code != 200:

        raise RuntimeError(
            "Không lấy được thông tin Phone: "
            f"{response.status_code} "
            f"{response.text}"
        )

    data = response.json()

    if data["device_name"] != "PHONE":

        raise RuntimeError(
            "Device ID không phải PHONE."
        )

    public_key = base64.b64decode(
        data["kem_public_key"]
    )

    return public_key


def main():

    print("=" * 60)
    print("SERVER KEM EXCHANGE TEST")
    print("=" * 60)

    kem = MLKEMManager()

    try:

        # ==================================================
        # 1. Lấy Public Key của PHONE từ Server
        # ==================================================

        print()
        print("[1] PC lấy Public Key của PHONE từ Server")

        phone_public_key = get_phone_public_key()

        print(
            "    Device ID:",
            PHONE_DEVICE_ID
        )

        print(
            "    Public Key:",
            len(phone_public_key),
            "bytes"
        )

        # ==================================================
        # 2. PC thực hiện Encaps
        # ==================================================

        print()
        print("[2] PC - Encaps()")

        ciphertext, shared_secret = \
            kem.encapsulate(phone_public_key)

        print(
            "    Ciphertext:",
            len(ciphertext),
            "bytes"
        )

        print(
            "    Shared Secret:",
            len(shared_secret),
            "bytes"
        )

        print()
        print(
            "    Shared Secret:",
            shared_secret.hex()
        )

        # ==================================================
        # 3. Kết thúc
        # ==================================================

        print()
        print("[3] SERVER KEM TEST")

        print(
            "    Server đã cung cấp đúng Public Key của PHONE."
        )

        print(
            "    PC đã Encaps thành công."
        )

        print(
            "    Ciphertext đã được tạo."
        )

    finally:

        kem.close()


if __name__ == "__main__":

    main()