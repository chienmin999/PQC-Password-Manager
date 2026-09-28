import base64
import requests

from common.mlkem_manager import MLKEMManager


SERVER_URL = "http://127.0.0.1:8000"
USER_ID = 1


def register_phone(phone_kem):
    """
    Phone tạo ML-KEM keypair và đăng ký Public Key với Server.
    """

    public_key, secret_key = phone_kem.generate_keypair()

    data = {
        "user_id": USER_ID,
        "device_name": "PHONE-E2E",
        "kem_public_key": base64.b64encode(
            public_key
        ).decode("ascii")
    }

    response = requests.post(
        f"{SERVER_URL}/api/devices/register",
        json=data,
        timeout=10
    )

    if response.status_code != 201:
        raise RuntimeError(
            "Đăng ký Phone thất bại: "
            f"{response.status_code} "
            f"{response.text}"
        )

    result = response.json()

    return (
        result["device_id"],
        public_key,
        secret_key
    )


def get_device_public_key(device_id):
    """
    PC lấy ML-KEM Public Key của Phone từ Server.
    """

    response = requests.get(
        f"{SERVER_URL}/api/devices/{device_id}",
        timeout=10
    )

    if response.status_code != 200:
        raise RuntimeError(
            "Không lấy được Public Key của Phone: "
            f"{response.status_code} "
            f"{response.text}"
        )

    data = response.json()

    public_key = base64.b64decode(
        data["kem_public_key"]
    )

    return public_key


def send_ciphertext_to_server(
    sender_device_id,
    receiver_device_id,
    ciphertext
):
    """
    PC gửi Ciphertext lên Server.
    Server chỉ lưu Ciphertext.
    """

    data = {
        "sender_device_id": sender_device_id,
        "receiver_device_id": receiver_device_id,
        "ciphertext": base64.b64encode(
            ciphertext
        ).decode("ascii")
    }

    response = requests.post(
        f"{SERVER_URL}/api/kem/exchange",
        json=data,
        timeout=10
    )

    if response.status_code != 201:
        raise RuntimeError(
            "Gửi Ciphertext lên Server thất bại: "
            f"{response.status_code} "
            f"{response.text}"
        )

    return response.json()


def get_ciphertext_from_server(exchange_id):
    """
    Phone lấy Ciphertext từ Server.
    """

    response = requests.get(
        f"{SERVER_URL}/api/kem/exchange/{exchange_id}",
        timeout=10
    )

    if response.status_code != 200:
        raise RuntimeError(
            "Không lấy được Ciphertext từ Server: "
            f"{response.status_code} "
            f"{response.text}"
        )

    data = response.json()

    ciphertext = base64.b64decode(
        data["ciphertext"]
    )

    return ciphertext


def main():

    print("=" * 60)
    print("ML-KEM END-TO-END TEST")
    print("PC -> SERVER -> PHONE")
    print("=" * 60)

    phone_kem = MLKEMManager()
    pc_kem = MLKEMManager()

    try:

        # ====================================================
        # 1. PHONE KEYGEN
        # ====================================================

        print()
        print("[1] PHONE - KeyGen()")

        phone_device_id, phone_public_key, phone_secret_key = \
            register_phone(phone_kem)

        print("    Device ID   :", phone_device_id)
        print("    Public Key  :", len(phone_public_key), "bytes")
        print("    Secret Key  :", len(phone_secret_key), "bytes")

        # ====================================================
        # 2. PC LẤY PUBLIC KEY
        # ====================================================

        print()
        print("[2] PC lấy Public Key của PHONE từ Server")

        server_phone_public_key = \
            get_device_public_key(phone_device_id)

        print(
            "    Public Key  :",
            len(server_phone_public_key),
            "bytes"
        )

        if server_phone_public_key != phone_public_key:
            raise RuntimeError(
                "Public Key nhận từ Server không giống "
                "Public Key của Phone."
            )

        print("    Public Key kiểm tra: OK")

        # ====================================================
        # 3. PC ENCAPS
        # ====================================================

        print()
        print("[3] PC - Encaps()")

        ciphertext, pc_shared_secret = \
            pc_kem.encapsulate(
                server_phone_public_key
            )

        print(
            "    Ciphertext  :",
            len(ciphertext),
            "bytes"
        )

        print(
            "    Shared Secret:",
            len(pc_shared_secret),
            "bytes"
        )

        print()
        print(
            "    PC Shared Secret:"
        )
        print(
            "    ",
            pc_shared_secret.hex()
        )

        # ====================================================
        # 4. PC GỬI CIPHERTEXT CHO SERVER
        # ====================================================

        print()
        print("[4] PC gửi Ciphertext lên Server")

        # Dùng device ID giả lập của PC đã đăng ký trước đó.
        # Device ID 3 là PC đã đăng ký trong các bước trước.
        pc_device_id = 3

        exchange = send_ciphertext_to_server(
            sender_device_id=pc_device_id,
            receiver_device_id=phone_device_id,
            ciphertext=ciphertext
        )

        exchange_id = exchange["exchange_id"]

        print(
            "    Exchange ID:",
            exchange_id
        )

        print(
            "    Server lưu Ciphertext: OK"
        )

        # ====================================================
        # 5. PHONE LẤY CIPHERTEXT
        # ====================================================

        print()
        print("[5] PHONE lấy Ciphertext từ Server")

        received_ciphertext = \
            get_ciphertext_from_server(
                exchange_id
            )

        print(
            "    Ciphertext:",
            len(received_ciphertext),
            "bytes"
        )

        if received_ciphertext != ciphertext:
            raise RuntimeError(
                "Ciphertext nhận từ Server không giống "
                "Ciphertext do PC tạo."
            )

        print(
            "    Ciphertext kiểm tra: OK"
        )

        # ====================================================
        # 6. PHONE DECAPS
        # ====================================================

        print()
        print("[6] PHONE - Decaps()")

        phone_shared_secret = \
            phone_kem.decapsulate(
                received_ciphertext
            )

        print(
            "    Shared Secret:",
            len(phone_shared_secret),
            "bytes"
        )

        print()
        print(
            "    PHONE Shared Secret:"
        )
        print(
            "    ",
            phone_shared_secret.hex()
        )

        # ====================================================
        # 7. SO SÁNH
        # ====================================================

        print()
        print("[7] KIỂM TRA SHARED SECRET")

        if pc_shared_secret == phone_shared_secret:

            print()
            print("    RESULT: SUCCESS")
            print()
            print(
                "    PC và PHONE có cùng Shared Secret."
            )
            print(
                "    ML-KEM End-to-End hoạt động chính xác."
            )

        else:

            print()
            print("    RESULT: FAILED")
            print()
            print(
                "    Shared Secret của PC và PHONE "
                "không giống nhau."
            )

            raise RuntimeError(
                "ML-KEM End-to-End Test thất bại."
            )

    finally:

        pc_kem.close()
        phone_kem.close()


if __name__ == "__main__":
    main()