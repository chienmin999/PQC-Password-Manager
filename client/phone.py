import base64
import requests

from common.mlkem_manager import MLKEMManager


SERVER_URL = "http://127.0.0.1:8000"


class Phone:

    def __init__(self):

        self.device_name = "PHONE"

        self.kem = MLKEMManager()

        self.public_key = None
        self.secret_key = None

        self.device_id = None

    # ========================================================
    # ML-KEM KEY GENERATION
    # ========================================================

    def generate_kem_keypair(self):

        self.public_key, self.secret_key = \
            self.kem.generate_keypair()

        return self.public_key, self.secret_key

    # ========================================================
    # PUBLIC KEY
    # ========================================================

    def get_public_key_base64(self):

        if self.public_key is None:

            raise RuntimeError(
                "Phone chưa có ML-KEM keypair."
            )

        return base64.b64encode(
            self.public_key
        ).decode("ascii")

    # ========================================================
    # REGISTER DEVICE
    # ========================================================

    def register(self, user_id):

        if self.public_key is None:

            raise RuntimeError(
                "Phải tạo ML-KEM keypair trước."
            )

        data = {
            "user_id": user_id,
            "device_name": self.device_name,
            "kem_public_key": self.get_public_key_base64()
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

        self.device_id = result["device_id"]

        return result

    # ========================================================
    # DECAPSULATION
    # ========================================================

    def decapsulate(self, ciphertext):

        if self.secret_key is None:

            raise RuntimeError(
                "Phone chưa có Secret Key."
            )

        return self.kem.decapsulate(ciphertext)

    # ========================================================
    # CLOSE
    # ========================================================

    def close(self):

        self.kem.close()


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    phone = Phone()

    try:

        print("=" * 60)
        print("CLIENT PHONE")
        print("=" * 60)

        public_key, secret_key = \
            phone.generate_kem_keypair()

        print(
            "ML-KEM:",
            phone.kem.ALGORITHM
        )

        print(
            "Public Key:",
            len(public_key),
            "bytes"
        )

        print(
            "Secret Key:",
            len(secret_key),
            "bytes"
        )

        print()
        print(
            "Đang đăng ký PHONE với Server..."
        )

        result = phone.register(
            user_id=1
        )

        print()
        print(
            "ĐĂNG KÝ PHONE THÀNH CÔNG"
        )

        print(
            "Device ID:",
            result["device_id"]
        )

        print(
            "User ID:",
            result["user_id"]
        )

        print(
            "Device:",
            result["device_name"]
        )

        print(
            "Status:",
            result["status"]
        )

    finally:

        phone.close()