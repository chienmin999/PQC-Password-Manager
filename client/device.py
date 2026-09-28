import base64
import requests

from common.mlkem_manager import MLKEMManager


SERVER_URL = "http://127.0.0.1:8000"


class Device:

    def __init__(self, device_name):
        self.device_name = device_name
        self.kem = MLKEMManager()

        self.public_key = None
        self.secret_key = None

    def generate_kem_keypair(self):
        self.public_key, self.secret_key = \
            self.kem.generate_keypair()

        return self.public_key, self.secret_key

    def get_public_key_base64(self):

        if self.public_key is None:
            raise RuntimeError(
                "Thiết bị chưa có ML-KEM keypair."
            )

        return base64.b64encode(
            self.public_key
        ).decode("ascii")

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
                f"Đăng ký thiết bị thất bại: "
                f"{response.status_code} "
                f"{response.text}"
            )

        return response.json()

    def encapsulate(self, public_key):

        ciphertext, shared_secret = \
            self.kem.encapsulate(public_key)

        return ciphertext, shared_secret

    def close(self):
        self.kem.close()


if __name__ == "__main__":

    device = Device("PC")

    try:

        public_key, secret_key = \
            device.generate_kem_keypair()

        print("=" * 60)
        print("CLIENT DEVICE")
        print("=" * 60)

        print("Device:", device.device_name)
        print("ML-KEM:", device.kem.ALGORITHM)

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
        print("Đang đăng ký thiết bị với Server...")

        result = device.register(user_id=1)

        print()
        print("ĐĂNG KÝ THÀNH CÔNG")
        print("Device ID:", result["device_id"])
        print("User ID:", result["user_id"])
        print("Device:", result["device_name"])
        print("Status:", result["status"])

    finally:

        device.close()