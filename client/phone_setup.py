import base64
import getpass
import json
from pathlib import Path

import requests

from common.mlkem_manager import MLKEMManager
from common.secret_key_protection import SecretKeyProtection


# ============================================================
# PATH
# ============================================================

PROJECT_DIR = Path(__file__).resolve().parent.parent

LOCAL_DATA_DIR = (
    PROJECT_DIR
    / "data"
)

LOCAL_DATA_DIR.mkdir(
    parents=True,
    exist_ok=True
)

PHONE_CONFIG_FILE = (
    LOCAL_DATA_DIR
    / "phone_config.json"
)


# ============================================================
# SERVER
# ============================================================

SERVER_URL = "http://127.0.0.1:8000"

# User đang sử dụng
USER_ID = 2


# ============================================================
# HTTP
# ============================================================

def post_json(path, payload):

    response = requests.post(
        SERVER_URL + path,
        json=payload,
        timeout=10,
    )

    if response.status_code >= 400:

        raise RuntimeError(
            f"HTTP {response.status_code}: "
            f"{response.text}"
        )

    return response.json()


def get_json(path):

    response = requests.get(
        SERVER_URL + path,
        timeout=10,
    )

    if response.status_code >= 400:

        raise RuntimeError(
            f"HTTP {response.status_code}: "
            f"{response.text}"
        )

    return response.json()


# ============================================================
# MAIN
# ============================================================

def main():

    print()
    print("=" * 60)
    print("          KHỞI TẠO PHONE")
    print("=" * 60)

    # --------------------------------------------------------
    # 1. KIỂM TRA SERVER
    # --------------------------------------------------------

    print()
    print("[1] KIỂM TRA SERVER")

    health = get_json(
        "/api/health"
    )

    print(
        "    Server: ONLINE"
    )

    print(
        "    Response:",
        health
    )

    # --------------------------------------------------------
    # 2. KIỂM TRA USER
    # --------------------------------------------------------

    print()
    print("[2] KIỂM TRA USER")

    try:

        user = get_json(
            f"/api/users/{USER_ID}"
        )

    except Exception as error:

        raise RuntimeError(
            f"Không tìm thấy User ID {USER_ID}."
        ) from error

    print(
        "    User ID:",
        user.get("user_id")
    )

    print(
        "    Username:",
        user.get("username")
    )

    # --------------------------------------------------------
    # 3. KIỂM TRA PHONE ĐÃ KHỞI TẠO CHƯA
    # --------------------------------------------------------

    print()
    print("[3] KIỂM TRA CẤU HÌNH PHONE")

    if PHONE_CONFIG_FILE.exists():

        print(
            "    Phone đã được khởi tạo."
        )

        print(
            "    File:",
            PHONE_CONFIG_FILE
        )

        print()
        print(
            "    Không tạo lại để tránh mất Secret Key."
        )

        print()
        print(
            "RESULT: PHONE ĐÃ TỒN TẠI"
        )

        return True

    print(
        "    Chưa có phone_config.json."
    )

    # --------------------------------------------------------
    # 4. TẠO MASTER PASSWORD PHONE
    # --------------------------------------------------------

    print()
    print("[4] TẠO MASTER PASSWORD CHO PHONE")

    while True:

        password = getpass.getpass(
            "    Nhập Phone Master Password: "
        )

        confirm = getpass.getpass(
            "    Nhập lại Phone Master Password: "
        )

        if not password:

            print(
                "    Password không được để trống."
            )

            continue

        if password != confirm:

            print(
                "    Hai Password không giống nhau."
            )

            continue

        break

    # --------------------------------------------------------
    # 5. ML-KEM KEYGEN
    # --------------------------------------------------------

    print()
    print("[5] PHONE ML-KEM-768 KEYGEN()")

    kem = MLKEMManager()

    try:

        (
            public_key,
            secret_key
        ) = kem.generate_keypair()

    finally:

        kem.close()

    print(
        "    Public Key:",
        len(public_key),
        "bytes"
    )

    print(
        "    Secret Key:",
        len(secret_key),
        "bytes"
    )

    # --------------------------------------------------------
    # 6. BẢO VỆ SECRET KEY
    # --------------------------------------------------------

    print()
    print(
        "[6] BẢO VỆ PHONE ML-KEM SECRET KEY"
    )

    (
        secret_key_salt,
        secret_key_nonce,
        encrypted_secret_key
    ) = SecretKeyProtection.protect_secret_key(
        secret_key,
        password
    )

    print(
        "    Scrypt Salt:",
        len(secret_key_salt),
        "bytes"
    )

    print(
        "    AES-GCM Nonce:",
        len(secret_key_nonce),
        "bytes"
    )

    print(
        "    Encrypted Secret Key:",
        len(encrypted_secret_key),
        "bytes"
    )

    # --------------------------------------------------------
    # 7. ĐĂNG KÝ PHONE VỚI SERVER
    # --------------------------------------------------------

    print()
    print("[7] ĐĂNG KÝ PHONE VỚI SERVER")

    result = post_json(
        "/api/devices/register",
        {
            "user_id": USER_ID,

            "device_name": "PHONE",

            "kem_public_key":
                base64.b64encode(
                    public_key
                ).decode("ascii"),
        }
    )

    phone_device_id = result.get(
        "device_id"
    )

    if phone_device_id is None:

        raise RuntimeError(
            "Server không trả về Device ID:\n"
            f"{result}"
        )

    print(
        "    Phone Device ID:",
        phone_device_id
    )

    print(
        "    Registration: OK"
    )

    # --------------------------------------------------------
    # 8. LƯU PHONE CONFIG
    # --------------------------------------------------------

    print()
    print("[8] LƯU PHONE CONFIG")

    config = {

        "version": 1,

        "algorithm": "ML-KEM-768",

        "device": {

            "device_name": "PHONE",

            "device_id": phone_device_id,

            "user_id": USER_ID,

            "public_key":
                base64.b64encode(
                    public_key
                ).decode("ascii")
        },

        "secret_key": {

            "algorithm":
                "Scrypt-AES-256-GCM",

            "salt":
                base64.b64encode(
                    secret_key_salt
                ).decode("ascii"),

            "nonce":
                base64.b64encode(
                    secret_key_nonce
                ).decode("ascii"),

            "encrypted_secret_key":
                base64.b64encode(
                    encrypted_secret_key
                ).decode("ascii")
        }
    }

    with open(
        PHONE_CONFIG_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            config,
            file,
            indent=4,
            ensure_ascii=False
        )

    print(
        "    File:",
        PHONE_CONFIG_FILE
    )

    print(
        "    Lưu cấu hình: OK"
    )

    # --------------------------------------------------------
    # 9. KIỂM TRA
    # --------------------------------------------------------

    print()
    print("[9] KIỂM TRA PHONE CONFIG")

    if not PHONE_CONFIG_FILE.exists():

        raise RuntimeError(
            "Không tạo được phone_config.json."
        )

    print(
        "    phone_config.json: OK"
    )

    print(
        "    Public Key: OK"
    )

    print(
        "    Encrypted Secret Key: OK"
    )

    print(
        "    Secret Key plaintext: KHÔNG LƯU"
    )

    # --------------------------------------------------------
    # RESULT
    # --------------------------------------------------------

    print()
    print("=" * 60)
    print("RESULT: SUCCESS")
    print("=" * 60)

    print()
    print(
        "Phone đã được khởi tạo."
    )

    print(
        "Phone Device ID:",
        phone_device_id
    )

    print(
        "ML-KEM Public Key:",
        len(public_key),
        "bytes"
    )

    print(
        "ML-KEM Secret Key:",
        len(secret_key),
        "bytes"
    )

    print()
    print(
        "Secret Key đã được mã hóa bằng "
        "Scrypt + AES-256-GCM."
    )


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":

    try:

        main()

    except KeyboardInterrupt:

        print()
        print("Đã hủy.")

    except Exception as error:

        print()
        print("=" * 60)
        print("RESULT: FAILED")
        print("=" * 60)

        print(
            "Chi tiết:",
            error
        )