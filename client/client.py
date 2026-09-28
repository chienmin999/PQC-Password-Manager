import base64
import getpass
import json
from pathlib import Path

from common.mlkem_manager import MLKEMManager
from common.secret_key_protection import SecretKeyProtection
from common.local_vault_protection import (
    LocalVaultKeyProtection
)
from vault.vault_crypto import VaultCrypto
from client.server_client import ServerClient


# ============================================================
# PATH
# ============================================================

CLIENT_DIR = Path(__file__).parent

LOCAL_DATA_DIR = CLIENT_DIR.parent / "data"

LOCAL_DATA_DIR.mkdir(
    parents=True,
    exist_ok=True
)

LOCAL_CONFIG_FILE = LOCAL_DATA_DIR / "client_config.json"


# ============================================================
# PASSWORD MANAGER
# ============================================================

class PasswordManager:

    def __init__(self):

        self.kem = MLKEMManager()

        self.public_key = None
        self.secret_key = None
        self.vault_key = None

        self.vault = {
            "accounts": []
        }

        self.config = None

        self.server = ServerClient()

    # ========================================================
    # CHECK INITIALIZED
    # ========================================================

    def is_initialized(self):

        return LOCAL_CONFIG_FILE.exists()

    # ========================================================
    # LOAD CONFIG
    # ========================================================

    def load_config(self):

        if not self.is_initialized():

            raise RuntimeError(
                "Password Manager chưa được khởi tạo."
            )

        with open(
            LOCAL_CONFIG_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            self.config = json.load(file)

        return self.config

    # ========================================================
    # SAVE CONFIG
    # ========================================================

    def save_config(self, config=None):

        if config is None:

            config = self.config

        with open(
            LOCAL_CONFIG_FILE,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                config,
                file,
                indent=4,
                ensure_ascii=False
            )

    # ========================================================
    # INITIALIZE
    # ========================================================

    def initialize(self):

        if self.is_initialized():

            print()
            print(
                "Password Manager đã được khởi tạo trước đó."
            )

            return False

        print()
        print("=" * 60)
        print("KHỞI TẠO PASSWORD MANAGER")
        print("=" * 60)

        print()
        print("[1] TẠO MASTER PASSWORD")

        while True:

            password = getpass.getpass(
                "    Nhập Master Password: "
            )

            confirm = getpass.getpass(
                "    Nhập lại Master Password: "
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

        print()
        print("[2] ML-KEM-768 KEYGEN()")

        self.public_key, self.secret_key = \
            self.kem.generate_keypair()

        print(
            "    Public Key:",
            len(self.public_key),
            "bytes"
        )

        print(
            "    Secret Key:",
            len(self.secret_key),
            "bytes"
        )

        print()
        print("[3] BẢO VỆ ML-KEM SECRET KEY")

        (
            secret_key_salt,
            secret_key_nonce,
            encrypted_secret_key
        ) = SecretKeyProtection.protect_secret_key(
            self.secret_key,
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

        print()
        print("[4] TẠO K_VAULT")

        self.vault_key = \
            VaultCrypto.generate_vault_key()

        print(
            "    K_VAULT:",
            len(self.vault_key),
            "bytes"
        )

        print()
        print("[5] BẢO VỆ K_VAULT")

        (
            vault_key_salt,
            vault_key_nonce,
            encrypted_vault_key
        ) = LocalVaultKeyProtection.protect_vault_key(
            self.vault_key,
            password
        )

        print(
            "    Scrypt Salt:",
            len(vault_key_salt),
            "bytes"
        )

        print(
            "    AES-GCM Nonce:",
            len(vault_key_nonce),
            "bytes"
        )

        print(
            "    Encrypted K_VAULT:",
            len(encrypted_vault_key),
            "bytes"
        )

        print()
        print("[6] TẠO VAULT RỖNG")

        self.vault = {
            "accounts": []
        }

        vault_plaintext = json.dumps(
            self.vault,
            ensure_ascii=False,
            separators=(",", ":")
        ).encode("utf-8")

        print()
        print("[7] AES-256-GCM ENCRYPT VAULT")

        vault_nonce, encrypted_vault = \
            VaultCrypto.encrypt_vault(
                vault_plaintext,
                self.vault_key
            )

        print(
            "    Encrypted Vault:",
            len(encrypted_vault),
            "bytes"
        )

        print(
            "    Vault Nonce:",
            len(vault_nonce),
            "bytes"
        )

        print()
        print("[8] LƯU CẤU HÌNH LOCAL")

        self.config = {

            "version": 2,

            "algorithm": "ML-KEM-768",

            "device": {

                "device_name": "PC",

                "public_key": base64.b64encode(
                    self.public_key
                ).decode("ascii")
            },

            "secret_key": {

                "salt": base64.b64encode(
                    secret_key_salt
                ).decode("ascii"),

                "nonce": base64.b64encode(
                    secret_key_nonce
                ).decode("ascii"),

                "encrypted_secret_key":
                    base64.b64encode(
                        encrypted_secret_key
                    ).decode("ascii")
            },

            "vault_key_protection": {

                "algorithm":
                    "Scrypt-AES-256-GCM",

                "salt": base64.b64encode(
                    vault_key_salt
                ).decode("ascii"),

                "nonce": base64.b64encode(
                    vault_key_nonce
                ).decode("ascii"),

                "encrypted_vault_key":
                    base64.b64encode(
                        encrypted_vault_key
                    ).decode("ascii")
            },

            "vault": {

                "nonce": base64.b64encode(
                    vault_nonce
                ).decode("ascii"),

                "encrypted_vault":
                    base64.b64encode(
                        encrypted_vault
                    ).decode("ascii"),

                "version": 1
            }
        }

        self.save_config()

        print(
            "    File:",
            LOCAL_CONFIG_FILE
        )

        print(
            "    Lưu cấu hình: OK"
        )

        print()
        print("[9] KHỞI TẠO HOÀN TẤT")

        print()
        print("    Master Password: OK")
        print("    ML-KEM-768 KeyPair: OK")
        print("    Secret Key Protection: OK")
        print("    K_VAULT Protection: OK")
        print("    AES-256-GCM Vault: OK")

        print()
        print("    RESULT: SUCCESS")

        return True

    # ========================================================
    # MIGRATE OLD CONFIG
    # ========================================================

    def migrate_legacy_vault_key(
        self,
        config,
        password
    ):

        vault_data = config.get(
            "vault",
            {}
        )

        if "vault_key" not in vault_data:

            return config

        print()
        print("[4] PHÁT HIỆN CẤU HÌNH CŨ")

        print(
            "    K_VAULT hiện đang được lưu plaintext."
        )

        print(
            "    Đang chuyển sang Encrypted K_VAULT..."
        )

        old_vault_key = base64.b64decode(
            vault_data["vault_key"]
        )

        if len(old_vault_key) != 32:

            raise ValueError(
                "K_VAULT trong cấu hình cũ không hợp lệ."
            )

        (
            salt,
            nonce,
            encrypted_vault_key
        ) = LocalVaultKeyProtection.protect_vault_key(
            old_vault_key,
            password
        )

        config["version"] = 2

        config["vault_key_protection"] = {

            "algorithm":
                "Scrypt-AES-256-GCM",

            "salt":
                base64.b64encode(
                    salt
                ).decode("ascii"),

            "nonce":
                base64.b64encode(
                    nonce
                ).decode("ascii"),

            "encrypted_vault_key":
                base64.b64encode(
                    encrypted_vault_key
                ).decode("ascii")
        }

        del vault_data["vault_key"]

        config["vault"] = vault_data

        self.save_config(config)

        print(
            "    Chuyển đổi cấu hình: OK"
        )

        print(
            "    Plaintext K_VAULT: ĐÃ XÓA"
        )

        print(
            "    Encrypted K_VAULT: OK"
        )

        return config

    # ========================================================
    # OPEN VAULT
    # ========================================================

    def open_vault(self):

        print()
        print("=" * 60)
        print("MỞ PASSWORD VAULT")
        print("=" * 60)

        print()
        print("[1] ĐỌC CẤU HÌNH LOCAL")

        config = self.load_config()

        print(
            "    Algorithm:",
            config["algorithm"]
        )

        print(
            "    Device:",
            config["device"]["device_name"]
        )

        print()
        print("[2] NHẬP MASTER PASSWORD")

        password = getpass.getpass(
            "    Master Password: "
        )

        print()
        print("[3] KHÔI PHỤC ML-KEM SECRET KEY")

        secret_key_data = config["secret_key"]

        salt = base64.b64decode(
            secret_key_data["salt"]
        )

        nonce = base64.b64decode(
            secret_key_data["nonce"]
        )

        encrypted_secret_key = \
            base64.b64decode(
                secret_key_data[
                    "encrypted_secret_key"
                ]
            )

        try:

            self.secret_key = \
                SecretKeyProtection.recover_secret_key(
                    encrypted_secret_key,
                    password,
                    salt,
                    nonce
                )

        except Exception:

            print()
            print(
                "    ERROR: Master Password không đúng "
                "hoặc dữ liệu Secret Key đã bị thay đổi."
            )

            return False

        print(
            "    Secret Key:",
            len(self.secret_key),
            "bytes"
        )

        print(
            "    Secret Key khôi phục: OK"
        )

        self.kem.close()

        self.kem = MLKEMManager(
            self.secret_key
        )

        self.public_key = \
            base64.b64decode(
                config["device"]["public_key"]
            )

        config = self.migrate_legacy_vault_key(
            config,
            password
        )

        print()
        print("[5] KHÔI PHỤC K_VAULT")

        vault_key_data = \
            config["vault_key_protection"]

        vault_key_salt = \
            base64.b64decode(
                vault_key_data["salt"]
            )

        vault_key_nonce = \
            base64.b64decode(
                vault_key_data["nonce"]
            )

        encrypted_vault_key = \
            base64.b64decode(
                vault_key_data[
                    "encrypted_vault_key"
                ]
            )

        try:

            self.vault_key = \
                LocalVaultKeyProtection.recover_vault_key(
                    encrypted_vault_key,
                    password,
                    vault_key_salt,
                    vault_key_nonce
                )

        except Exception:

            print()
            print(
                "    ERROR: Không thể khôi phục K_VAULT."
            )

            return False

        print(
            "    K_VAULT:",
            len(self.vault_key),
            "bytes"
        )

        print(
            "    K_VAULT khôi phục: OK"
        )

        print()
        print("[6] ĐỌC ENCRYPTED VAULT")

        vault_data = config["vault"]

        encrypted_vault = \
            base64.b64decode(
                vault_data["encrypted_vault"]
            )

        vault_nonce = \
            base64.b64decode(
                vault_data["nonce"]
            )

        print(
            "    Encrypted Vault:",
            len(encrypted_vault),
            "bytes"
        )

        print(
            "    Vault Nonce:",
            len(vault_nonce),
            "bytes"
        )

        print()
        print("[7] AES-256-GCM DECRYPT VAULT")

        try:

            plaintext = \
                VaultCrypto.decrypt_vault(
                    encrypted_vault,
                    vault_nonce,
                    self.vault_key
                )

        except Exception:

            print(
                "    ERROR: Không thể giải mã Vault."
            )

            return False

        try:

            self.vault = json.loads(
                plaintext.decode("utf-8")
            )

        except Exception:

            print(
                "    ERROR: Dữ liệu Vault không phải "
                "JSON hợp lệ."
            )

            return False

        print(
            "    Vault giải mã: OK"
        )

        print()
        print("[8] KIỂM TRA ML-KEM SECRET KEY")

        try:

            test_ciphertext, \
                test_shared_secret = \
                self.kem.encapsulate(
                    self.public_key
                )

            recovered_shared_secret = \
                self.kem.decapsulate(
                    test_ciphertext
                )

        except Exception as error:

            print(
                "    ERROR: ML-KEM Decaps() thất bại."
            )

            print(
                "    Chi tiết:",
                error
            )

            return False

        if recovered_shared_secret != \
                test_shared_secret:

            print(
                "    ERROR: Shared Secret không khớp."
            )

            return False

        print(
            "    ML-KEM Decaps(): OK"
        )

        print(
            "    Shared Secret: MATCH"
        )

        self.display_accounts()

        return True

    # ========================================================
    # DISPLAY ACCOUNTS
    # ========================================================

    def display_accounts(self):

        print()
        print("[9] PASSWORD VAULT")

        accounts = self.vault.get(
            "accounts",
            []
        )

        if not accounts:

            print(
                "    Vault hiện đang rỗng."
            )

            return

        print()

        for index, account in enumerate(
            accounts,
            start=1
        ):

            print(
                f"    [{index}]"
            )

            print(
                "        Website:",
                account.get(
                    "site",
                    ""
                )
            )

            print(
                "        Username:",
                account.get(
                    "username",
                    ""
                )
            )

            print(
                "        Password:",
                account.get(
                    "password",
                    ""
                )
            )

            print()

    # ========================================================
    # SAVE VAULT
    # ========================================================

    def save_vault(self):

        vault_plaintext = json.dumps(
            self.vault,
            ensure_ascii=False,
            separators=(",", ":")
        ).encode("utf-8")

        vault_nonce, encrypted_vault = \
            VaultCrypto.encrypt_vault(
                vault_plaintext,
                self.vault_key
            )

        self.config["vault"]["nonce"] = \
            base64.b64encode(
                vault_nonce
            ).decode("ascii")

        self.config["vault"]["encrypted_vault"] = \
            base64.b64encode(
                encrypted_vault
            ).decode("ascii")

        current_version = \
            self.config["vault"].get(
                "version",
                1
            )

        self.config["vault"]["version"] = \
            current_version + 1

        self.save_config()

        return True

    # ========================================================
    # ADD ACCOUNT
    # ========================================================

    def add_account(self):

        print()
        print("=" * 60)
        print("THÊM TÀI KHOẢN")
        print("=" * 60)

        print()

        site = input(
            "Website: "
        ).strip()

        if not site:

            print(
                "Website không được để trống."
            )

            return False

        username = input(
            "Username: "
        ).strip()

        if not username:

            print(
                "Username không được để trống."
            )

            return False

        password = getpass.getpass(
            "Password: "
        )

        if not password:

            print(
                "Password không được để trống."
            )

            return False

        account = {

            "site": site,

            "username": username,

            "password": password
        }

        self.vault.setdefault(
            "accounts",
            []
        )

        self.vault["accounts"].append(
            account
        )

        self.save_vault()

        print()
        print(
            "Tài khoản đã được thêm."
        )

        print(
            "Vault đã được mã hóa lại bằng "
            "AES-256-GCM."
        )

        print(
            "Version:",
            self.config["vault"]["version"]
        )

        print()
        print(
            "RESULT: SUCCESS"
        )

        return True

    # ========================================================
    # EDIT ACCOUNT
    # ========================================================

    def edit_account(self):

        accounts = self.vault.get(
            "accounts",
            []
        )

        if not accounts:

            print()
            print(
                "Vault hiện đang rỗng."
            )

            return False

        print()
        print("=" * 60)
        print("SỬA TÀI KHOẢN")
        print("=" * 60)

        print()

        for index, account in enumerate(
            accounts,
            start=1
        ):

            print(
                f"{index}. {account.get('site', '')}"
            )

            print(
                f"   Username: "
                f"{account.get('username', '')}"
            )

        print()

        choice = input(
            "Chọn số tài khoản cần sửa: "
        ).strip()

        try:

            index = int(choice)

        except ValueError:

            print(
                "Lựa chọn không hợp lệ."
            )

            return False

        if index < 1 or index > len(accounts):

            print(
                "Số tài khoản không hợp lệ."
            )

            return False

        account = accounts[index - 1]

        print()
        print(
            "Để giữ nguyên giá trị hiện tại, "
            "nhấn Enter."
        )

        print()

        new_site = input(
            f"Website [{account.get('site', '')}]: "
        ).strip()

        new_username = input(
            f"Username [{account.get('username', '')}]: "
        ).strip()

        print(
            "Password [ẩn]:"
        )

        new_password = getpass.getpass(
            "    Nhập Password mới "
            "(Enter để giữ nguyên): "
        )

        if new_site:

            account["site"] = new_site

        if new_username:

            account["username"] = new_username

        if new_password:

            account["password"] = new_password

        self.save_vault()

        print()
        print(
            "Tài khoản đã được cập nhật."
        )

        print(
            "Vault đã được mã hóa lại."
        )

        print(
            "Version:",
            self.config["vault"]["version"]
        )

        print()
        print(
            "RESULT: SUCCESS"
        )

        return True

    # ========================================================
    # DELETE ACCOUNT
    # ========================================================

    def delete_account(self):

        accounts = self.vault.get(
            "accounts",
            []
        )

        if not accounts:

            print()
            print(
                "Vault hiện đang rỗng."
            )

            return False

        print()
        print("=" * 60)
        print("XÓA TÀI KHOẢN")
        print("=" * 60)

        print()

        for index, account in enumerate(
            accounts,
            start=1
        ):

            print(
                f"{index}. "
                f"{account.get('site', '')} - "
                f"{account.get('username', '')}"
            )

        print()

        choice = input(
            "Chọn số tài khoản cần xóa: "
        ).strip()

        try:

            index = int(choice)

        except ValueError:

            print(
                "Lựa chọn không hợp lệ."
            )

            return False

        if index < 1 or index > len(accounts):

            print(
                "Số tài khoản không hợp lệ."
            )

            return False

        account = accounts[index - 1]

        print()
        print(
            "Tài khoản:"
        )

        print(
            "    Website:",
            account.get("site", "")
        )

        print(
            "    Username:",
            account.get("username", "")
        )

        confirm = input(
            "Bạn có chắc muốn xóa? (y/n): "
        ).strip().lower()

        if confirm != "y":

            print(
                "Đã hủy thao tác."
            )

            return False

        del accounts[index - 1]

        self.save_vault()

        print()
        print(
            "Tài khoản đã được xóa."
        )

        print(
            "Vault đã được mã hóa lại."
        )

        print(
            "Version:",
            self.config["vault"]["version"]
        )

        print()
        print(
            "RESULT: SUCCESS"
        )

        return True

    # ========================================================
    # REGISTER PC + SYNC VAULT
    # ========================================================

    def sync_with_server(self):

        print()
        print("=" * 60)
        print("ĐỒNG BỘ PASSWORD VAULT VỚI SERVER")
        print("=" * 60)

        # ----------------------------------------------------
        # SERVER HEALTH
        # ----------------------------------------------------

        print()
        print("[1] KIỂM TRA SERVER")

        try:
            health = self.server.health()

        except Exception as error:

            print()
            print(
                "    ERROR: Không kết nối được Server."
            )

            print(
                "    Chi tiết:",
                error
            )

            print()
            print(
                "    Hãy chắc chắn Server đang chạy:"
            )

            print(
                "    python -m server.server"
            )

            return False

        print(
            "    Server: ONLINE"
        )

        print(
            "    Response:",
            health
        )

        # ----------------------------------------------------
        # LOAD CONFIG
        # ----------------------------------------------------

        config = self.load_config()

        server_config = \
            config.get(
                "server",
                {}
            )

        # Khi chọn chức năng đồng bộ trực tiếp từ menu,
        # open_vault() chưa được gọi nên self.public_key vẫn là None.
        # Public Key đã được lưu trong client_config.json từ lúc
        # khởi tạo, vì vậy nạp lại từ cấu hình local tại đây.
        if self.public_key is None:
            try:
                device_config = config.get("device", {})
                encoded_public_key = device_config.get("public_key")

                if not encoded_public_key:
                    raise ValueError(
                        "Không tìm thấy ML-KEM Public Key trong cấu hình local."
                    )

                self.public_key = base64.b64decode(
                    encoded_public_key
                )

                if not self.public_key:
                    raise ValueError(
                        "ML-KEM Public Key trong cấu hình local rỗng."
                    )

            except Exception as error:
                print()
                print(
                    "    ERROR: Không thể khôi phục ML-KEM Public Key."
                )
                print(
                    "    Chi tiết:",
                    error
                )
                return False

        user_id = \
            server_config.get(
                "user_id"
            )

        device_id = \
            server_config.get(
                "device_id"
            )

        # ----------------------------------------------------
        # CREATE USER
        # ----------------------------------------------------

        if user_id is None:

            print()
            print("[2] ĐĂNG KÝ USER")

            username = input(
                "    Nhập Username Server: "
            ).strip()

            if not username:

                print(
                    "    Username không được để trống."
                )

                return False

            try:

                user_result = \
                    self.server.create_user(
                        username
                    )

            except Exception as error:

                print()
                print(
                    "    ERROR: Không tạo được User."
                )

                print(
                    "    Chi tiết:",
                    error
                )

                print()
                print(
                    "    Nếu Username này đã tồn tại trên Server, "
                    "hãy dùng Username khác."
                )

                return False

            # Server API trả về "user_id", không phải "id".
            user_id = \
                user_result.get(
                    "user_id"
                )

            if user_id is None:

                # Tương thích với response cũ nếu có.
                user_id = \
                    user_result.get(
                        "id"
                    )

            if user_id is None:

                print()
                print(
                    "    ERROR: Server không trả về User ID."
                )

                print(
                    "    Response:",
                    user_result
                )

                return False

            print(
                "    User ID:",
                user_id
            )

        else:

            print()
            print("[2] USER ĐÃ ĐĂNG KÝ")

            print(
                "    User ID:",
                user_id
            )

        # ----------------------------------------------------
        # REGISTER DEVICE
        # ----------------------------------------------------

        if device_id is None:

            print()
            print("[3] ĐĂNG KÝ THIẾT BỊ PC")

            try:

                device_result = \
                    self.server.register_device(
                        user_id,
                        "PC",
                        self.public_key
                    )

            except Exception as error:

                print()
                print(
                    "    ERROR: Không đăng ký được "
                    "thiết bị."
                )

                print(
                    "    Chi tiết:",
                    error
                )

                return False

            # Server có thể trả "device_id".
            device_id = \
                device_result.get(
                    "device_id"
                )

            if device_id is None:

                # Tương thích với response cũ nếu có.
                device_id = \
                    device_result.get(
                        "id"
                    )

            if device_id is None:

                print()
                print(
                    "    ERROR: Server không trả về Device ID."
                )

                print(
                    "    Response:",
                    device_result
                )

                return False

            print(
                "    Device ID:",
                device_id
            )

        else:

            print()
            print("[3] THIẾT BỊ PC ĐÃ ĐĂNG KÝ")

            print(
                "    Device ID:",
                device_id
            )

        # ----------------------------------------------------
        # SAVE SERVER IDENTITY
        # ----------------------------------------------------

        config["server"] = {

            "base_url":
                self.server.base_url,

            "user_id":
                user_id,

            "device_id":
                device_id,

            # Version của Vault trên Server mà thiết bị
            # đã đồng bộ lần cuối.
            #
            # Không dùng vault.version ở đây vì
            # vault.version là phiên bản thay đổi cục bộ.
            "server_version":
                server_config.get(
                    "server_version",
                    0
                )
        }

        self.config = config

        self.save_config()

        # ----------------------------------------------------
        # READ CURRENT VAULT
        # ----------------------------------------------------

        print()
        print("[4] CHUẨN BỊ ENCRYPTED VAULT")

        vault_data = \
            config["vault"]

        encrypted_vault = \
            base64.b64decode(
                vault_data["encrypted_vault"]
            )

        vault_nonce = \
            base64.b64decode(
                vault_data["nonce"]
            )

        local_version = \
            vault_data.get(
                "version",
                1
            )

        print(
            "    Encrypted Vault:",
            len(encrypted_vault),
            "bytes"
        )

        print(
            "    Vault Nonce:",
            len(vault_nonce),
            "bytes"
        )

        print(
            "    Local Version:",
            local_version
        )

        # ----------------------------------------------------
        # CHECK SERVER VAULT
        # ----------------------------------------------------

        print()
        print("[5] KIỂM TRA VAULT TRÊN SERVER")

        try:

            server_vault = \
                self.server.get_vault(
                    user_id
                )

            server_version = \
                int(
                    server_vault.get(
                        "version",
                        0
                    )
                )

            print(
                "    Server Version:",
                server_version
            )

        except Exception:

            server_vault = None

            print(
                "    Server chưa có Vault."
            )

            server_version = 0

        # ----------------------------------------------------
        # DETERMINE CLIENT BASE VERSION
        # ----------------------------------------------------
        #
        # base_version phải là phiên bản Server mà thiết bị
        # đã biết/đã đồng bộ lần trước.
        #
        # KHÔNG được lấy server_version hiện tại để gửi lên
        # Server, vì như vậy sẽ bỏ qua cơ chế chống ghi đè.
        # ----------------------------------------------------

        last_server_version = \
            config["server"].get(
                "server_version",
                0
            )

        try:

            last_server_version = \
                int(
                    last_server_version
                )

        except (TypeError, ValueError):

            last_server_version = 0

        print()
        print(
            "    Client Base Version:",
            last_server_version
        )

        # ----------------------------------------------------
        # VERSION CHECK
        # ----------------------------------------------------
        #
        # Nếu Server đã có Vault và version hiện tại khác
        # version mà client đã đồng bộ lần trước, không upload
        # dữ liệu cũ của client.
        # ----------------------------------------------------

        if server_vault is not None:

            if server_version != \
                    last_server_version:

                print()
                print(
                    "    ERROR: VERSION CONFLICT"
                )

                print(
                    "    Server Version:",
                    server_version
                )

                print(
                    "    Client Base Version:",
                    last_server_version
                )

                print()
                print(
                    "    Server đã có thay đổi mà thiết bị "
                    "này chưa đồng bộ."
                )

                print(
                    "    Không ghi đè Vault trên Server."
                )

                return False

        else:

            # Server chưa có Vault thì phiên bản cơ sở
            # bắt buộc là 0.
            last_server_version = 0

        # ----------------------------------------------------
        # UPLOAD
        # ----------------------------------------------------

        print()
        print("[6] UPLOAD ENCRYPTED VAULT")

        try:

            response = \
                self.server.upload_vault(
                    user_id,
                    encrypted_vault,
                    vault_nonce,
                    last_server_version
                )

        except Exception as error:

            print()
            print(
                "    ERROR: Không upload được Vault."
            )

            print(
                "    Chi tiết:",
                error
            )

            return False

        if response.status_code == 409:

            print()
            print(
                "    ERROR: VERSION CONFLICT"
            )

            try:

                error_data = response.json()

                print(
                    "    Server Version:",
                    error_data.get(
                        "server_version"
                    )
                )

                print(
                    "    Client Base Version:",
                    error_data.get(
                        "client_base_version"
                    )
                )

            except Exception:

                print(
                    response.text
                )

            return False

        if response.status_code >= 400:

            print()
            print(
                "    ERROR: Server từ chối Upload."
            )

            print(
                "    HTTP:",
                response.status_code
            )

            print(
                "    Response:",
                response.text
            )

            return False

        try:

            upload_result = \
                response.json()

        except Exception:

            upload_result = {}

        server_new_version = \
            upload_result.get(
                "version"
            )

        if server_new_version is None:

            server_new_version = \
                last_server_version + 1

        try:

            server_new_version = \
                int(
                    server_new_version
                )

        except (TypeError, ValueError):

            server_new_version = \
                last_server_version + 1

        # ----------------------------------------------------
        # SAVE SYNC STATE
        # ----------------------------------------------------
        #
        # Giữ nguyên vault.version cục bộ.
        # Chỉ cập nhật server.server_version.
        # ----------------------------------------------------

        config["server"]["user_id"] = \
            user_id

        config["server"]["device_id"] = \
            device_id

        config["server"]["server_version"] = \
            server_new_version

        self.config = config

        self.save_config()

        print(
            "    Upload: OK"
        )

        print(
            "    Server Version:",
            server_new_version
        )

        print(
            "    Local Version:",
            local_version
        )

        # ----------------------------------------------------
        # FINAL
        # ----------------------------------------------------

        print()
        print("[7] ĐỒNG BỘ HOÀN TẤT")

        print()
        print(
            "    User ID:",
            user_id
        )

        print(
            "    PC Device ID:",
            device_id
        )

        print(
            "    Encrypted Vault: OK"
        )

        print(
            "    K_VAULT: KHÔNG GỬI LÊN SERVER"
        )

        print(
            "    Server Version:",
            server_new_version
        )

        print(
            "    RESULT: SUCCESS"
        )

        return True

    # ========================================================
    # CLOSE
    # ========================================================

    def close(self):

        if self.kem is not None:

            self.kem.close()


# ============================================================
# MENU
# ============================================================

def main():

    manager = PasswordManager()

    try:

        print()
        print("=" * 60)
        print("       PQC PASSWORD MANAGER")
        print("=" * 60)

        print()

        if not manager.is_initialized():

            print(
                "Trạng thái: CHƯA KHỞI TẠO"
            )

            print()
            print(
                "1. Khởi tạo Password Manager"
            )

            print(
                "0. Thoát"
            )

            print()

            choice = input(
                "Lựa chọn: "
            ).strip()

            if choice == "1":

                manager.initialize()

            elif choice == "0":

                print(
                    "Thoát chương trình."
                )

            else:

                print(
                    "Lựa chọn không hợp lệ."
                )

            return

        print(
            "Trạng thái: ĐÃ KHỞI TẠO"
        )

        print()
        print(
            "1. Mở Password Vault"
        )

        print(
            "2. Thêm tài khoản"
        )

        print(
            "3. Xem tài khoản"
        )

        print(
            "4. Sửa tài khoản"
        )

        print(
            "5. Xóa tài khoản"
        )

        print(
            "6. Đồng bộ Vault với Server"
        )

        print(
            "0. Thoát"
        )

        print()

        choice = input(
            "Lựa chọn: "
        ).strip()

        if choice == "1":

            manager.open_vault()

        elif choice == "2":

            print()
            print(
                "Để thêm tài khoản, trước tiên "
                "phải mở Vault."
            )

            if manager.open_vault():

                manager.add_account()

        elif choice == "3":

            print()
            print(
                "Để xem tài khoản, trước tiên "
                "phải mở Vault."
            )

            if manager.open_vault():

                print()

                input(
                    "Nhấn Enter để thoát..."
                )

        elif choice == "4":

            print()
            print(
                "Để sửa tài khoản, trước tiên "
                "phải mở Vault."
            )

            if manager.open_vault():

                manager.edit_account()

        elif choice == "5":

            print()
            print(
                "Để xóa tài khoản, trước tiên "
                "phải mở Vault."
            )

            if manager.open_vault():

                manager.delete_account()

        elif choice == "6":

            manager.sync_with_server()

        elif choice == "0":

            print(
                "Thoát chương trình."
            )

        else:

            print(
                "Lựa chọn không hợp lệ."
            )

    finally:

        manager.close()


if __name__ == "__main__":

    main()