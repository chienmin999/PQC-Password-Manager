import json
from pathlib import Path


class PasswordVault:

    def __init__(self):
        self.entries = []

    def add_entry(
        self,
        service: str,
        username: str,
        password: str,
        note: str = ""
    ):
        entry = {
            "service": service,
            "username": username,
            "password": password,
            "note": note
        }

        self.entries.append(entry)

    def get_entries(self):
        return self.entries

    def to_json(self) -> bytes:
        """
        Chuyển kho mật khẩu thành JSON bytes.
        """

        data = {
            "version": 1,
            "entries": self.entries
        }

        return json.dumps(
            data,
            ensure_ascii=False,
            indent=2
        ).encode("utf-8")

    def from_json(self, data: bytes):
        """
        Khôi phục kho mật khẩu từ JSON bytes.
        """

        obj = json.loads(
            data.decode("utf-8")
        )

        self.entries = obj.get(
            "entries",
            []
        )

    def save_plaintext(self, path):
        """
        Chỉ dùng để kiểm tra.
        Không dùng trong phiên bản bảo mật cuối cùng.
        """

        path = Path(path)

        path.write_bytes(
            self.to_json()
        )

    def load_plaintext(self, path):
        """
        Chỉ dùng để kiểm tra.
        """

        path = Path(path)

        self.from_json(
            path.read_bytes()
        )