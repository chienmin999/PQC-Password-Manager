import oqs


class MLKEMManager:
    """
    Quản lý các thao tác ML-KEM-768:
    - Tạo cặp khóa
    - Encaps
    - Decaps
    """

    ALGORITHM = "ML-KEM-768"

    def __init__(self):
        if not oqs.is_kem_enabled(self.ALGORITHM):
            raise RuntimeError(
                "ML-KEM-768 không được kích hoạt trong liboqs."
            )

        self.kem = oqs.KeyEncapsulation(self.ALGORITHM)

    def generate_keypair(self):
        """
        Tạo cặp khóa ML-KEM-768.

        Returns:
            public_key: khóa công khai
            secret_key: khóa bí mật
        """

        public_key = self.kem.generate_keypair()
        secret_key = self.kem.export_secret_key()

        return public_key, secret_key

    def encapsulate(self, public_key):
        """
        Encaps bằng khóa công khai.

        Returns:
            ciphertext: bản mã KEM
            shared_secret: bí mật chung
        """

        ciphertext, shared_secret = self.kem.encap_secret(
            public_key
        )

        return ciphertext, shared_secret

    def decapsulate(self, ciphertext):
        """
        Decaps bằng khóa bí mật hiện tại.

        Returns:
            shared_secret: bí mật chung
        """

        return self.kem.decap_secret(ciphertext)

    def get_details(self):
        """Trả về thông tin thuật toán."""

        return self.kem.details

    def close(self):
        """Giải phóng tài nguyên."""

        self.kem.free()