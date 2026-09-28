import oqs


class MLKEMManager:

    ALGORITHM = "ML-KEM-768"

    def __init__(self, secret_key=None):

        if not oqs.is_kem_enabled(
            self.ALGORITHM
        ):
            raise RuntimeError(
                "ML-KEM-768 không được kích hoạt "
                "trong liboqs."
            )

        if secret_key is None:

            self.kem = oqs.KeyEncapsulation(
                self.ALGORITHM
            )

        else:

            self.kem = oqs.KeyEncapsulation(
                self.ALGORITHM,
                secret_key
            )

    def generate_keypair(self):

        public_key = \
            self.kem.generate_keypair()

        secret_key = \
            self.kem.export_secret_key()

        return (
            public_key,
            secret_key
        )

    def encapsulate(self, public_key):

        ciphertext, shared_secret = \
            self.kem.encap_secret(
                public_key
            )

        return (
            ciphertext,
            shared_secret
        )

    def decapsulate(self, ciphertext):

        return self.kem.decap_secret(
            ciphertext
        )

    def get_details(self):

        return self.kem.details

    def close(self):

        if self.kem is not None:

            self.kem.free()