import base64
import requests


class ServerClient:

    def __init__(
        self,
        base_url="http://127.0.0.1:8000"
    ):

        self.base_url = base_url.rstrip("/")

    # ========================================================
    # HEALTH
    # ========================================================

    def health(self):

        response = requests.get(
            f"{self.base_url}/api/health",
            timeout=10
        )

        response.raise_for_status()

        return response.json()

    # ========================================================
    # CREATE USER
    # ========================================================

    def create_user(
        self,
        username
    ):

        response = requests.post(
            f"{self.base_url}/api/users",
            json={
                "username": username
            },
            timeout=10
        )

        response.raise_for_status()

        return response.json()

    # ========================================================
    # GET USER
    # ========================================================

    def get_user(
        self,
        user_id
    ):

        response = requests.get(
            f"{self.base_url}/api/users/{user_id}",
            timeout=10
        )

        response.raise_for_status()

        return response.json()

    # ========================================================
    # REGISTER DEVICE
    # ========================================================

    def register_device(
        self,
        user_id,
        device_name,
        kem_public_key,
        dsa_public_key=None
    ):

        data = {

            "user_id": user_id,

            "device_name": device_name,

            "kem_public_key":
                base64.b64encode(
                    kem_public_key
                ).decode("ascii")
        }

        if dsa_public_key is not None:

            data["dsa_public_key"] = \
                base64.b64encode(
                    dsa_public_key
                ).decode("ascii")

        response = requests.post(
            f"{self.base_url}/api/devices/register",
            json=data,
            timeout=10
        )

        response.raise_for_status()

        return response.json()

    # ========================================================
    # GET DEVICES
    # ========================================================

    def get_devices(
        self,
        user_id
    ):

        response = requests.get(
            f"{self.base_url}/api/users/"
            f"{user_id}/devices",
            timeout=10
        )

        response.raise_for_status()

        return response.json()

    # ========================================================
    # UPLOAD VAULT
    # ========================================================

    def upload_vault(
        self,
        user_id,
        encrypted_vault,
        vault_nonce,
        base_version
    ):

        data = {

            "user_id": user_id,

            "encrypted_vault":
                base64.b64encode(
                    encrypted_vault
                ).decode("ascii"),

            "vault_nonce":
                base64.b64encode(
                    vault_nonce
                ).decode("ascii"),

            "base_version":
                base_version
        }

        response = requests.post(
            f"{self.base_url}/api/vaults",
            json=data,
            timeout=10
        )

        return response

    # ========================================================
    # GET VAULT
    # ========================================================

    def get_vault(
        self,
        user_id
    ):

        response = requests.get(
            f"{self.base_url}/api/vaults/{user_id}",
            timeout=10
        )

        response.raise_for_status()

        return response.json()

    # ========================================================
    # SAVE VAULT KEY
    # ========================================================

    def save_vault_key(
        self,
        vault_id,
        device_id,
        kem_ciphertext,
        encrypted_vault_key,
        nonce
    ):

        data = {

            "device_id":
                device_id,

            "kem_ciphertext":
                base64.b64encode(
                    kem_ciphertext
                ).decode("ascii"),

            "encrypted_vault_key":
                base64.b64encode(
                    encrypted_vault_key
                ).decode("ascii"),

            "nonce":
                base64.b64encode(
                    nonce
                ).decode("ascii")
        }

        response = requests.post(
            f"{self.base_url}/api/vaults/"
            f"{vault_id}/keys",
            json=data,
            timeout=10
        )

        response.raise_for_status()

        return response.json()

    # ========================================================
    # GET VAULT KEY
    # ========================================================

    def get_vault_key(
        self,
        vault_id,
        device_id
    ):

        response = requests.get(
            f"{self.base_url}/api/vaults/"
            f"{vault_id}/keys/"
            f"{device_id}",
            timeout=10
        )

        response.raise_for_status()

        return response.json()