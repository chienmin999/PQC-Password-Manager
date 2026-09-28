import json
from pathlib import Path


VAULT_FILE = Path("data/vault.json")


def save_vault(data: dict):

    VAULT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(
        VAULT_FILE,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            data,
            f,
            ensure_ascii=False,
            indent=2
        )


def load_vault():

    if not VAULT_FILE.exists():
        return None

    with open(
        VAULT_FILE,
        "r",
        encoding="utf-8"
    ) as f:

        return json.load(f)