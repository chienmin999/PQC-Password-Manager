import sqlite3
from pathlib import Path


DB_PATH = Path(__file__).parent / "server.db"


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_database():

    conn = get_connection()

    # ==================================================
    # USERS
    # ==================================================

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL
        )
    """)

    # ==================================================
    # DEVICES
    # ==================================================

    conn.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            device_name TEXT NOT NULL,
            kem_public_key BLOB NOT NULL,
            dsa_public_key BLOB,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            approved INTEGER DEFAULT 0,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    # ==================================================
    # VAULTS
    # ==================================================

    conn.execute("""
        CREATE TABLE IF NOT EXISTS vaults (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER UNIQUE NOT NULL,
            encrypted_vault BLOB,
            vault_nonce BLOB,
            version INTEGER DEFAULT 1,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    # ==================================================
    # MIGRATION VAULTS
    # ==================================================

    vault_columns = conn.execute(
        "PRAGMA table_info(vaults)"
    ).fetchall()

    vault_column_names = {
        column["name"]
        for column in vault_columns
    }

    if "vault_nonce" not in vault_column_names:

        conn.execute("""
            ALTER TABLE vaults
            ADD COLUMN vault_nonce BLOB
        """)

    if "version" not in vault_column_names:

        conn.execute("""
            ALTER TABLE vaults
            ADD COLUMN version INTEGER DEFAULT 1
        """)

    # ==================================================
    # VAULT KEYS
    # ==================================================

    conn.execute("""
        CREATE TABLE IF NOT EXISTS vault_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vault_id INTEGER NOT NULL,
            device_id INTEGER NOT NULL,
            kem_ciphertext BLOB NOT NULL,
            encrypted_vault_key BLOB NOT NULL,
            nonce BLOB NOT NULL,
            FOREIGN KEY(vault_id) REFERENCES vaults(id),
            FOREIGN KEY(device_id) REFERENCES devices(id)
        )
    """)

    # ==================================================
    # KEM EXCHANGES
    # ==================================================

    conn.execute("""
        CREATE TABLE IF NOT EXISTS kem_exchanges (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_device_id INTEGER NOT NULL,
            receiver_device_id INTEGER NOT NULL,
            ciphertext BLOB NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(sender_device_id) REFERENCES devices(id),
            FOREIGN KEY(receiver_device_id) REFERENCES devices(id)
        )
    """)

    conn.commit()
    conn.close()