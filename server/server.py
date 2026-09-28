import base64

from flask import Flask, jsonify, request

from .database import (
    init_database,
    get_connection
)


app = Flask(__name__)


# ============================================================
# DATABASE
# ============================================================

init_database()


# ============================================================
# HEALTH
# ============================================================

@app.route("/api/health", methods=["GET"])
def health():

    return jsonify({
        "status": "ok"
    })


# ============================================================
# USERS
# ============================================================

@app.route("/api/users", methods=["POST"])
def create_user():

    data = request.get_json()

    if not data or "username" not in data:

        return jsonify({
            "error": "username_required"
        }), 400

    username = data["username"]

    conn = get_connection()

    try:

        cursor = conn.execute(
            """
            INSERT INTO users (username)
            VALUES (?)
            """,
            (username,)
        )

        conn.commit()

        user_id = cursor.lastrowid

        return jsonify({
            "user_id": user_id,
            "username": username,
            "status": "created"
        }), 201

    except Exception as e:

        return jsonify({
            "error": str(e)
        }), 400

    finally:

        conn.close()


@app.route("/api/users/<int:user_id>", methods=["GET"])
def get_user(user_id):

    conn = get_connection()

    row = conn.execute(
        """
        SELECT id, username
        FROM users
        WHERE id = ?
        """,
        (user_id,)
    ).fetchone()

    conn.close()

    if row is None:

        return jsonify({
            "error": "user_not_found"
        }), 404

    return jsonify({
        "user_id": row["id"],
        "username": row["username"]
    })


# ============================================================
# DEVICES
# ============================================================

@app.route(
    "/api/devices/register",
    methods=["POST"]
)
def register_device():

    data = request.get_json()

    required = [
        "user_id",
        "device_name",
        "kem_public_key"
    ]

    for field in required:

        if field not in data:

            return jsonify({
                "error": f"{field}_required"
            }), 400

    try:

        user_id = int(data["user_id"])

        kem_public_key = base64.b64decode(
            data["kem_public_key"]
        )

    except Exception:

        return jsonify({
            "error": "invalid_data"
        }), 400

    dsa_public_key = None

    if data.get("dsa_public_key"):

        dsa_public_key = base64.b64decode(
            data["dsa_public_key"]
        )

    conn = get_connection()

    user = conn.execute(
        """
        SELECT id
        FROM users
        WHERE id = ?
        """,
        (user_id,)
    ).fetchone()

    if user is None:

        conn.close()

        return jsonify({
            "error": "user_not_found"
        }), 404

    cursor = conn.execute(
        """
        INSERT INTO devices (
            user_id,
            device_name,
            kem_public_key,
            dsa_public_key
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            user_id,
            data["device_name"],
            kem_public_key,
            dsa_public_key
        )
    )

    conn.commit()

    device_id = cursor.lastrowid

    conn.close()

    return jsonify({
        "device_id": device_id,
        "status": "registered"
    }), 201


@app.route(
    "/api/users/<int:user_id>/devices",
    methods=["GET"]
)
def get_user_devices(user_id):

    conn = get_connection()

    rows = conn.execute(
        """
        SELECT
            id,
            user_id,
            device_name,
            kem_public_key,
            dsa_public_key,
            created_at,
            approved
        FROM devices
        WHERE user_id = ?
        ORDER BY id
        """,
        (user_id,)
    ).fetchall()

    conn.close()

    devices = []

    for row in rows:

        devices.append({
            "device_id": row["id"],
            "user_id": row["user_id"],
            "device_name": row["device_name"],
            "kem_public_key": base64.b64encode(
                row["kem_public_key"]
            ).decode("ascii"),
            "dsa_public_key": (
                base64.b64encode(
                    row["dsa_public_key"]
                ).decode("ascii")
                if row["dsa_public_key"]
                else None
            ),
            "created_at": row["created_at"],
            "approved": row["approved"]
        })

    return jsonify({
        "devices": devices
    })


@app.route(
    "/api/devices/<int:device_id>",
    methods=["GET"]
)
def get_device(device_id):

    conn = get_connection()

    row = conn.execute(
        """
        SELECT
            id,
            user_id,
            device_name,
            kem_public_key,
            dsa_public_key,
            created_at,
            approved
        FROM devices
        WHERE id = ?
        """,
        (device_id,)
    ).fetchone()

    conn.close()

    if row is None:

        return jsonify({
            "error": "device_not_found"
        }), 404

    return jsonify({
        "device_id": row["id"],
        "user_id": row["user_id"],
        "device_name": row["device_name"],
        "kem_public_key": base64.b64encode(
            row["kem_public_key"]
        ).decode("ascii"),
        "dsa_public_key": (
            base64.b64encode(
                row["dsa_public_key"]
            ).decode("ascii")
            if row["dsa_public_key"]
            else None
        ),
        "created_at": row["created_at"],
        "approved": row["approved"]
    })


# ============================================================
# KEM EXCHANGE
# ============================================================

@app.route(
    "/api/kem/exchange",
    methods=["POST"]
)
def create_kem_exchange():

    data = request.get_json()

    required = [
        "sender_device_id",
        "receiver_device_id",
        "ciphertext"
    ]

    for field in required:

        if field not in data:

            return jsonify({
                "error": f"{field}_required"
            }), 400

    try:

        sender_device_id = int(
            data["sender_device_id"]
        )

        receiver_device_id = int(
            data["receiver_device_id"]
        )

        ciphertext = base64.b64decode(
            data["ciphertext"]
        )

    except Exception:

        return jsonify({
            "error": "invalid_data"
        }), 400

    conn = get_connection()

    cursor = conn.execute(
        """
        INSERT INTO kem_exchanges (
            sender_device_id,
            receiver_device_id,
            ciphertext
        )
        VALUES (?, ?, ?)
        """,
        (
            sender_device_id,
            receiver_device_id,
            ciphertext
        )
    )

    conn.commit()

    exchange_id = cursor.lastrowid

    conn.close()

    return jsonify({
        "exchange_id": exchange_id,
        "status": "stored"
    }), 201


@app.route(
    "/api/kem/exchange/<int:exchange_id>",
    methods=["GET"]
)
def get_kem_exchange(exchange_id):

    conn = get_connection()

    row = conn.execute(
        """
        SELECT
            id,
            sender_device_id,
            receiver_device_id,
            ciphertext,
            created_at
        FROM kem_exchanges
        WHERE id = ?
        """,
        (exchange_id,)
    ).fetchone()

    conn.close()

    if row is None:

        return jsonify({
            "error": "exchange_not_found"
        }), 404

    return jsonify({
        "exchange_id": row["id"],
        "sender_device_id": row["sender_device_id"],
        "receiver_device_id": row["receiver_device_id"],
        "ciphertext": base64.b64encode(
            row["ciphertext"]
        ).decode("ascii"),
        "created_at": row["created_at"]
    })


# ============================================================
# VAULT
# ============================================================

@app.route(
    "/api/vaults",
    methods=["POST"]
)
def create_or_update_vault():

    data = request.get_json()

    required = [
        "user_id",
        "encrypted_vault",
        "vault_nonce"
    ]

    for field in required:

        if field not in data:

            return jsonify({
                "error": f"{field}_required"
            }), 400

    try:

        user_id = int(data["user_id"])

        encrypted_vault = base64.b64decode(
            data["encrypted_vault"]
        )

        vault_nonce = base64.b64decode(
            data["vault_nonce"]
        )

    except Exception:

        return jsonify({
            "error": "invalid_data"
        }), 400

    # --------------------------------------------------------
    # base_version
    # --------------------------------------------------------

    if "base_version" not in data:

        return jsonify({
            "error": "base_version_required"
        }), 400

    try:

        base_version = int(
            data["base_version"]
        )

    except Exception:

        return jsonify({
            "error": "invalid_base_version"
        }), 400

    conn = get_connection()

    existing = conn.execute(
        """
        SELECT
            id,
            version
        FROM vaults
        WHERE user_id = ?
        """,
        (user_id,)
    ).fetchone()

    # --------------------------------------------------------
    # TẠO VAULT MỚI
    # --------------------------------------------------------

    if existing is None:

        # Vault mới phải bắt đầu từ base_version = 0

        if base_version != 0:

            conn.close()

            return jsonify({
                "error": "version_conflict",
                "message": "Vault chưa tồn tại.",
                "server_version": 0,
                "client_base_version": base_version
            }), 409

        cursor = conn.execute(
            """
            INSERT INTO vaults (
                user_id,
                encrypted_vault,
                vault_nonce,
                version
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                user_id,
                encrypted_vault,
                vault_nonce,
                1
            )
        )

        conn.commit()

        vault_id = cursor.lastrowid

        conn.close()

        return jsonify({
            "vault_id": vault_id,
            "version": 1,
            "status": "vault_created"
        })

    # --------------------------------------------------------
    # VAULT ĐÃ TỒN TẠI
    # --------------------------------------------------------

    vault_id = existing["id"]
    server_version = existing["version"]

    # --------------------------------------------------------
    # KIỂM TRA XUNG ĐỘT
    # --------------------------------------------------------

    if base_version != server_version:

        conn.close()

        return jsonify({
            "error": "version_conflict",
            "message": (
                "Vault đã được thiết bị khác "
                "cập nhật."
            ),
            "server_version": server_version,
            "client_base_version": base_version
        }), 409

    # --------------------------------------------------------
    # CẬP NHẬT VAULT
    # --------------------------------------------------------

    new_version = server_version + 1

    conn.execute(
        """
        UPDATE vaults
        SET
            encrypted_vault = ?,
            vault_nonce = ?,
            version = ?
        WHERE id = ?
        """,
        (
            encrypted_vault,
            vault_nonce,
            new_version,
            vault_id
        )
    )

    conn.commit()

    conn.close()

    return jsonify({
        "vault_id": vault_id,
        "version": new_version,
        "status": "vault_updated"
    })


@app.route(
    "/api/vaults/<int:user_id>",
    methods=["GET"]
)
def get_vault(user_id):

    conn = get_connection()

    row = conn.execute(
        """
        SELECT
            id,
            user_id,
            encrypted_vault,
            vault_nonce,
            version
        FROM vaults
        WHERE user_id = ?
        """,
        (user_id,)
    ).fetchone()

    conn.close()

    if row is None:

        return jsonify({
            "error": "vault_not_found"
        }), 404

    return jsonify({
        "vault_id": row["id"],
        "user_id": row["user_id"],
        "encrypted_vault": base64.b64encode(
            row["encrypted_vault"]
        ).decode("ascii"),
        "vault_nonce": base64.b64encode(
            row["vault_nonce"]
        ).decode("ascii"),
        "version": row["version"]
    })


# ============================================================
# VAULT KEYS
# ============================================================

@app.route(
    "/api/vaults/<int:vault_id>/keys",
    methods=["POST"]
)
def create_vault_key(vault_id):

    data = request.get_json()

    required = [
        "device_id",
        "kem_ciphertext",
        "encrypted_vault_key",
        "nonce"
    ]

    for field in required:

        if field not in data:

            return jsonify({
                "error": f"{field}_required"
            }), 400

    try:

        device_id = int(
            data["device_id"]
        )

        kem_ciphertext = base64.b64decode(
            data["kem_ciphertext"]
        )

        encrypted_vault_key = base64.b64decode(
            data["encrypted_vault_key"]
        )

        nonce = base64.b64decode(
            data["nonce"]
        )

    except Exception:

        return jsonify({
            "error": "invalid_data"
        }), 400

    conn = get_connection()

    cursor = conn.execute(
        """
        INSERT INTO vault_keys (
            vault_id,
            device_id,
            kem_ciphertext,
            encrypted_vault_key,
            nonce
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            vault_id,
            device_id,
            kem_ciphertext,
            encrypted_vault_key,
            nonce
        )
    )

    conn.commit()

    key_id = cursor.lastrowid

    conn.close()

    return jsonify({
        "key_id": key_id,
        "status": "vault_key_stored"
    }), 201


@app.route(
    "/api/vaults/<int:vault_id>/keys/<int:device_id>",
    methods=["GET"]
)
def get_vault_key(
    vault_id,
    device_id
):

    conn = get_connection()

    row = conn.execute(
        """
        SELECT
            id,
            vault_id,
            device_id,
            kem_ciphertext,
            encrypted_vault_key,
            nonce
        FROM vault_keys
        WHERE
            vault_id = ?
            AND device_id = ?
        ORDER BY id DESC
        LIMIT 1
        """,
        (
            vault_id,
            device_id
        )
    ).fetchone()

    conn.close()

    if row is None:

        return jsonify({
            "error": "vault_key_not_found"
        }), 404

    return jsonify({
        "key_id": row["id"],
        "vault_id": row["vault_id"],
        "device_id": row["device_id"],
        "kem_ciphertext": base64.b64encode(
            row["kem_ciphertext"]
        ).decode("ascii"),
        "encrypted_vault_key": base64.b64encode(
            row["encrypted_vault_key"]
        ).decode("ascii"),
        "nonce": base64.b64encode(
            row["nonce"]
        ).decode("ascii")
    })


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=8000,
        debug=True
    )