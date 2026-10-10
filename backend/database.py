import sqlite3
from datetime import datetime

from auth import (
    DEMO_USERNAME,
    DEMO_PASSWORD,
    create_password,
)


DATABASE_NAME = "sarmoya_shield.db"


def get_connection():
    connection = sqlite3.connect(DATABASE_NAME)
    connection.row_factory = sqlite3.Row
    return connection


def column_exists(connection, table_name, column_name):
    rows = connection.execute(
        f"PRAGMA table_info({table_name})"
    ).fetchall()

    return any(
        row["name"] == column_name
        for row in rows
    )


def add_column_if_missing(
    connection,
    table_name,
    column_name,
    column_type,
):
    if not column_exists(
        connection,
        table_name,
        column_name,
    ):
        connection.execute(
            f"ALTER TABLE {table_name} "
            f"ADD COLUMN {column_name} {column_type}"
        )


def init_db():
    connection = get_connection()

    # ========================================================
    # BLOCKED EVENTS
    # ========================================================

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS blocked_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            category TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )

    # ========================================================
    # CUSTOM RULES
    # ========================================================

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS custom_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL UNIQUE,
            action TEXT NOT NULL,
            category TEXT NOT NULL DEFAULT 'custom',
            created_at TEXT NOT NULL
        )
        """
    )

    # ========================================================
    # USERS
    # ========================================================

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_salt TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'parent',
            created_at TEXT NOT NULL
        )
        """
    )

    # Existing database migration
    add_column_if_missing(
        connection,
        "users",
        "full_name",
        "TEXT",
    )

    add_column_if_missing(
        connection,
        "users",
        "phone",
        "TEXT",
    )

    add_column_if_missing(
        connection,
        "users",
        "email",
        "TEXT",
    )

    add_column_if_missing(
        connection,
        "users",
        "is_verified",
        "INTEGER NOT NULL DEFAULT 0",
    )

    add_column_if_missing(
        connection,
        "users",
        "google_sub",
        "TEXT",
    )

    # ========================================================
    # OTP
    # ========================================================

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS otp_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            code_hash TEXT NOT NULL,
            channel TEXT NOT NULL,
            purpose TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        """
    )

    # ========================================================
    # UNIQUE INDEXES
    # ========================================================

    connection.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS
        idx_users_email
        ON users(email)
        WHERE email IS NOT NULL
        """
    )

    connection.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS
        idx_users_phone
        ON users(phone)
        WHERE phone IS NOT NULL
        """
    )

    connection.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS
        idx_users_google_sub
        ON users(google_sub)
        WHERE google_sub IS NOT NULL
        """
    )

    # ========================================================
    # DEMO ACCOUNT
    # ========================================================

    demo_user = connection.execute(
        """
        SELECT id
        FROM users
        WHERE username = ?
        """,
        (DEMO_USERNAME,),
    ).fetchone()

    if demo_user is None:

        salt, password_hash = create_password(
            DEMO_PASSWORD
        )

        connection.execute(
            """
            INSERT INTO users
            (
                username,
                password_salt,
                password_hash,
                role,
                created_at,
                full_name,
                phone,
                email,
                is_verified,
                google_sub
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                DEMO_USERNAME,
                salt,
                password_hash,
                "parent",
                datetime.now().isoformat(
                    timespec="seconds"
                ),
                "Demo Parent",
                None,
                "demo@sarmoya.local",
                1,
                None,
            ),
        )

    connection.commit()
    connection.close()


# ============================================================
# USERS
# ============================================================

def get_user_by_id(user_id):

    connection = get_connection()

    row = connection.execute(
        """
        SELECT *
        FROM users
        WHERE id = ?
        """,
        (user_id,),
    ).fetchone()

    connection.close()

    return dict(row) if row else None


def get_user_by_username(username):

    connection = get_connection()

    row = connection.execute(
        """
        SELECT *
        FROM users
        WHERE username = ?
        """,
        (username,),
    ).fetchone()

    connection.close()

    return dict(row) if row else None


def get_user_by_email(email):

    connection = get_connection()

    row = connection.execute(
        """
        SELECT *
        FROM users
        WHERE email = ?
        """,
        (email,),
    ).fetchone()

    connection.close()

    return dict(row) if row else None


def get_user_by_phone(phone):

    connection = get_connection()

    row = connection.execute(
        """
        SELECT *
        FROM users
        WHERE phone = ?
        """,
        (phone,),
    ).fetchone()

    connection.close()

    return dict(row) if row else None


def get_user_by_google_sub(google_sub):

    connection = get_connection()

    row = connection.execute(
        """
        SELECT *
        FROM users
        WHERE google_sub = ?
        """,
        (google_sub,),
    ).fetchone()

    connection.close()

    return dict(row) if row else None


def create_user(
    full_name,
    phone,
    email,
    password_salt,
    password_hash,
):

    connection = get_connection()

    cursor = connection.execute(
        """
        INSERT INTO users
        (
            username,
            password_salt,
            password_hash,
            role,
            created_at,
            full_name,
            phone,
            email,
            is_verified,
            google_sub
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            email,
            password_salt,
            password_hash,
            "parent",
            datetime.now().isoformat(
                timespec="seconds"
            ),
            full_name,
            phone,
            email,
            0,
            None,
        ),
    )

    connection.commit()

    user_id = cursor.lastrowid

    connection.close()

    return user_id


def create_google_user(
    full_name,
    email,
    google_sub,
):

    connection = get_connection()

    cursor = connection.execute(
        """
        INSERT INTO users
        (
            username,
            password_salt,
            password_hash,
            role,
            created_at,
            full_name,
            phone,
            email,
            is_verified,
            google_sub
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            email,
            "",
            "",
            "parent",
            datetime.now().isoformat(
                timespec="seconds"
            ),
            full_name,
            None,
            email,
            1,
            google_sub,
        ),
    )

    connection.commit()

    user_id = cursor.lastrowid

    connection.close()

    return user_id


def verify_user(user_id):

    connection = get_connection()

    connection.execute(
        """
        UPDATE users
        SET is_verified = 1
        WHERE id = ?
        """,
        (user_id,),
    )

    connection.commit()
    connection.close()


# ============================================================
# OTP
# ============================================================

def create_otp(
    user_id,
    code_hash,
    channel,
    purpose,
    expires_at,
):

    connection = get_connection()

    connection.execute(
        """
        DELETE FROM otp_codes
        WHERE user_id = ?
        AND purpose = ?
        """,
        (
            user_id,
            purpose,
        ),
    )

    connection.execute(
        """
        INSERT INTO otp_codes
        (
            user_id,
            code_hash,
            channel,
            purpose,
            expires_at,
            attempts,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            user_id,
            code_hash,
            channel,
            purpose,
            expires_at,
            0,
            datetime.now().isoformat(
                timespec="seconds"
            ),
        ),
    )

    connection.commit()
    connection.close()


def get_latest_otp(
    user_id,
    purpose,
):

    connection = get_connection()

    row = connection.execute(
        """
        SELECT *
        FROM otp_codes
        WHERE user_id = ?
        AND purpose = ?
        ORDER BY id DESC
        LIMIT 1
        """,
        (
            user_id,
            purpose,
        ),
    ).fetchone()

    connection.close()

    return dict(row) if row else None


def increment_otp_attempt(otp_id):

    connection = get_connection()

    connection.execute(
        """
        UPDATE otp_codes
        SET attempts = attempts + 1
        WHERE id = ?
        """,
        (otp_id,),
    )

    connection.commit()
    connection.close()


# ============================================================
# BLOCKED EVENTS
# ============================================================

def save_blocked_event(
    domain,
    category,
):

    connection = get_connection()

    connection.execute(
        """
        INSERT INTO blocked_events
        (
            domain,
            category,
            created_at
        )
        VALUES (?, ?, ?)
        """,
        (
            domain,
            category,
            datetime.now().isoformat(
                timespec="seconds"
            ),
        ),
    )

    connection.commit()
    connection.close()


def get_stats():

    connection = get_connection()

    total = connection.execute(
        """
        SELECT COUNT(*)
        FROM blocked_events
        """
    ).fetchone()[0]

    rows = connection.execute(
        """
        SELECT
            category,
            COUNT(*) AS count
        FROM blocked_events
        GROUP BY category
        """
    ).fetchall()

    by_category = {
        row["category"]: row["count"]
        for row in rows
    }

    connection.close()

    return {
        "total_blocked": total,
        "by_category": by_category,
    }


def get_recent_events(limit=20):

    connection = get_connection()

    rows = connection.execute(
        """
        SELECT
            id,
            domain,
            category,
            created_at
        FROM blocked_events
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()

    connection.close()

    return [
        dict(row)
        for row in rows
    ]


# ============================================================
# CUSTOM RULES
# ============================================================

def get_rule_for_domain(domain):

    connection = get_connection()

    row = connection.execute(
        """
        SELECT *
        FROM custom_rules
        WHERE domain = ?
        """,
        (domain,),
    ).fetchone()

    connection.close()

    return dict(row) if row else None


def get_all_rules():

    connection = get_connection()

    rows = connection.execute(
        """
        SELECT *
        FROM custom_rules
        ORDER BY id DESC
        """
    ).fetchall()

    connection.close()

    return [
        dict(row)
        for row in rows
    ]


def add_rule(
    domain,
    action,
    category="custom",
):

    connection = get_connection()

    connection.execute(
        """
        INSERT INTO custom_rules
        (
            domain,
            action,
            category,
            created_at
        )
        VALUES (?, ?, ?, ?)
        ON CONFLICT(domain)
        DO UPDATE SET
            action = excluded.action,
            category = excluded.category
        """,
        (
            domain,
            action,
            category,
            datetime.now().isoformat(
                timespec="seconds"
            ),
        ),
    )

    connection.commit()
    connection.close()


def delete_rule(rule_id):

    connection = get_connection()

    connection.execute(
        """
        DELETE FROM custom_rules
        WHERE id = ?
        """,
        (rule_id,),
    )

    connection.commit()
    connection.close()