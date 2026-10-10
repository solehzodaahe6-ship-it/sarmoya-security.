import hashlib
import hmac
import secrets


DEMO_USERNAME = "parent"
DEMO_PASSWORD = "Sarmoya2026!"


def hash_password(password: str, salt: bytes) -> str:
    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        120_000,
    )

    return password_hash.hex()


def create_password(password: str):
    salt = secrets.token_bytes(16)
    password_hash = hash_password(password, salt)

    return salt.hex(), password_hash


def verify_password(
    password: str,
    salt_hex: str,
    password_hash: str
) -> bool:

    try:
        salt = bytes.fromhex(salt_hex)

        calculated = hash_password(
            password,
            salt
        )

        return hmac.compare_digest(
            calculated,
            password_hash
        )

    except (ValueError, TypeError):
        return False


def generate_otp() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


def hash_otp(code: str) -> str:
    return hashlib.sha256(
        code.encode("utf-8")
    ).hexdigest()


def verify_otp(code: str, code_hash: str) -> bool:
    return hmac.compare_digest(
        hash_otp(code),
        code_hash
    )