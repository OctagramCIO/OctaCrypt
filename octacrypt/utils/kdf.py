from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os


SALT_SIZE = 16        # 128 bits
ITERATIONS = 200_000  # seguro y razonable en 2025
KEY_SIZE = 32         # AES-256


def derive_key(password: str, salt: bytes) -> bytes:
    if not isinstance(password, str):
        raise TypeError("Password must be a string")

    if not isinstance(salt, bytes):
        raise TypeError("Salt must be bytes")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )

    return kdf.derive(password.encode())


def generate_salt() -> bytes:
    return os.urandom(SALT_SIZE)
