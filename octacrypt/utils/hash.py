# octacrypt/utils/hash.py

from cryptography.hazmat.primitives import hashes
import bcrypt
import os


def hash_sha(data: bytes, algorithm: str = "sha256") -> str:
    algo = algorithm.lower()

    if algo == "sha256":
        digest = hashes.Hash(hashes.SHA256())
    elif algo == "sha512":
        digest = hashes.Hash(hashes.SHA512())
    else:
        raise ValueError("Unsupported SHA algorithm")

    digest.update(data)
    return digest.finalize().hex()


def hash_bcrypt(password: str) -> str:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed.decode()


def verify_bcrypt(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())


def hash_scrypt(password: str) -> bytes:
    salt = os.urandom(16)

    kdf = hashes.Hash(
        hashes.SHA256()
    )

    kdf.update(password.encode() + salt)
    return salt + kdf.finalize()
