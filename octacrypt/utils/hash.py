import bcrypt
import hashlib


# -------------------------
# SHA (archivos / strings)
# -------------------------

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha512(data: bytes) -> str:
    return hashlib.sha512(data).hexdigest()


# -------------------------
# BCRYPT (passwords)
# -------------------------

def bcrypt_hash(password: str) -> str:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed.decode()


def bcrypt_verify(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())


# -------------------------
# SCRYPT (passwords)
# -------------------------

def scrypt_hash(password: str) -> str:
    salt = bcrypt.gensalt()  # bcrypt salt sirve perfecto
    key = hashlib.scrypt(
        password.encode(),
        salt=salt,
        n=2**14,
        r=8,
        p=1
    )
    return (salt + key).hex()


def scrypt_verify(password: str, stored_hex: str) -> bool:
    raw = bytes.fromhex(stored_hex)
    salt = raw[:29]
    key = raw[29:]

    new_key = hashlib.scrypt(
        password.encode(),
        salt=salt,
        n=2**14,
        r=8,
        p=1
    )
    return new_key == key

