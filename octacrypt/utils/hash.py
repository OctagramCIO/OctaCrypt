import hashlib
import hmac
import os

import bcrypt


def _to_bytes(value: str | bytes) -> bytes:
    return value.encode() if isinstance(value, str) else value


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

def bcrypt_hash(password: str | bytes) -> str:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(_to_bytes(password), salt)
    return hashed.decode()


def bcrypt_verify(password: str | bytes, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(_to_bytes(password), hashed.encode())
    except (ValueError, TypeError):
        return False


# -------------------------
# SCRYPT (passwords)
# -------------------------

_SCRYPT_PREFIX = "scrypt"
_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_SALT_SIZE = 16
# Longitud fija del salt del formato antiguo (bcrypt.gensalt() = 29 bytes)
_LEGACY_SCRYPT_SALT_SIZE = 29
# Límites superiores para evitar DoS por parámetros maliciosos en el hash almacenado.
_SCRYPT_MAX_N = 2**20
_SCRYPT_MAX_R = 32
_SCRYPT_MAX_P = 16


def _scrypt_params_valid(n: int, r: int, p: int) -> bool:
    return (
        1 < n <= _SCRYPT_MAX_N
        and n & (n - 1) == 0  # n debe ser potencia de 2
        and 1 <= r <= _SCRYPT_MAX_R
        and 1 <= p <= _SCRYPT_MAX_P
    )


def scrypt_hash(password: str | bytes) -> str:
    """
    Hash scrypt con formato propio:
      scrypt$<n>$<r>$<p>$<salt_hex>$<key_hex>
    """
    salt = os.urandom(_SCRYPT_SALT_SIZE)
    key = hashlib.scrypt(
        _to_bytes(password), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P
    )
    return f"{_SCRYPT_PREFIX}${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${salt.hex()}${key.hex()}"


def scrypt_verify(password: str | bytes, stored: str) -> bool:
    """
    Verifica un hash scrypt. Soporta el formato propio
    (scrypt$n$r$p$salt$key) y el formato antiguo (hex continuo salt+key).
    """
    if stored.startswith(f"{_SCRYPT_PREFIX}$"):
        parts = stored.split("$")
        if len(parts) != 6 or parts[0] != _SCRYPT_PREFIX:
            return False
        try:
            n, r, p = int(parts[1]), int(parts[2]), int(parts[3])
            salt = bytes.fromhex(parts[4])
            expected = bytes.fromhex(parts[5])
        except ValueError:
            return False
        if not _scrypt_params_valid(n, r, p):
            return False
        if not salt or not expected:
            return False
    else:
        # Formato legado: salt bcrypt (29 bytes) + key, todo en hex
        try:
            raw = bytes.fromhex(stored)
        except ValueError:
            return False
        if len(raw) <= _LEGACY_SCRYPT_SALT_SIZE:
            return False
        salt = raw[:_LEGACY_SCRYPT_SALT_SIZE]
        expected = raw[_LEGACY_SCRYPT_SALT_SIZE:]
        n, r, p = _SCRYPT_N, _SCRYPT_R, _SCRYPT_P

    key = hashlib.scrypt(_to_bytes(password), salt=salt, n=n, r=r, p=p)
    return hmac.compare_digest(key, expected)
