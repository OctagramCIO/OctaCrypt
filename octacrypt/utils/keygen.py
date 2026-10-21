# octacrypt/utils/keygen.py

import os

from cryptography.hazmat.primitives import serialization

# Importación de los submódulos post-cuánticos (no re-exportados en `asymmetric/__init__`).
from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa, mlkem, rsa


def _write_private_file(path: str, data: bytes) -> None:
    """
    Escribe un archivo sensible creándolo con permisos restrictivos (0600 en
    sistemas POSIX) para que la clave privada no sea legible por otros usuarios.
    """
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    # Garantiza permisos correctos aunque el archivo ya existiera.
    if os.name == "posix":
        os.chmod(path, 0o600)


def generate_rsa(bits: int = 2048):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def generate_ed25519():
    return ed25519.Ed25519PrivateKey.generate()


def generate_mlkem(variant: str = "mlkem768"):
    """
    Genera una clave privada ML-KEM (post-cuántica, FIPS 203).

    Args:
        variant: "mlkem768" (recomendado) o "mlkem1024".
    """
    if variant not in ("mlkem768", "mlkem1024"):
        raise ValueError("La variante ML-KEM debe ser 'mlkem768' o 'mlkem1024'.")

    private_class = getattr(mlkem, f"{variant.upper()}PrivateKey")
    return private_class.generate()


def generate_mldsa(variant: str = "mldsa65"):
    """
    Genera una clave privada ML-DSA (post-cuántica, FIPS 204).

    Args:
        variant: "mldsa44", "mldsa65" (recomendado) o "mldsa87".
    """
    if variant not in ("mldsa44", "mldsa65", "mldsa87"):
        raise ValueError("La variante ML-DSA debe ser 'mldsa44', 'mldsa65' o 'mldsa87'.")

    private_class = getattr(mldsa, f"{variant.upper()}PrivateKey")
    return private_class.generate()


def save_keys(private_key, name: str, password: str | None = None):
    """
    Guarda un par de claves en formato PEM.

    Si se provee password, la clave privada se cifra con AES-256-CBC (BestAvailableEncryption).
    La clave publica NUNCA se cifra.

    La clave privada se crea con permisos restrictivos (0600 en POSIX).
    """
    public_key = private_key.public_key()

    private_path = f"{name}_private.pem"
    public_path = f"{name}_public.pem"

    # Cifrado de la clave privada
    if password:
        encryption = serialization.BestAvailableEncryption(password.encode())
    else:
        encryption = serialization.NoEncryption()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    _write_private_file(private_path, private_bytes)

    with open(public_path, "wb") as f:
        f.write(public_bytes)

    return private_path, public_path


def load_private_key(path: str, password: str | None = None):
    """
    Carga una clave privada PEM, con o sin password.

    Args:
        path:     Ruta al archivo .pem
        password: Contrasena si la clave esta cifrada (None si no lo esta)

    Returns:
        Objeto de clave privada de cryptography.
    """
    with open(path, "rb") as f:
        pem_data = f.read()

    password_bytes = password.encode() if password else None

    return serialization.load_pem_private_key(pem_data, password=password_bytes)
