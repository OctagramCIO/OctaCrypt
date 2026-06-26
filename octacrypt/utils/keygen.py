# octacrypt/utils/keygen.py

from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
from cryptography.hazmat.primitives import serialization


def generate_rsa(bits: int = 2048):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def generate_ed25519():
    return ed25519.Ed25519PrivateKey.generate()


def save_keys(private_key, name: str, password: str | None = None):
    """
    Guarda un par de claves en formato PEM.

    Si se provee password, la clave privada se cifra con AES-256-CBC (BestAvailableEncryption).
    La clave publica NUNCA se cifra.
    """
    public_key = private_key.public_key()

    private_path = f"{name}_private.pem"
    public_path = f"{name}_public.pem"

    # Cifrado de la clave privada
    if password:
        encryption = serialization.BestAvailableEncryption(password.encode())
    else:
        encryption = serialization.NoEncryption()

    with open(private_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption,
            )
        )

    with open(public_path, "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

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
