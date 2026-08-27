# octacrypt/utils/keygen.py

from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
from cryptography.hazmat.primitives import serialization

# Importación de los submódulos post-cuánticos (no re-exportados en `asymmetric/__init__`).
from cryptography.hazmat.primitives.asymmetric import mlkem, mldsa


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
