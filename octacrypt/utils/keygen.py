from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
from cryptography.hazmat.backends import default_backend


def generate_rsa(bits: int = 2048):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=bits,
        backend=default_backend(),
    )

    return private_key


def generate_ed25519():
    return ed25519.Ed25519PrivateKey.generate()


def save_keys(private_key, name: str):
    private_path = Path(f"{name}.key")
    public_path = Path(f"{name}.pub")

    # Private key PEM
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Public key PEM
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    private_path.write_bytes(private_bytes)
    public_path.write_bytes(public_bytes)

    return private_path, public_path
