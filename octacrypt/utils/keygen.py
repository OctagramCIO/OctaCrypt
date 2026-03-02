from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
from cryptography.hazmat.primitives import serialization


def generate_rsa(bits: int = 2048):
    """
    Generate RSA private key
    """
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=bits
    )


def generate_ed25519():
    """
    Generate Ed25519 private key
    """
    return ed25519.Ed25519PrivateKey.generate()


def save_keys(private_key, name: str):
    """
    Save private and public keys in PEM format
    """
    public_key = private_key.public_key()

    private_path = f"{name}_private.pem"
    public_path = f"{name}_public.pem"

    # Save private key
    with open(private_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # Save public key
    with open(public_path, "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    return private_path, public_path
