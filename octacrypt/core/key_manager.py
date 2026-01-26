import os

def generate_key(length: int = 32) -> bytes:
    """
    Generate a secure random key.
    Default: 32 bytes (AES-256)
    """
    return os.urandom(length)
