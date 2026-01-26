import os

def generate_symmetric_key(length: int = 32) -> bytes:
    return os.urandom(length)
