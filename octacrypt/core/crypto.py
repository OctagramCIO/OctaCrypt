# octacrypt/core/crypto.py

from pathlib import Path
from octacrypt.core.crypto_engine import CryptoEngine


def encrypt_file(input_path: Path, output_path: Path | None, key: str):
    engine = CryptoEngine(
        algorithm="xor",
        key=key.encode()
    )

    data = input_path.read_bytes()
    encrypted = engine.encrypt(data)

    if output_path is None:
        output_path = input_path.with_suffix(input_path.suffix + ".enc")

    output_path.write_bytes(encrypted)
    return output_path


def decrypt_file(input_path: Path, output_path: Path | None, key: str):
    engine = CryptoEngine(
        algorithm="xor",
        key=key.encode()
    )

    data = input_path.read_bytes()
    decrypted = engine.decrypt(data)

    if output_path is None:
        output_path = input_path.with_suffix("")

    output_path.write_bytes(decrypted)
    return output_path

