# octacrypt/core/crypto.py

from pathlib import Path
from octacrypt.core.crypto_engine import CryptoEngine


def encrypt_file(input_path: Path, output_path: str | Path | None, key: str):
    engine = CryptoEngine(
        algorithm="xor",
        key=key.encode()
    )

    input_path = Path(input_path)

    if output_path is None:
        output_path = input_path.with_suffix(input_path.suffix + ".enc")
    else:
        output_path = Path(output_path)

    data = input_path.read_bytes()
    encrypted = engine.encrypt(data)

    output_path.write_bytes(encrypted)
    return output_path


def decrypt_file(input_path: Path, output_path: str | Path | None, key: str):
    engine = CryptoEngine(
        algorithm="xor",
        key=key.encode()
    )

    input_path = Path(input_path)

    if output_path is None:
        output_path = input_path.with_suffix("")
    else:
        output_path = Path(output_path)

    data = input_path.read_bytes()
    decrypted = engine.decrypt(data)

    output_path.write_bytes(decrypted)
    return output_path
