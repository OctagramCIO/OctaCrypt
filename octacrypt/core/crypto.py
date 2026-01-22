from pathlib import Path
from octacrypt.core.crypto_engine import CryptoEngine
from octacrypt.utils.kdf import derive_key, generate_salt


def encrypt_file(
    input_path: Path,
    output_path: str | Path | None,
    key: str,
    algorithm: str = "xor",
):
    input_path = Path(input_path)

    if output_path is None:
        output_path = input_path.with_suffix(input_path.suffix + ".enc")
    else:
        output_path = Path(output_path)

    # --- AES uses KDF ---
    if algorithm == "aes":
        salt = generate_salt()
        derived_key = derive_key(key, salt)
        engine = CryptoEngine("aes", derived_key)
    else:
        engine = CryptoEngine("xor", key.encode())
        salt = b""

    data = input_path.read_bytes()
    encrypted = engine.encrypt(data)

    # AES: salt + nonce + ciphertext
    output_path.write_bytes(salt + encrypted)
    return output_path


def decrypt_file(
    input_path: Path,
    output_path: str | Path | None,
    key: str,
    algorithm: str = "xor",
):
    input_path = Path(input_path)

    if output_path is None:
        output_path = input_path.with_suffix("")
    else:
        output_path = Path(output_path)

    raw = input_path.read_bytes()

    if algorithm == "aes":
        salt = raw[:16]
        encrypted = raw[16:]
        derived_key = derive_key(key, salt)
        engine = CryptoEngine("aes", derived_key)
    else:
        encrypted = raw
        engine = CryptoEngine("xor", key.encode())

    decrypted = engine.decrypt(encrypted)
    output_path.write_bytes(decrypted)
    return output_path

