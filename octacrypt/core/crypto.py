from pathlib import Path
from octacrypt.core.crypto_engine import CryptoEngine
from octacrypt.utils.kdf import derive_key, generate_salt
from octacrypt.algorithms.aes import AESAlgorithm


def encrypt_file(input_path: Path, output_path: str | Path | None, key: str):
    input_path = Path(input_path)

    if output_path is None:
        output_path = input_path.with_suffix(input_path.suffix + ".enc")
    else:
        output_path = Path(output_path)

    # 1️⃣ generar salt
    salt = generate_salt()

    # 2️⃣ derivar clave AES
    derived_key = derive_key(key, salt)

    # 3️⃣ cifrar
    engine = CryptoEngine("aes", derived_key)
    data = input_path.read_bytes()
    encrypted = engine.encrypt(data)

    # 4️⃣ escribir salt + ciphertext
    output_path.write_bytes(salt + encrypted)
    return output_path


def decrypt_file(input_path: Path, output_path: str | Path | None, key: str):
    input_path = Path(input_path)

    if output_path is None:
        output_path = input_path.with_suffix("")
    else:
        output_path = Path(output_path)

    raw = input_path.read_bytes()

    # 1️⃣ extraer salt
    salt = raw[:16]
    encrypted = raw[16:]

    # 2️⃣ derivar la misma clave
    derived_key = derive_key(key, salt)

    # 3️⃣ descifrar
    engine = CryptoEngine("aes", derived_key)
    decrypted = engine.decrypt(encrypted)

    output_path.write_bytes(decrypted)
    return output_path
