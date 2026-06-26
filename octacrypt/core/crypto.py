from pathlib import Path
from octacrypt.core.crypto_engine import CryptoEngine
from octacrypt.utils.kdf import derive_key, generate_salt

SALT_SIZE = 16

def encrypt_file(input_path, output_path, key: str, algorithm: str = "aes"):
    input_path = Path(input_path)
    output_path = Path(output_path) if output_path else input_path.with_suffix(input_path.suffix + ".enc")
    salt = generate_salt()
    derived_key = derive_key(key, salt)
    engine = CryptoEngine(algorithm, derived_key)
    encrypted = engine.encrypt(input_path.read_bytes())
    algo_prefix = algorithm.encode().ljust(10, b"\x00")
    output_path.write_bytes(algo_prefix + salt + encrypted)
    return output_path

def decrypt_file(input_path, output_path, key: str, algorithm: str = "aes"):
    input_path = Path(input_path)
    output_path = Path(output_path) if output_path else input_path.with_suffix("")
    raw = input_path.read_bytes()
    algo_prefix = raw[:10].rstrip(b"\x00").decode()
    salt = raw[10:10 + SALT_SIZE]
    encrypted = raw[10 + SALT_SIZE:]
    derived_key = derive_key(key, salt)
    engine = CryptoEngine(algo_prefix, derived_key)
    output_path.write_bytes(engine.decrypt(encrypted))
    return output_path
