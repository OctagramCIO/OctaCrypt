# octacrypt/cli/main.py

import argparse
from pathlib import Path

from octacrypt.core.crypto_engine import CryptoEngine


def encrypt_file(input_path: Path, key: bytes):
    data = input_path.read_bytes()

    engine = CryptoEngine(
        algorithm="xor",
        key=key
    )

    encrypted = engine.encrypt(data)

    output_path = input_path.with_suffix(input_path.suffix + ".enc")
    output_path.write_bytes(encrypted)

    print(f"[+] Archivo cifrado: {output_path}")


def decrypt_file(input_path: Path, key: bytes):
    data = input_path.read_bytes()

    engine = CryptoEngine(
        algorithm="xor",
        key=key
    )

    decrypted = engine.decrypt(data)

    output_path = input_path.with_suffix("")
    output_path.write_bytes(decrypted)

    print(f"[+] Archivo descifrado: {output_path}")


def main():
    parser = argparse.ArgumentParser(
        prog="octacrypt",
        description="OctaCrypt – Secure file encryption tool"
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # encrypt
    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt a file")
    encrypt_parser.add_argument("file", help="File to encrypt")
    encrypt_parser.add_argument("--key", required=True, help="Encryption key")

    # decrypt
    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt a file")
    decrypt_parser.add_argument("file", help="File to decrypt")
    decrypt_parser.add_argument("--key", required=True, help="Decryption key")

    args = parser.parse_args()

    file_path = Path(args.file)

    if not file_path.exists():
        print("[-] Error: file does not exist")
        return

    key_bytes = args.key.encode()

    if args.command == "encrypt":
        encrypt_file(file_path, key_bytes)

    elif args.command == "decrypt":
        decrypt_file(file_path, key_bytes)


if __name__ == "__main__":
    main()