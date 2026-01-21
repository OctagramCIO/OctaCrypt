import argparse
import sys
from pathlib import Path

from octacrypt.core.crypto import encrypt_file, decrypt_file


def build_parser():
    parser = argparse.ArgumentParser(
        prog="octacrypt",
        description="OctaCrypt – Secure file encryption tool"
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # encrypt
    enc = subparsers.add_parser("encrypt", help="Encrypt a file")
    enc.add_argument("input", help="Input file")
    enc.add_argument("--key", required=True, help="Encryption key")
    enc.add_argument("--out", help="Output file")

    # decrypt
    dec = subparsers.add_parser("decrypt", help="Decrypt a file")
    dec.add_argument("input", help="Encrypted file")
    dec.add_argument("--key", required=True, help="Decryption key")
    dec.add_argument("--out", help="Output file")

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    input_path = Path(args.input)

    if not input_path.exists():
        print(f"[✖] Archivo no encontrado: {input_path}")
        sys.exit(1)

    try:
        if args.command == "encrypt":
            output = args.out or f"{input_path}.enc"
            encrypt_file(input_path, output, args.key)

            print("[✔] Archivo cifrado correctamente")
            print(f"    → Entrada : {input_path}")
            print(f"    → Salida  : {output}")

        elif args.command == "decrypt":
            output = args.out or str(input_path).replace(".enc", "")
            decrypt_file(input_path, output, args.key)

            print("[✔] Archivo descifrado correctamente")
            print(f"    → Entrada : {input_path}")
            print(f"    → Salida  : {output}")

    except Exception as e:
        print(f"[✖] Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
