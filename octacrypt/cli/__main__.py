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
    enc.add_argument(
        "--alg",
        default="xor",
        choices=["xor", "aes"],
        help="Encryption algorithm (default: xor)"
    )

    # decrypt
    dec = subparsers.add_parser("decrypt", help="Decrypt a file")
    dec.add_argument("input", help="Encrypted file")
    dec.add_argument("--key", required=True, help="Decryption key")
    dec.add_argument("--out", help="Output file")
    dec.add_argument(
        "--alg",
        default="xor",
        choices=["xor", "aes"],
        help="Decryption algorithm (default: xor)"
    )

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
            output = Path(args.out) if args.out else input_path.with_suffix(
                input_path.suffix + ".enc"
            )

            encrypt_file(
                input_path=input_path,
                key=args.key,
                output_path=output,
                algorithm=args.alg
            )

            print("[✔] Archivo cifrado correctamente")
            print(f"    → Entrada : {input_path}")
            print(f"    → Salida  : {output}")
            print(f"    → Alg     : {args.alg}")

        elif args.command == "decrypt":
            output = Path(args.out) if args.out else input_path.with_suffix("")

            decrypt_file(
                input_path=input_path,
                key=args.key,
                output_path=output,
                algorithm=args.alg
            )

            print("[✔] Archivo descifrado correctamente")
            print(f"    → Entrada : {input_path}")
            print(f"    → Salida  : {output}")
            print(f"    → Alg     : {args.alg}")

    except Exception as e:
        print(f"[✖] Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()