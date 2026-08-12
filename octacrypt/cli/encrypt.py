# octacrypt/cli/encrypt.py

import click
from pathlib import Path
from octacrypt.core.crypto import encrypt_file


@click.command("encrypt")
@click.argument("input_file")
@click.option("--key", default=None, help="Contrasena de cifrado (modos aes/chacha20)")
@click.option("--out", default=None, help="Archivo de salida (default: input.enc)")
@click.option(
    "--alg",
    default="aes",
    type=click.Choice(["aes", "chacha20", "hybrid"]),
    help="Algoritmo: aes (default), chacha20, hybrid",
)
@click.option("--pub", "pub_key", default=None, help="Clave publica RSA para modo hybrid")
def encrypt(input_file, key, out, alg, pub_key):
    """
    Cifra un archivo.

    \b
    Modos:
      aes      -> AES-256-GCM + PBKDF2       (--key)
      chacha20 -> ChaCha20-Poly1305 + PBKDF2 (--key)
      hybrid   -> RSA-OAEP + AES-256-GCM     (--pub)

    \b
    Ejemplos:
      octacrypt encrypt doc.pdf --key mipassword
      octacrypt encrypt doc.pdf --alg chacha20 --key mipassword
      octacrypt encrypt doc.pdf --alg hybrid --pub key_public.pem
    """
    input_path = Path(input_file)
    if not input_path.exists():
        raise click.ClickException(f"Archivo no encontrado: {input_path}")

    if alg == "hybrid":
        if not pub_key:
            raise click.ClickException("El modo hybrid requiere --pub <clave_publica.pem>")
        pub_path = Path(pub_key)
        if not pub_path.exists():
            raise click.ClickException(f"Clave publica no encontrada: {pub_path}")
        from octacrypt.algorithms.hybrid import HybridCipher
        output_path = Path(out) if out else input_path.with_suffix(input_path.suffix + ".enc")
        try:
            cipher = HybridCipher(public_key_pem=pub_path.read_bytes())
            output_path.write_bytes(cipher.encrypt(input_path.read_bytes()))
            click.echo("Archivo cifrado con RSA-OAEP + AES-256-GCM")
            click.echo(f"   -> Entrada : {input_path}")
            click.echo(f"   -> Salida  : {output_path}")
            click.echo(f"   -> Clave   : {pub_path}")
        except Exception as e:
            raise click.ClickException(f"No se pudo cifrar: {e}")
    else:
        if not key:
            raise click.ClickException(f"El modo {alg} requiere --key <contrasena>")
        try:
            result = encrypt_file(
                input_path=input_path,
                output_path=Path(out) if out else None,
                key=key,
                algorithm=alg,
            )
            algo_label = "AES-256-GCM" if alg == "aes" else "ChaCha20-Poly1305"
            click.echo(f"Archivo cifrado con {algo_label} + PBKDF2")
            click.echo(f"   -> Entrada : {input_path}")
            click.echo(f"   -> Salida  : {result}")
        except Exception as e:
            raise click.ClickException(f"No se pudo cifrar: {e}")
