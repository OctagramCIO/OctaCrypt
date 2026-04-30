# octacrypt/cli/encrypt.py

import click
from pathlib import Path

from octacrypt.core.crypto import encrypt_file


@click.command("encrypt")
@click.argument("input_file")
@click.option("--key", required=True, help="Contraseña de cifrado")
@click.option("--out", default=None, help="Archivo de salida (default: input.enc)")
@click.option(
    "--alg",
    default="aes",
    type=click.Choice(["aes", "hybrid"]),
    help="Algoritmo: aes (default) o hybrid (requiere --pub)",
)
@click.option("--pub", "pub_key", default=None, help="Clave pública RSA para modo hybrid")
def encrypt(input_file, key, out, alg, pub_key):
    """
    Cifra un archivo con AES-256-GCM o cifrado híbrido RSA+AES.

    \b
    Ejemplos:
      octacrypt encrypt documento.pdf --key mipassword
      octacrypt encrypt documento.pdf --alg hybrid --pub key_public.pem
    """
    input_path = Path(input_file)

    if not input_path.exists():
        raise click.ClickException(f"Archivo no encontrado: {input_path}")

    if alg == "hybrid":
        if not pub_key:
            raise click.ClickException("El modo hybrid requiere --pub <clave_publica.pem>")

        pub_path = Path(pub_key)
        if not pub_path.exists():
            raise click.ClickException(f"Clave pública no encontrada: {pub_path}")

        from octacrypt.algorithms.hybrid import HybridCipher
        output_path = Path(out) if out else input_path.with_suffix(input_path.suffix + ".enc")

        data = input_path.read_bytes()
        cipher = HybridCipher(public_key_pem=pub_path.read_bytes())
        output_path.write_bytes(cipher.encrypt(data))

        click.echo(f"✅ Archivo cifrado con RSA-OAEP + AES-256-GCM")
        click.echo(f"   → Entrada : {input_path}")
        click.echo(f"   → Salida  : {output_path}")
        click.echo(f"   → Clave   : {pub_path}")

    else:
        output_path = Path(out) if out else None
        result = encrypt_file(
            input_path=input_path,
            output_path=output_path,
            key=key,
            algorithm="aes",
        )
        click.echo(f"✅ Archivo cifrado con AES-256-GCM + PBKDF2")
        click.echo(f"   → Entrada : {input_path}")
        click.echo(f"   → Salida  : {result}")