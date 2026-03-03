# octacrypt/cli/hybrid.py
#
# Comandos CLI para cifrado híbrido:
#   octacrypt hybrid-encrypt <file> --pub key_public.pem [--out output]
#   octacrypt hybrid-decrypt <file> --priv key_private.pem [--out output] [--password ...]

import click
from pathlib import Path

from octacrypt.algorithms.hybrid import HybridCipher


@click.command("hybrid-encrypt")
@click.argument("input_file")
@click.option("--pub", "pub_key", required=True, help="Ruta a la clave pública RSA (.pem)")
@click.option("--out", default=None, help="Archivo de salida (default: input.henc)")
def hybrid_encrypt(input_file, pub_key, out):
    """
    Cifra un archivo con cifrado híbrido RSA + AES-256-GCM.

    Usa la clave pública RSA para proteger la session key AES.
    """
    input_path = Path(input_file)
    pub_path = Path(pub_key)

    if not input_path.exists():
        raise click.ClickException(f"Archivo no encontrado: {input_path}")

    if not pub_path.exists():
        raise click.ClickException(f"Clave pública no encontrada: {pub_path}")

    output_path = Path(out) if out else input_path.with_suffix(input_path.suffix + ".henc")

    # Leer clave pública y datos
    pub_pem = pub_path.read_bytes()
    data = input_path.read_bytes()

    # Cifrar
    cipher = HybridCipher(public_key_pem=pub_pem)
    encrypted = cipher.encrypt(data)

    output_path.write_bytes(encrypted)

    click.echo(f"✅ Archivo cifrado con RSA + AES-256-GCM")
    click.echo(f"   → Entrada : {input_path}")
    click.echo(f"   → Salida  : {output_path}")
    click.echo(f"   → Clave   : {pub_path}")


@click.command("hybrid-decrypt")
@click.argument("input_file")
@click.option("--priv", "priv_key", required=True, help="Ruta a la clave privada RSA (.pem)")
@click.option("--out", default=None, help="Archivo de salida (default: sin extensión .henc)")
@click.option("--password", default=None, help="Contraseña de la clave privada (si aplica)")
def hybrid_decrypt(input_file, priv_key, out, password):
    """
    Descifra un archivo cifrado con hybrid-encrypt.

    Usa la clave privada RSA para recuperar la session key AES.
    """
    input_path = Path(input_file)
    priv_path = Path(priv_key)

    if not input_path.exists():
        raise click.ClickException(f"Archivo no encontrado: {input_path}")

    if not priv_path.exists():
        raise click.ClickException(f"Clave privada no encontrada: {priv_path}")

    # Output: quitar .henc si existe
    if out:
        output_path = Path(out)
    elif input_path.suffix == ".henc":
        output_path = input_path.with_suffix("")
    else:
        output_path = input_path.with_suffix(".dec")

    # Leer clave privada y datos cifrados
    priv_pem = priv_path.read_bytes()
    password_bytes = password.encode() if password else None
    data = input_path.read_bytes()

    # Descifrar
    cipher = HybridCipher(
        private_key_pem=priv_pem,
        private_key_password=password_bytes,
    )
    decrypted = cipher.decrypt(data)

    output_path.write_bytes(decrypted)

    click.echo(f"✅ Archivo descifrado correctamente")
    click.echo(f"   → Entrada : {input_path}")
    click.echo(f"   → Salida  : {output_path}")
    click.echo(f"   → Clave   : {priv_path}")