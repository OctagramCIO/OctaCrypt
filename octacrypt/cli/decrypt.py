# octacrypt/cli/decrypt.py

import click
from pathlib import Path
from octacrypt.core.crypto import decrypt_file


@click.command("decrypt")
@click.argument("input_file")
@click.option("--key", default=None, help="Contrasena de descifrado")
@click.option("--out", default=None, help="Archivo de salida (default: elimina .enc)")
@click.option(
    "--alg",
    default="aes",
    type=click.Choice(["aes", "chacha20", "hybrid"]),
    help="Algoritmo usado al cifrar: aes (default), chacha20, hybrid",
)
@click.option("--priv", "priv_key", default=None, help="Clave privada RSA para modo hybrid")
def decrypt(input_file, key, out, alg, priv_key):
    """
    Descifra un archivo cifrado con encrypt.

    \b
    Ejemplos:
      octacrypt decrypt doc.pdf.enc --key mipassword
      octacrypt decrypt doc.pdf.enc --alg chacha20 --key mipassword
      octacrypt decrypt doc.pdf.enc --alg hybrid --priv key_private.pem
    """
    input_path = Path(input_file)
    if not input_path.exists():
        raise click.ClickException(f"Archivo no encontrado: {input_path}")

    if alg == "hybrid":
        if not priv_key:
            raise click.ClickException("El modo hybrid requiere --priv <clave_privada.pem>")
        priv_path = Path(priv_key)
        if not priv_path.exists():
            raise click.ClickException(f"Clave privada no encontrada: {priv_path}")
        from octacrypt.algorithms.hybrid import HybridCipher
        output_path = Path(out) if out else (
            input_path.with_suffix("") if input_path.suffix == ".enc"
            else input_path.with_suffix(".dec")
        )
        try:
            cipher = HybridCipher(private_key_pem=priv_path.read_bytes())
            output_path.write_bytes(cipher.decrypt(input_path.read_bytes()))
            click.echo("Archivo descifrado correctamente")
            click.echo(f"   -> Entrada : {input_path}")
            click.echo(f"   -> Salida  : {output_path}")
            click.echo(f"   -> Clave   : {priv_path}")
        except Exception as e:
            raise click.ClickException(f"No se pudo descifrar: {e}")
    else:
        if not key:
            raise click.ClickException(f"El modo {alg} requiere --key <contrasena>")
        try:
            result = decrypt_file(
                input_path=input_path,
                output_path=Path(out) if out else None,
                key=key,
                algorithm=alg,
            )
            click.echo("Archivo descifrado correctamente")
            click.echo(f"   -> Entrada : {input_path}")
            click.echo(f"   -> Salida  : {result}")
        except Exception as e:
            raise click.ClickException(
                f"No se pudo descifrar. Verifica la contrasena y el algoritmo. ({type(e).__name__})"
            )
