# octacrypt/cli/decrypt.py

from pathlib import Path

import click

from octacrypt.core.crypto import decrypt_file


def _read_algo_prefix(input_path: Path) -> str | None:
    """Lee el prefijo de algoritmo embebido en un archivo cifrado (10 bytes)."""
    with open(input_path, "rb") as f:
        prefix = f.read(10)
    if len(prefix) < 10:
        return None
    return prefix.rstrip(b"\x00").decode(errors="replace") or None


@click.command("decrypt")
@click.argument("input_file")
@click.option("--key", default=None, help="Contrasena de descifrado")
@click.option("--out", default=None, help="Archivo de salida (default: elimina .enc)")
@click.option(
    "--alg",
    default=None,
    type=click.Choice(["aes", "chacha20", "hybrid"]),
    help="Algoritmo usado al cifrar: hybrid requiere --priv; aes/chacha20 se detectan automaticamente",
)
@click.option("--priv", "priv_key", default=None, help="Clave privada RSA para modo hybrid")
@click.option("--password", default=None, help="Contrasena de la clave privada RSA (si esta cifrada)")
def decrypt(input_file, key, out, alg, priv_key, password):
    """
    Descifra un archivo cifrado con encrypt.

    El algoritmo simetrico (aes/chacha20) se detecta automaticamente desde
    el propio archivo. Usa --alg solo para validar o para el modo hybrid.

    \b
    Ejemplos:
      octacrypt decrypt doc.pdf.enc --key mipassword
      octacrypt decrypt doc.pdf.enc --key mipassword --alg chacha20
      octacrypt decrypt doc.pdf.enc --alg hybrid --priv key_private.pem --password mipassword
    """
    input_path = Path(input_file)
    if not input_path.exists():
        raise click.ClickException(f"Archivo no encontrado: {input_path}")

    output_path = Path(out) if out else (
        input_path.with_suffix("") if input_path.suffix == ".enc"
        else input_path.with_suffix(".dec")
    )
    if output_path.resolve() == input_path.resolve():
        raise click.ClickException(
            "La ruta de salida coincide con la de entrada; especifica --out."
        )

    if alg == "hybrid":
        if not priv_key:
            raise click.ClickException("El modo hybrid requiere --priv <clave_privada.pem>")
        priv_path = Path(priv_key)
        if not priv_path.exists():
            raise click.ClickException(f"Clave privada no encontrada: {priv_path}")
        from octacrypt.algorithms.hybrid import HybridCipher
        try:
            cipher = HybridCipher(
                private_key_pem=priv_path.read_bytes(),
                private_key_password=password.encode() if password else None,
            )
            output_path.write_bytes(cipher.decrypt(input_path.read_bytes()))
            click.echo("Archivo descifrado correctamente")
            click.echo(f"   -> Entrada : {input_path}")
            click.echo(f"   -> Salida  : {output_path}")
            click.echo(f"   -> Clave   : {priv_path}")
        except Exception as e:
            raise click.ClickException(f"No se pudo descifrar: {e}")
    else:
        if not key:
            raise click.ClickException(f"El modo {alg or 'aes'} requiere --key <contrasena>")

        embedded_alg = _read_algo_prefix(input_path)
        if alg and embedded_alg and alg != embedded_alg:
            raise click.ClickException(
                f"El archivo fue cifrado con '{embedded_alg}', no con '{alg}'. "
                f"Usa --alg {embedded_alg} o elimina --alg."
            )

        try:
            result = decrypt_file(
                input_path=input_path,
                output_path=output_path,
                key=key,
            )
            click.echo("Archivo descifrado correctamente")
            click.echo(f"   -> Entrada : {input_path}")
            click.echo(f"   -> Salida  : {result}")
        except Exception as e:
            raise click.ClickException(
                f"No se pudo descifrar. Verifica la contrasena y el algoritmo. ({type(e).__name__})"
            )
