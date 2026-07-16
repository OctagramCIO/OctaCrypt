# octacrypt/cli/encrypt_dir.py

import click
from pathlib import Path
from octacrypt.core.dir_crypto import encrypt_directory, decrypt_directory, get_directory_info


def _fmt(n: int) -> str:
    if n < 1024: return f"{n} B"
    elif n < 1024**2: return f"{n/1024:.1f} KB"
    elif n < 1024**3: return f"{n/1024**2:.1f} MB"
    else: return f"{n/1024**3:.2f} GB"


@click.command("encrypt-dir")
@click.argument("input_dir")
@click.option("--key", required=True, help="Contrasena de cifrado")
@click.option("--out", default=None, help="Directorio de salida (default: input.enc)")
@click.option("--alg", default="aes", type=click.Choice(["aes", "chacha20"]), help="Algoritmo")
def encrypt_dir(input_dir, key, out, alg):
    """
    Cifra un directorio completo preservando su estructura.

    \b
    Ejemplos:
      octacrypt encrypt-dir documentos/ --key mipassword
      octacrypt encrypt-dir documentos/ --alg chacha20 --key mipassword
    """
    input_path = Path(input_dir)
    if not input_path.exists():
        raise click.ClickException(f"Directorio no encontrado: {input_path}")
    if not input_path.is_dir():
        raise click.ClickException(f"No es un directorio: {input_path}")

    label = "AES-256-GCM" if alg == "aes" else "ChaCha20-Poly1305"
    click.echo(f"Cifrando con {label}...")
    try:
        result, files, total = encrypt_directory(input_path, Path(out) if out else None, key=key, algorithm=alg)
        click.echo(f"Directorio cifrado correctamente")
        click.echo(f"   -> Entrada  : {input_path}")
        click.echo(f"   -> Salida   : {result}")
        click.echo(f"   -> Archivos : {files}")
        click.echo(f"   -> Tamano   : {_fmt(total)}")
    except Exception as e:
        raise click.ClickException(str(e))


@click.command("decrypt-dir")
@click.argument("input_dir")
@click.option("--key", required=True, help="Contrasena de descifrado")
@click.option("--out", default=None, help="Directorio de salida")
def decrypt_dir(input_dir, key, out):
    """
    Descifra un directorio cifrado con encrypt-dir.

    \b
    Ejemplo:
      octacrypt decrypt-dir documentos.enc/ --key mipassword
    """
    input_path = Path(input_dir)
    if not input_path.exists():
        raise click.ClickException(f"Directorio no encontrado: {input_path}")
    if not input_path.is_dir():
        raise click.ClickException(f"No es un directorio: {input_path}")

    click.echo("Descifrando directorio...")
    try:
        result, files, total = decrypt_directory(input_path, Path(out) if out else None, key=key)
        click.echo(f"Directorio descifrado correctamente")
        click.echo(f"   -> Entrada  : {input_path}")
        click.echo(f"   -> Salida   : {result}")
        click.echo(f"   -> Archivos : {files}")
        click.echo(f"   -> Tamano   : {_fmt(total)}")
    except FileNotFoundError as e:
        raise click.ClickException(str(e))
    except Exception:
        raise click.ClickException("No se pudo descifrar. Verifica la contrasena.")


@click.command("dir-info")
@click.argument("input_dir")
def dir_info(input_dir):
    """
    Muestra informacion de un directorio cifrado.

    \b
    Ejemplo:
      octacrypt dir-info documentos.enc/
    """
    try:
        info = get_directory_info(Path(input_dir))
        click.echo(f"Directorio OctaCrypt")
        click.echo(f"   -> Original  : {info['original_dir']}")
        click.echo(f"   -> Algoritmo : {info['algorithm'].upper()}")
        click.echo(f"   -> Archivos  : {info['total_files']}")
        click.echo(f"   -> Tamano    : {_fmt(info['total_bytes'])}")
        click.echo(f"   -> Creado    : {info['created_at']}")
        click.echo(f"\nArchivos:")
        for entry in info["files"]:
            click.echo(f"   {entry['original']}  ({_fmt(entry['size'])})")
    except FileNotFoundError as e:
        raise click.ClickException(str(e))
