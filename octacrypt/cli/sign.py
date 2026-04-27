# octacrypt/cli/sign.py

import click
from pathlib import Path

from octacrypt.algorithms.signer import Ed25519Signer


@click.command("sign")
@click.argument("target")
@click.option("--priv", "priv_key", required=True, help="Clave privada Ed25519 (.pem)")
@click.option("--out", default=None, help="Archivo de salida para la firma (.sig)")
@click.option("--message", "-m", is_flag=True, help="Firmar texto directo en vez de archivo")
def sign(target, priv_key, out, message):
    """
    Firma un archivo o mensaje con Ed25519.

    Ejemplos:

    \b
      octacrypt sign documento.pdf --priv key_private.pem
      octacrypt sign "hola mundo" --priv key_private.pem --message
    """
    priv_path = Path(priv_key)
    if not priv_path.exists():
        raise click.ClickException(f"Clave privada no encontrada: {priv_path}")

    priv_pem = priv_path.read_bytes()
    signer = Ed25519Signer(private_key_pem=priv_pem)

    if message:
        data = target.encode()
    else:
        target_path = Path(target)
        if not target_path.exists():
            raise click.ClickException(f"Archivo no encontrado: {target_path}")
        data = target_path.read_bytes()

    signature = signer.sign(data)

    if message:
        click.echo(f"✅ Firma (hex): {signature.hex()}")
    else:
        target_path = Path(target)
        output_path = Path(out) if out else target_path.with_suffix(target_path.suffix + ".sig")
        output_path.write_bytes(signature)
        click.echo(f"✅ Archivo firmado con Ed25519")
        click.echo(f"   → Archivo : {target_path}")
        click.echo(f"   → Firma   : {output_path}")
        click.echo(f"   → Clave   : {priv_path}")


@click.command("verify")
@click.argument("target")
@click.option("--pub", "pub_key", required=True, help="Clave pública Ed25519 (.pem)")
@click.option("--sig", "sig_file", default=None, help="Archivo de firma (.sig)")
@click.option("--signature", default=None, help="Firma en hex (para mensajes)")
@click.option("--message", "-m", is_flag=True, help="Verificar texto directo en vez de archivo")
def verify(target, pub_key, sig_file, signature, message):
    """
    Verifica la firma Ed25519 de un archivo o mensaje.

    Ejemplos:

    \b
      octacrypt verify documento.pdf --pub key_public.pem --sig documento.pdf.sig
      octacrypt verify "hola mundo" --pub key_public.pem --signature <hex> --message
    """
    pub_path = Path(pub_key)
    if not pub_path.exists():
        raise click.ClickException(f"Clave pública no encontrada: {pub_path}")

    pub_pem = pub_path.read_bytes()
    verifier = Ed25519Signer(public_key_pem=pub_pem)

    if message:
        data = target.encode()
        if not signature:
            raise click.ClickException("Usa --signature <hex> para verificar mensajes.")
        sig_bytes = bytes.fromhex(signature)
    else:
        target_path = Path(target)
        if not target_path.exists():
            raise click.ClickException(f"Archivo no encontrado: {target_path}")
        data = target_path.read_bytes()

        sig_path = Path(sig_file) if sig_file else target_path.with_suffix(target_path.suffix + ".sig")
        if not sig_path.exists():
            raise click.ClickException(f"Archivo de firma no encontrado: {sig_path}")
        sig_bytes = sig_path.read_bytes()

    valid = verifier.verify(data, sig_bytes)

    if valid:
        click.echo("✅ Firma válida — el contenido no ha sido alterado.")
    else:
        click.echo("❌ Firma INVÁLIDA — el contenido puede haber sido manipulado.")
        raise SystemExit(1)