# octacrypt/cli/pq.py
#
# Comandos CLI post-cuánticos (ML-KEM / ML-DSA):
#   octacrypt pq-encrypt <file> --pub pq_public.pem [--out output]
#   octacrypt pq-decrypt <file> --priv pq_private.pem [--out output] [--password ...]
#   octacrypt pq-sign <file> --priv pqsign_private.pem [--out output]
#   octacrypt pq-verify <file> --pub pqsign_public.pem --sig file.pq.sig

import click
from pathlib import Path

from octacrypt.algorithms.mlkem import MLKEMCipher
from octacrypt.algorithms.mldsa import MLDSASigner


@click.command("pq-encrypt")
@click.argument("input_file")
@click.option("--pub", "pub_key", required=True, help="Ruta a la clave publica ML-KEM (.pem)")
@click.option("--out", default=None, help="Archivo de salida (default: input.pqenc)")
def pq_encrypt(input_file, pub_key, out):
    """
    Cifra un archivo con cifrado hibrido post-cuantico ML-KEM + AES-256-GCM.

    Usa la clave publica ML-KEM (FIPS 203) para encapsular la session key AES.
    """
    input_path = Path(input_file)
    pub_path = Path(pub_key)

    if not input_path.exists():
        raise click.ClickException(f"Archivo no encontrado: {input_path}")

    if not pub_path.exists():
        raise click.ClickException(f"Clave publica no encontrada: {pub_path}")

    output_path = Path(out) if out else input_path.with_suffix(input_path.suffix + ".pqenc")

    pub_pem = pub_path.read_bytes()
    data = input_path.read_bytes()

    cipher = MLKEMCipher(public_key_pem=pub_pem)
    encrypted = cipher.encrypt(data)

    output_path.write_bytes(encrypted)

    click.echo("✅ Archivo cifrado con ML-KEM + AES-256-GCM (post-cuantico)")
    click.echo(f"   → Entrada : {input_path}")
    click.echo(f"   → Salida  : {output_path}")
    click.echo(f"   → Clave   : {pub_path}")


@click.command("pq-decrypt")
@click.argument("input_file")
@click.option("--priv", "priv_key", required=True, help="Ruta a la clave privada ML-KEM (.pem)")
@click.option("--out", default=None, help="Archivo de salida (default: sin extension .pqenc)")
@click.option("--password", default=None, help="Contrasena de la clave privada (si aplica)")
def pq_decrypt(input_file, priv_key, out, password):
    """
    Descifra un archivo cifrado con pq-encrypt.

    Usa la clave privada ML-KEM para desencapsular la session key AES.
    """
    input_path = Path(input_file)
    priv_path = Path(priv_key)

    if not input_path.exists():
        raise click.ClickException(f"Archivo no encontrado: {input_path}")

    if not priv_path.exists():
        raise click.ClickException(f"Clave privada no encontrada: {priv_path}")

    if out:
        output_path = Path(out)
    elif input_path.suffix == ".pqenc":
        output_path = input_path.with_suffix("")
    else:
        output_path = input_path.with_suffix(".dec")

    priv_pem = priv_path.read_bytes()
    password_bytes = password.encode() if password else None
    data = input_path.read_bytes()

    cipher = MLKEMCipher(
        private_key_pem=priv_pem,
        private_key_password=password_bytes,
    )
    decrypted = cipher.decrypt(data)

    output_path.write_bytes(decrypted)

    click.echo("✅ Archivo descifrado correctamente (ML-KEM post-cuantico)")
    click.echo(f"   → Entrada : {input_path}")
    click.echo(f"   → Salida  : {output_path}")
    click.echo(f"   → Clave   : {priv_path}")


@click.command("pq-sign")
@click.argument("target")
@click.option("--priv", "priv_key", required=True, help="Clave privada ML-DSA (.pem)")
@click.option("--out", default=None, help="Archivo de salida para la firma (.pqsig)")
@click.option("--message", "-m", is_flag=True, help="Firmar texto directo en vez de archivo")
@click.option("--password", default=None, help="Contrasena de la clave privada (si aplica)")
def pq_sign(target, priv_key, out, message, password):
    """
    Firma un archivo o mensaje con ML-DSA (post-cuantico).

    Ejemplos:

    \b
      octacrypt pq-sign documento.pdf --priv pqsign_private.pem
      octacrypt pq-sign "hola mundo" --priv pqsign_private.pem --message
    """
    priv_path = Path(priv_key)
    if not priv_path.exists():
        raise click.ClickException(f"Clave privada no encontrada: {priv_path}")

    priv_pem = priv_path.read_bytes()
    password_bytes = password.encode() if password else None
    signer = MLDSASigner(
        private_key_pem=priv_pem,
        private_key_password=password_bytes,
    )

    if message:
        data = target.encode()
    else:
        target_path = Path(target)
        if not target_path.exists():
            raise click.ClickException(f"Archivo no encontrado: {target_path}")
        data = target_path.read_bytes()

    signature = signer.sign(data)

    if message:
        click.echo(f"✅ Firma ML-DSA (hex): {signature.hex()}")
    else:
        target_path = Path(target)
        output_path = Path(out) if out else target_path.with_suffix(target_path.suffix + ".pqsig")
        output_path.write_bytes(signature)
        click.echo("✅ Archivo firmado con ML-DSA (post-cuantico)")
        click.echo(f"   → Archivo : {target_path}")
        click.echo(f"   → Firma   : {output_path}")
        click.echo(f"   → Clave   : {priv_path}")


@click.command("pq-verify")
@click.argument("target")
@click.option("--pub", "pub_key", required=True, help="Clave publica ML-DSA (.pem)")
@click.option("--sig", "sig_file", default=None, help="Archivo de firma (.pqsig)")
@click.option("--signature", default=None, help="Firma en hex (para mensajes)")
@click.option("--message", "-m", is_flag=True, help="Verificar texto directo en vez de archivo")
def pq_verify(target, pub_key, sig_file, signature, message):
    """
    Verifica una firma ML-DSA (post-cuantica).

    Ejemplos:

    \b
      octacrypt pq-verify documento.pdf --pub pqsign_public.pem --sig documento.pdf.pqsig
      octacrypt pq-verify "hola mundo" --pub pqsign_public.pem --signature <hex> --message
    """
    pub_path = Path(pub_key)
    if not pub_path.exists():
        raise click.ClickException(f"Clave publica no encontrada: {pub_path}")

    pub_pem = pub_path.read_bytes()
    verifier = MLDSASigner(public_key_pem=pub_pem)

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

        sig_path = Path(sig_file) if sig_file else target_path.with_suffix(target_path.suffix + ".pqsig")
        if not sig_path.exists():
            raise click.ClickException(f"Archivo de firma no encontrado: {sig_path}")
        sig_bytes = sig_path.read_bytes()

    valid = verifier.verify(data, sig_bytes)

    if valid:
        click.echo("✅ Firma ML-DSA valida — el contenido no ha sido alterado.")
    else:
        click.echo("❌ Firma INVALIDA — el contenido puede haber sido manipulado.")
        raise SystemExit(1)
