# octacrypt/cli/message.py

import click
from octacrypt.core.messenger import MessageCipher
from octacrypt.algorithms.signer import Ed25519Signer


@click.command("msg-encrypt")
@click.argument("message")
@click.option("--password", "-p", default=None, help="Cifrado simétrico con password")
@click.option("--pub", "pub_key", default=None, help="Cifrado híbrido con clave pública RSA")
@click.option("--pub-pq", "pub_pq_key", default=None, help="Cifrado post-cuántico con clave pública ML-KEM")
@click.option("--sign-priv", default=None, help="Clave privada Ed25519 para firmar (opcional)")
def msg_encrypt(message, password, pub_key, pub_pq_key, sign_priv):
    """
    Cifra un mensaje de texto.

    Modos:

    \b
      Simétrico (password):
        octacrypt msg-encrypt "secreto" --password mipassword

      Híbrido (RSA):
        octacrypt msg-encrypt "secreto" --pub key_public.pem

      Post-cuántico (ML-KEM):
        octacrypt msg-encrypt "secreto" --pub-pq pq_public.pem

      Con firma:
        octacrypt msg-encrypt "secreto" --password pw --sign-priv sign_private.pem
    """
    if not password and not pub_key and not pub_pq_key:
        raise click.ClickException("Debes usar --password, --pub o --pub-pq para cifrar.")

    signer = None
    if sign_priv:
        from pathlib import Path
        priv_path = Path(sign_priv)
        if not priv_path.exists():
            raise click.ClickException(f"Clave de firma no encontrada: {priv_path}")
        signer = Ed25519Signer(private_key_pem=priv_path.read_bytes())

    if password:
        encrypted = MessageCipher.encrypt_symmetric(message, password, signer=signer)
        mode = "AES-256-GCM + PBKDF2"
    elif pub_pq_key:
        from pathlib import Path
        pub_path = Path(pub_pq_key)
        if not pub_path.exists():
            raise click.ClickException(f"Clave pública no encontrada: {pub_path}")
        encrypted = MessageCipher.encrypt_pq(message, pub_path.read_bytes(), signer=signer)
        mode = "ML-KEM + AES-256-GCM (post-cuántico)"
    else:
        from pathlib import Path
        pub_path = Path(pub_key)
        if not pub_path.exists():
            raise click.ClickException(f"Clave pública no encontrada: {pub_path}")
        encrypted = MessageCipher.encrypt_hybrid(message, pub_path.read_bytes(), signer=signer)
        mode = "RSA-OAEP + AES-256-GCM"

    b64 = MessageCipher.to_base64(encrypted)

    click.echo(f"✅ Mensaje cifrado [{mode}]")
    if sign_priv:
        click.echo("   🔏 Firmado con Ed25519")
    click.echo(f"\n{b64}")


@click.command("msg-decrypt")
@click.argument("ciphertext")
@click.option("--password", "-p", default=None, help="Descifrado simétrico con password")
@click.option("--priv", "priv_key", default=None, help="Descifrado híbrido con clave privada RSA")
@click.option("--priv-pq", "priv_pq_key", default=None, help="Descifrado post-cuántico con clave privada ML-KEM")
@click.option("--priv-password", default=None, help="Password de la clave privada (RSA o ML-KEM), si está cifrada")
@click.option("--verify-pub", default=None, help="Clave pública Ed25519 para verificar firma (opcional)")
def msg_decrypt(ciphertext, password, priv_key, priv_pq_key, priv_password, verify_pub):
    """
    Descifra un mensaje cifrado con msg-encrypt.

    Ejemplos:

    \b
      octacrypt msg-decrypt "<base64>" --password mipassword
      octacrypt msg-decrypt "<base64>" --priv key_private.pem
      octacrypt msg-decrypt "<base64>" --priv-pq pq_private.pem
      octacrypt msg-decrypt "<base64>" --priv-pq pq_private.pem --priv-password secret
      octacrypt msg-decrypt "<base64>" --password pw --verify-pub sign_public.pem
    """
    if not password and not priv_key and not priv_pq_key:
        raise click.ClickException("Debes usar --password, --priv o --priv-pq para descifrar.")

    verifier = None
    if verify_pub:
        from pathlib import Path
        pub_path = Path(verify_pub)
        if not pub_path.exists():
            raise click.ClickException(f"Clave de verificación no encontrada: {pub_path}")
        verifier = Ed25519Signer(public_key_pem=pub_path.read_bytes())

    try:
        data = MessageCipher.from_base64(ciphertext)
    except Exception:
        raise click.ClickException("El ciphertext no es base64 válido.")

    private_password = priv_password.encode() if priv_password else None

    try:
        if password:
            plaintext = MessageCipher.decrypt_symmetric(data, password, verifier=verifier)
        elif priv_pq_key:
            from pathlib import Path
            priv_path = Path(priv_pq_key)
            if not priv_path.exists():
                raise click.ClickException(f"Clave privada no encontrada: {priv_path}")
            plaintext = MessageCipher.decrypt_pq(
                data,
                priv_path.read_bytes(),
                private_key_password=private_password,
                verifier=verifier,
            )
        else:
            from pathlib import Path
            priv_path = Path(priv_key)
            if not priv_path.exists():
                raise click.ClickException(f"Clave privada no encontrada: {priv_path}")
            plaintext = MessageCipher.decrypt_hybrid(
                data,
                priv_path.read_bytes(),
                private_key_password=private_password,
                verifier=verifier,
            )
    except ValueError as e:
        raise click.ClickException(str(e))

    click.echo("✅ Mensaje descifrado:")
    click.echo(f"\n{plaintext.decode()}")
