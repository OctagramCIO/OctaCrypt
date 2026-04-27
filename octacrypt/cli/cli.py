# octacrypt/cli/cli.py

import click

from .encrypt import encrypt
from .decrypt import decrypt
from .hash import hash
from .keygen import keygen
from .hybrid import hybrid_encrypt, hybrid_decrypt
from .sign import sign, verify
from .message import msg_encrypt, msg_decrypt


@click.group()
@click.version_option("0.2.0", prog_name="OctaCrypt")
def cli():
    """
    \b
    ╔═══════════════════════════════════════╗
    ║          🔐  O C T A C R Y P T       ║
    ║   Cifrado de grado máximo por        ║
    ║   Octagram — security through        ║
    ║   transparency.                      ║
    ╚═══════════════════════════════════════╝

    \b
    Comandos disponibles:
      encrypt / decrypt     → Cifrado de archivos (AES-256-GCM)
      hybrid-encrypt / hybrid-decrypt → Cifrado híbrido RSA + AES
      msg-encrypt / msg-decrypt       → Cifrado de mensajes
      sign / verify         → Firmas digitales Ed25519
      keygen                → Generación de claves
      hash                  → Hashing (SHA256, SHA512, bcrypt, scrypt)
    """
    pass


cli.add_command(encrypt)
cli.add_command(decrypt)
cli.add_command(hash)
cli.add_command(keygen)
cli.add_command(hybrid_encrypt)
cli.add_command(hybrid_decrypt)
cli.add_command(sign)
cli.add_command(verify)
cli.add_command(msg_encrypt)
cli.add_command(msg_decrypt)