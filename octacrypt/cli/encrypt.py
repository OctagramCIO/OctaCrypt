from octacrypt.core.crypto_engine import CryptoEngine
from octacrypt.core.key_manager import generate_key
from octacrypt.utils.keygen import generate_symmetric_key

import click

@click.command()
def encrypt():
    key = generate_key()
    engine = CryptoEngine("xor", key)
    click.echo("Encrypt command working")
