import click

from .encrypt import encrypt
from .decrypt import decrypt
from .hash import hash
from .keygen import keygen
from .hybrid import hybrid_encrypt, hybrid_decrypt

@click.group()
def cli():
    """OctaCrypt CLI"""
    pass

cli.add_command(encrypt)
cli.add_command(decrypt)
cli.add_command(hash)
cli.add_command(keygen)
cli.add_command(hybrid_encrypt)
cli.add_command(hybrid_decrypt)
