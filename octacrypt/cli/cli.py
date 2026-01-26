import click

from .encrypt import encrypt
from .decrypt import decrypt
from .hash import hash
from ..utils.keygen import generate_symmetric_key

@click.group()
def cli():
    """OctaCrypt CLI"""
    pass

cli.add_command(encrypt)
cli.add_command(decrypt)
cli.add_command(hash)
cli.add_command(generate_symmetric_key)
