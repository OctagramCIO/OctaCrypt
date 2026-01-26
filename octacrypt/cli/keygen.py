import click
from octacrypt.utils.keygen import generate_symmetric_key

@click.command()
@click.option("--length", default=32, show_default=True, help="Key length in bytes")
def keygen(length):
    key = generate_symmetric_key(length)
    click.echo(key.hex())
