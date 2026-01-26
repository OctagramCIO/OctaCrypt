import click

from octacrypt.core.crypto_engine import CryptoEngine
from octacrypt.utils.keygen import generate_symmetric_key

@click.command()
@click.argument("input_file")
@click.argument("output_file")
def encrypt(input_file, output_file):
    key = generate_symmetric_key()
    engine = CryptoEngine("aes", key)

    with open(input_file, "rb") as f:
        data = f.read()

    encrypted = engine.encrypt(data)

    with open(output_file, "wb") as f:
        f.write(encrypted)

    click.echo("✅ File encrypted with AES-GCM")

