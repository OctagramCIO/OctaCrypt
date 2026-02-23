import click
from octacrypt.utils.keygen import (
    generate_rsa,
    generate_ed25519,
    save_keys,
)


@click.command()
@click.option(
    "--type",
    "key_type",
    type=click.Choice(["rsa", "ed25519"]),
    required=True,
    help="Type of key to generate",
)
@click.option(
    "--bits",
    default=2048,
    type=click.Choice(["2048", "4096"]),
    help="RSA key size",
)
@click.option(
    "--out",
    default="key",
    help="Output file name (without extension)",
)
def keygen(key_type, bits, out):
    """
    Generate cryptographic keys
    """

    if key_type == "rsa":
        private_key = generate_rsa(int(bits))

    elif key_type == "ed25519":
        private_key = generate_ed25519()

    private_path, public_path = save_keys(private_key, out)

    click.echo(f"Private key saved to: {private_path}")
    click.echo(f"Public key saved to: {public_path}")