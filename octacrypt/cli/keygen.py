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
    type=int,
    help="RSA key size (2048 or 4096)",
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
        if bits not in (2048, 4096):
            raise click.BadParameter("RSA bits must be 2048 or 4096")

        private_key = generate_rsa(bits)

    elif key_type == "ed25519":
        private_key = generate_ed25519()

    private_path, public_path = save_keys(private_key, out)

    click.echo(f"✔ Private key saved to: {private_path}")
    click.echo(f"✔ Public key saved to: {public_path}")