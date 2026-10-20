from pathlib import Path

import click

from octacrypt.utils.hash import (
    bcrypt_hash,
    bcrypt_verify,
    scrypt_hash,
    scrypt_verify,
    sha256,
    sha512,
)


@click.command()
@click.argument("target")
@click.option("--sha256", "alg", flag_value="sha256", help="SHA-256 hash")
@click.option("--sha512", "alg", flag_value="sha512", help="SHA-512 hash")
@click.option("--bcrypt", is_flag=True, help="bcrypt hash")
@click.option("--scrypt", is_flag=True, help="scrypt hash")
@click.option("--verify", help="Verify hash (bcrypt/scrypt only)")
def hash(target, alg, bcrypt, scrypt, verify):
    """
    Hash a file or string
    """

    # file or string
    path = Path(target)
    if path.exists():
        data = path.read_bytes()
    else:
        data = target.encode()

    if verify and not (bcrypt or scrypt):
        raise click.UsageError("--verify solo aplica con --bcrypt o --scrypt.")

    if alg == "sha256":
        click.echo(sha256(data))
        return

    if alg == "sha512":
        click.echo(sha512(data))
        return

    if bcrypt:
        if verify:
            click.echo(bcrypt_verify(data, verify))
        else:
            click.echo(bcrypt_hash(data))
        return

    if scrypt:
        if verify:
            click.echo(scrypt_verify(data, verify))
        else:
            click.echo(scrypt_hash(data))
        return

    raise click.UsageError("Select a hash algorithm")
