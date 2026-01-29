# octacrypt/cli/hash.py

import click
from pathlib import Path
from octacrypt.utils.hash import hash_sha, hash_bcrypt


@click.command()
@click.argument("target")
@click.option("--alg", type=click.Choice(["sha256", "sha512", "bcrypt"]), default="sha256")
@click.option("--string", is_flag=True, help="Hash a raw string instead of a file")
def hash(target, alg, string):
    """
    Hash a file or string
    """

    if string:
        data = target.encode()
    else:
        path = Path(target)
        if not path.exists():
            raise click.ClickException("File not found")
        data = path.read_bytes()

    if alg in ("sha256", "sha512"):
        result = hash_sha(data, alg)
    elif alg == "bcrypt":
        result = hash_bcrypt(target)
    else:
        raise click.ClickException("Unsupported algorithm")

    click.echo(result)
