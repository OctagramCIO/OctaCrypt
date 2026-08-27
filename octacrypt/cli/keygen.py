# octacrypt/cli/keygen.py

import click
from octacrypt.utils.keygen import (
    generate_rsa,
    generate_ed25519,
    generate_mlkem,
    generate_mldsa,
    save_keys,
)


@click.command()
@click.option("--type", "key_type", type=click.Choice(["rsa", "ed25519", "mlkem", "mldsa"]), required=True, help="Tipo de clave")
@click.option("--bits", default=4096, type=int, help="Tamano de clave RSA (2048 o 4096, default: 4096)")
@click.option("--variant", default=None, help="Variante post-cuantica: mlkem768/mlkem1024 o mldsa44/mldsa65/mldsa87")
@click.option("--out", default="key", help="Nombre base del archivo de salida")
@click.option("--password", "password", default=None, help="Contrasena para cifrar la clave privada (recomendado)")
@click.option("--prompt-password", is_flag=True, default=False, help="Pedir contrasena de forma segura (oculta)")
def keygen(key_type, bits, out, password, prompt_password, variant):
    """
    Genera un par de claves criptograficas.

    \b
    Tipos disponibles:
      rsa     -> RSA 4096 bits (cifrado hibrido)
      ed25519 -> Ed25519 (firmas digitales)
      mlkem   -> ML-KEM post-cuantico (cifrado hibrido)  [--variant mlkem768|mlkem1024]
      mldsa   -> ML-DSA post-cuantico (firmas digitales) [--variant mldsa44|mldsa65|mldsa87]

    \b
    Ejemplos:
      octacrypt keygen --type rsa --out mykey
      octacrypt keygen --type rsa --out mykey --prompt-password
      octacrypt keygen --type ed25519 --out signkey --password mysecret
      octacrypt keygen --type mlkem --out pqkey --variant mlkem1024
      octacrypt keygen --type mldsa --out pqsign --variant mldsa65
    """

    # Obtener password
    if prompt_password:
        password = click.prompt(
            "Contrasena para la clave privada",
            hide_input=True,
            confirmation_prompt="Confirmar contrasena",
        )

    if key_type == "rsa":
        if bits not in (2048, 4096):
            raise click.BadParameter("RSA bits debe ser 2048 o 4096")
        private_key = generate_rsa(bits)
        click.echo(f"Generando clave RSA-{bits}...")
    elif key_type == "mlkem":
        variant = variant or "mlkem768"
        if variant not in ("mlkem768", "mlkem1024"):
            raise click.BadParameter("La variante ML-KEM debe ser mlkem768 o mlkem1024")
        private_key = generate_mlkem(variant)
        click.echo(f"Generando clave ML-KEM ({variant}, post-cuantica)...")
    elif key_type == "mldsa":
        variant = variant or "mldsa65"
        if variant not in ("mldsa44", "mldsa65", "mldsa87"):
            raise click.BadParameter("La variante ML-DSA debe ser mldsa44, mldsa65 o mldsa87")
        private_key = generate_mldsa(variant)
        click.echo(f"Generando clave ML-DSA ({variant}, post-cuantica)...")
    else:
        private_key = generate_ed25519()
        click.echo("Generando clave Ed25519...")

    private_path, public_path = save_keys(private_key, out, password=password)

    click.echo(f"Clave privada -> {private_path}" + (" [CIFRADA con password]" if password else " [SIN proteccion]"))
    click.echo(f"Clave publica  -> {public_path}")

    if not password:
        click.echo("")
        click.echo("ADVERTENCIA: La clave privada no tiene password.")
        click.echo("Usa --prompt-password para protegerla.")
