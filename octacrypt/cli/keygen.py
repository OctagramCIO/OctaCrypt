# octacrypt/cli/keygen.py

import click
from octacrypt.utils.keygen import generate_rsa, generate_ed25519, save_keys


@click.command()
@click.option("--type", "key_type", type=click.Choice(["rsa", "ed25519"]), required=True, help="Tipo de clave")
@click.option("--bits", default=4096, type=int, help="Tamano de clave RSA (2048 o 4096, default: 4096)")
@click.option("--out", default="key", help="Nombre base del archivo de salida")
@click.option("--password", "password", default=None, help="Contrasena para cifrar la clave privada (recomendado)")
@click.option("--prompt-password", is_flag=True, default=False, help="Pedir contrasena de forma segura (oculta)")
def keygen(key_type, bits, out, password, prompt_password):
    """
    Genera un par de claves criptograficas.

    \b
    Tipos disponibles:
      rsa     -> RSA 4096 bits (cifrado hibrido)
      ed25519 -> Ed25519 (firmas digitales)

    \b
    Ejemplos:
      octacrypt keygen --type rsa --out mykey
      octacrypt keygen --type rsa --out mykey --prompt-password
      octacrypt keygen --type ed25519 --out signkey --password mysecret
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