# octacrypt/tui/tui.py

import sys
from pathlib import Path

import questionary
from questionary import Style
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.text import Text

console = Console()

STYLE = Style([
    ("qmark",        "fg:#00ff99 bold"),
    ("question",     "fg:#ffffff bold"),
    ("answer",       "fg:#00ff99 bold"),
    ("pointer",      "fg:#00ff99 bold"),
    ("highlighted",  "fg:#00ff99 bold"),
    ("selected",     "fg:#00ff99"),
    ("separator",    "fg:#444444"),
    ("instruction",  "fg:#888888"),
])


def show_banner():
    console.clear()
    banner = Text()
    banner.append("\n")
    banner.append("  ██████╗  ██████╗████████╗ █████╗  ██████╗██████╗██╗   ██╗██████╗ ████████╗\n", style="bold green")
    banner.append(" ██╔═══██╗██╔════╝╚══██╔══╝██╔══██╗██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝\n", style="bold green")
    banner.append(" ██║   ██║██║        ██║   ███████║██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   \n", style="bold green")
    banner.append(" ██║   ██║██║        ██║   ██╔══██║██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   \n", style="bold green")
    banner.append(" ╚██████╔╝╚██████╗   ██║   ██║  ██║╚██████╗██║  ██║   ██║   ██║        ██║   \n", style="bold green")
    banner.append("  ╚═════╝  ╚═════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝\n", style="bold green")
    banner.append("\n")
    banner.append("         Maximum-grade encryption by Octagram\n", style="dim green")
    banner.append("         security through transparency\n\n", style="dim green")
    console.print(banner)


def success(msg):
    console.print(f"\n[bold green]OK[/bold green] {msg}")

def error(msg):
    console.print(f"\n[bold red]ERROR[/bold red] {msg}")

def info(msg):
    console.print(f"\n[bold cyan]->[/bold cyan] {msg}")

def pause():
    console.print()
    questionary.press_any_key_to_continue("  Presiona cualquier tecla para continuar...").ask()

def ask_file(prompt):
    path_str = questionary.path(prompt, style=STYLE).ask()
    if not path_str:
        return None
    path = Path(path_str)
    if not path.exists():
        error(f"Archivo no encontrado: {path}")
        return None
    return path

def ask_password(prompt="Contrasena"):
    return questionary.password(prompt, style=STYLE).ask()


def menu_file_encrypt():
    console.print(Panel("[bold green]Cifrar Archivo[/bold green]", box=box.ROUNDED))
    input_file = ask_file("Archivo a cifrar:")
    if not input_file:
        return

    alg = questionary.select("Algoritmo:", choices=[
        "AES-256-GCM (recomendado)",
        "ChaCha20-Poly1305 (mas rapido en moviles)",
        "Hibrido RSA + AES (para un destinatario)",
    ], style=STYLE).ask()
    if alg is None:
        return

    if "Hibrido" in alg:
        pub_key = ask_file("Clave publica RSA (.pem):")
        if not pub_key:
            return
        from octacrypt.algorithms.hybrid import HybridCipher
        output_path = input_file.with_suffix(input_file.suffix + ".enc")
        try:
            cipher = HybridCipher(public_key_pem=pub_key.read_bytes())
            output_path.write_bytes(cipher.encrypt(input_file.read_bytes()))
            success(f"Archivo cifrado con RSA + AES-256-GCM")
            info(f"Salida: {output_path}")
        except Exception as e:
            error(f"{e}")
    else:
        algorithm = "aes" if "AES" in alg else "chacha20"
        password = ask_password()
        if not password:
            return
        from octacrypt.core.crypto import encrypt_file
        try:
            result = encrypt_file(input_file, None, key=password, algorithm=algorithm)
            label = "AES-256-GCM" if algorithm == "aes" else "ChaCha20-Poly1305"
            success(f"Archivo cifrado con {label} + PBKDF2")
            info(f"Salida: {result}")
        except Exception as e:
            error(f"{e}")
    pause()


def menu_file_decrypt():
    console.print(Panel("[bold green]Descifrar Archivo[/bold green]", box=box.ROUNDED))
    input_file = ask_file("Archivo cifrado (.enc):")
    if not input_file:
        return

    mode = questionary.select("Modo:", choices=[
        "Simetrico (password)",
        "Hibrido RSA (clave privada)",
    ], style=STYLE).ask()
    if mode is None:
        return

    if "Hibrido" in mode:
        priv_key = ask_file("Clave privada RSA (.pem):")
        if not priv_key:
            return
        pw = ask_password("Contrasena de la clave privada (Enter si no tiene):")
        output_path = input_file.with_suffix("") if input_file.suffix == ".enc" else input_file.with_suffix(".dec")
        from octacrypt.algorithms.hybrid import HybridCipher
        try:
            pw_bytes = pw.encode() if pw else None
            cipher = HybridCipher(private_key_pem=priv_key.read_bytes(), private_key_password=pw_bytes)
            output_path.write_bytes(cipher.decrypt(input_file.read_bytes()))
            success("Archivo descifrado correctamente")
            info(f"Salida: {output_path}")
        except Exception as e:
            error(f"{e}")
    else:
        password = ask_password()
        if not password:
            return
        from octacrypt.core.crypto import decrypt_file
        try:
            result = decrypt_file(input_file, None, key=password)
            success("Archivo descifrado correctamente")
            info(f"Salida: {result}")
        except Exception:
            error("No se pudo descifrar. Verifica la contrasena.")
    pause()


def menu_message():
    console.print(Panel("[bold green]Cifrar / Descifrar Mensaje[/bold green]", box=box.ROUNDED))
    action = questionary.select("Accion:", choices=["Cifrar mensaje", "Descifrar mensaje"], style=STYLE).ask()
    if action is None:
        return

    from octacrypt.core.messenger import MessageCipher

    if "Cifrar" in action:
        message = questionary.text("Mensaje a cifrar:", style=STYLE).ask()
        if not message:
            return
        mode = questionary.select("Modo:", choices=["Simetrico (password)", "Hibrido RSA (clave publica)"], style=STYLE).ask()
        if mode is None:
            return
        try:
            if "Hibrido" in mode:
                pub_key = ask_file("Clave publica RSA (.pem):")
                if not pub_key:
                    return
                encrypted = MessageCipher.encrypt_hybrid(message, pub_key.read_bytes())
            else:
                alg_choice = questionary.select("Algoritmo:", choices=["AES-256-GCM", "ChaCha20-Poly1305"], style=STYLE).ask()
                algorithm = "aes" if "AES" in alg_choice else "chacha20"
                password = ask_password()
                if not password:
                    return
                encrypted = MessageCipher.encrypt_symmetric(message, password, algorithm=algorithm)
            b64 = MessageCipher.to_base64(encrypted)
            success("Mensaje cifrado:")
            console.print(Panel(b64, title="[green]Ciphertext (base64)[/green]", box=box.ROUNDED))
        except Exception as e:
            error(f"{e}")
    else:
        ciphertext = questionary.text("Pega el ciphertext (base64):", style=STYLE).ask()
        if not ciphertext:
            return
        mode = questionary.select("Modo:", choices=["Simetrico (password)", "Hibrido RSA (clave privada)"], style=STYLE).ask()
        if mode is None:
            return
        try:
            data = MessageCipher.from_base64(ciphertext)
            if "Hibrido" in mode:
                priv_key = ask_file("Clave privada RSA (.pem):")
                if not priv_key:
                    return
                pw = ask_password("Contrasena de la clave privada (Enter si no tiene):")
                pw_bytes = pw.encode() if pw else None
                plaintext = MessageCipher.decrypt_hybrid(data, priv_key.read_bytes(), private_key_password=pw_bytes)
            else:
                password = ask_password()
                if not password:
                    return
                plaintext = MessageCipher.decrypt_symmetric(data, password)
            success("Mensaje descifrado:")
            console.print(Panel(plaintext.decode(), title="[green]Plaintext[/green]", box=box.ROUNDED))
        except Exception as e:
            error(f"{e}")
    pause()


def menu_sign():
    console.print(Panel("[bold green]Firmas Digitales Ed25519[/bold green]", box=box.ROUNDED))
    action = questionary.select("Accion:", choices=["Firmar archivo", "Verificar firma"], style=STYLE).ask()
    if action is None:
        return

    from octacrypt.algorithms.signer import Ed25519Signer

    if "Firmar" in action:
        target = ask_file("Archivo a firmar:")
        if not target:
            return
        priv_key = ask_file("Clave privada Ed25519 (.pem):")
        if not priv_key:
            return
        pw = ask_password("Contrasena de la clave privada (Enter si no tiene):")
        try:
            pw_bytes = pw.encode() if pw else None
            signer = Ed25519Signer(private_key_pem=priv_key.read_bytes(), private_key_password=pw_bytes)
            sig_path = target.with_suffix(target.suffix + ".sig")
            sig_path.write_bytes(signer.sign(target.read_bytes()))
            success("Archivo firmado con Ed25519")
            info(f"Firma guardada en: {sig_path}")
        except Exception as e:
            error(f"{e}")
    else:
        target = ask_file("Archivo a verificar:")
        if not target:
            return
        sig_file = ask_file("Archivo de firma (.sig):")
        if not sig_file:
            return
        pub_key = ask_file("Clave publica Ed25519 (.pem):")
        if not pub_key:
            return
        try:
            verifier = Ed25519Signer(public_key_pem=pub_key.read_bytes())
            valid = verifier.verify(target.read_bytes(), sig_file.read_bytes())
            if valid:
                success("Firma VALIDA — contenido integro.")
            else:
                error("Firma INVALIDA — contenido puede haber sido manipulado.")
        except Exception as e:
            error(f"{e}")
    pause()


def menu_keygen():
    console.print(Panel("[bold green]Generar Claves[/bold green]", box=box.ROUNDED))
    key_type = questionary.select("Tipo de clave:", choices=[
        "RSA-4096 (para cifrado hibrido)",
        "Ed25519 (para firmas digitales)",
    ], style=STYLE).ask()
    if key_type is None:
        return

    name = questionary.text("Nombre base del archivo:", default="key", style=STYLE).ask()
    if not name:
        return

    protect = questionary.confirm("Proteger la clave privada con password?", default=True, style=STYLE).ask()
    password = None
    if protect:
        password = questionary.password("Contrasena:", style=STYLE).ask()
        confirm = questionary.password("Confirmar contrasena:", style=STYLE).ask()
        if password != confirm:
            error("Las contrasenas no coinciden.")
            pause()
            return

    from octacrypt.utils.keygen import generate_rsa, generate_ed25519, save_keys
    try:
        if "RSA" in key_type:
            info("Generando RSA-4096... (puede tomar unos segundos)")
            private_key = generate_rsa(4096)
        else:
            private_key = generate_ed25519()

        priv_path, pub_path = save_keys(private_key, name, password=password)
        success("Par de claves generado")
        info(f"Privada: {priv_path}" + (" [CIFRADA]" if password else " [SIN proteccion]"))
        info(f"Publica: {pub_path}")
        if not password:
            console.print("\n[bold yellow]ADVERTENCIA:[/bold yellow] Se recomienda proteger la clave privada con password.")
    except Exception as e:
        error(f"{e}")
    pause()


def menu_hash():
    console.print(Panel("[bold green]Hashing[/bold green]", box=box.ROUNDED))
    target = questionary.text("Texto o ruta de archivo:", style=STYLE).ask()
    if not target:
        return

    alg = questionary.select("Algoritmo:", choices=["SHA-256", "SHA-512", "bcrypt", "scrypt"], style=STYLE).ask()
    if alg is None:
        return

    from octacrypt.utils.hash import sha256, sha512, bcrypt_hash, scrypt_hash
    path = Path(target)
    data = path.read_bytes() if path.exists() else target.encode()

    try:
        if alg == "SHA-256":
            result = sha256(data)
        elif alg == "SHA-512":
            result = sha512(data)
        elif alg == "bcrypt":
            result = bcrypt_hash(target)
        else:
            result = scrypt_hash(target)
        success(f"Hash [{alg}]:")
        console.print(Panel(result, box=box.ROUNDED))
    except Exception as e:
        error(f"{e}")
    pause()


def show_about():
    table = Table(box=box.ROUNDED, show_header=False, padding=(0, 2))
    table.add_column("Campo", style="bold green")
    table.add_column("Valor", style="white")
    table.add_row("Version",           "0.2.0")
    table.add_row("Proyecto",          "OctaCrypt")
    table.add_row("Autor",             "Octagram")
    table.add_row("Licencia",          "MIT")
    table.add_row("Repo",              "github.com/OctagramCIO/OctaCrypt")
    table.add_row("", "")
    table.add_row("AES-256-GCM",       "[green]activo[/green]")
    table.add_row("ChaCha20-Poly1305", "[green]activo[/green]")
    table.add_row("RSA-OAEP + AES",    "[green]activo[/green]")
    table.add_row("Ed25519",           "[green]activo[/green]")
    table.add_row("PBKDF2 (200k it.)", "[green]activo[/green]")
    table.add_row("bcrypt / scrypt",   "[green]activo[/green]")
    console.print(Panel(table, title="[bold green]Acerca de OctaCrypt[/bold green]", box=box.ROUNDED))
    pause()


def main():
    while True:
        show_banner()
        choice = questionary.select(
            "Selecciona una opcion:",
            choices=[
                "Cifrar archivo",
                "Descifrar archivo",
                "Cifrar / Descifrar mensaje",
                "Firmar / Verificar archivo",
                "Generar claves",
                "Hash",
                "Acerca de OctaCrypt",
                "Salir",
            ],
            style=STYLE,
        ).ask()

        if choice is None or choice == "Salir":
            console.print("\n[bold green]Hasta luego. Stay encrypted.[/bold green]\n")
            sys.exit(0)
        elif choice == "Cifrar archivo":
            menu_file_encrypt()
        elif choice == "Descifrar archivo":
            menu_file_decrypt()
        elif choice == "Cifrar / Descifrar mensaje":
            menu_message()
        elif choice == "Firmar / Verificar archivo":
            menu_sign()
        elif choice == "Generar claves":
            menu_keygen()
        elif choice == "Hash":
            menu_hash()
        elif choice == "Acerca de OctaCrypt":
            show_about()


if __name__ == "__main__":
    main()
