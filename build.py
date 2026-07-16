#!/usr/bin/env python3
# build.py
#
# Script de build para OctaCrypt
# Genera ejecutables portables para Windows, Linux y macOS
#
# Uso:
#   python build.py              -> build completo (CLI + TUI)
#   python build.py --cli-only   -> solo CLI
#   python build.py --tui-only   -> solo TUI
#   python build.py --clean      -> limpiar build anterior

import sys
import shutil
import subprocess
import argparse
from pathlib import Path

DIST_DIR = Path("dist")
BUILD_DIR = Path("build")


def clean():
    print("Limpiando build anterior...")
    for d in [DIST_DIR, BUILD_DIR]:
        if d.exists():
            shutil.rmtree(d)
            print(f"  -> Eliminado: {d}")
    print("Listo.\n")


def check_dependencies():
    try:
        import PyInstaller
        print(f"PyInstaller: OK ({PyInstaller.__version__})")
    except ImportError:
        print("ERROR: PyInstaller no encontrado.")
        print("Instala con: pip install pyinstaller")
        sys.exit(1)

    try:
        import cryptography
        print(f"cryptography: OK")
    except ImportError:
        print("ERROR: cryptography no encontrado.")
        sys.exit(1)


def build_exe(entry: str, name: str, extra_imports: list[str] = []):
    print(f"\nGenerando ejecutable: {name}")
    print(f"  Entry point: {entry}")

    hidden = [
        "octacrypt.algorithms.aes",
        "octacrypt.algorithms.chacha",
        "octacrypt.algorithms.hybrid",
        "octacrypt.algorithms.signer",
        "octacrypt.core.crypto_engine",
        "octacrypt.core.crypto",
        "octacrypt.core.dir_crypto",
        "octacrypt.core.messenger",
        "octacrypt.utils.kdf",
        "octacrypt.utils.keygen",
        "octacrypt.utils.hash",
        "octacrypt.utils.logger",
        "cryptography.hazmat.primitives.ciphers.aead",
        "cryptography.hazmat.primitives.asymmetric.rsa",
        "cryptography.hazmat.primitives.asymmetric.ed25519",
        "cryptography.hazmat.primitives.asymmetric.padding",
        "cryptography.hazmat.primitives.kdf.pbkdf2",
        "cryptography.hazmat.backends",
        "bcrypt",
        "click",
    ] + extra_imports

    cmd = [
        sys.executable, "-m", "PyInstaller",
        entry,
        "--onefile",
        "--console",
        "--name", name,
        "--clean",
        "--noconfirm",
    ]

    for imp in hidden:
        cmd += ["--hidden-import", imp]

    result = subprocess.run(cmd, capture_output=False)

    if result.returncode != 0:
        print(f"\nERROR: Fallo el build de {name}")
        sys.exit(1)

    exe_path = DIST_DIR / name
    if sys.platform == "win32":
        exe_path = DIST_DIR / (name + ".exe")

    if exe_path.exists():
        size_mb = exe_path.stat().st_size / 1024 / 1024
        print(f"\n  Ejecutable generado: {exe_path}")
        print(f"  Tamano: {size_mb:.1f} MB")
    else:
        print(f"\nADVERTENCIA: No se encontro el ejecutable en {exe_path}")


def main():
    parser = argparse.ArgumentParser(description="OctaCrypt Build Tool")
    parser.add_argument("--cli-only", action="store_true", help="Solo generar CLI")
    parser.add_argument("--tui-only", action="store_true", help="Solo generar TUI")
    parser.add_argument("--clean", action="store_true", help="Limpiar y salir")
    args = parser.parse_args()

    print("=" * 50)
    print("  OctaCrypt Build Tool")
    print("=" * 50)

    if args.clean:
        clean()
        return

    clean()
    check_dependencies()

    tui_imports = [
        "rich", "rich.console", "rich.panel",
        "rich.table", "rich.text", "rich.box",
        "questionary",
    ]

    if args.tui_only:
        build_exe("octacrypt/tui/tui_entry.py", "octacrypt-tui", tui_imports)
    elif args.cli_only:
        build_exe("octacrypt/cli/cli_entry.py", "octacrypt")
    else:
        build_exe("octacrypt/cli/cli_entry.py", "octacrypt")
        build_exe("octacrypt/tui/tui_entry.py", "octacrypt-tui", tui_imports)

    print("\n" + "=" * 50)
    print("  Build completado.")
    print(f"  Ejecutables en: {DIST_DIR.absolute()}")
    print("=" * 50)


if __name__ == "__main__":
    main()
