# octacrypt/core/dir_crypto.py

import json
from datetime import datetime, timezone
from pathlib import Path

from octacrypt.core.crypto import decrypt_file, encrypt_file

MANIFEST_NAME = ".octadir"


def _safe_join(base: Path, relative: str, field: str) -> Path:
    """
    Une una ruta relativa del manifiesto con base, garantizando que
    el resultado quede dentro de base (previene path traversal).
    """
    rel = Path(relative)
    if rel.is_absolute() or ".." in rel.parts:
        raise ValueError(
            f"Ruta inválida en manifiesto ('{field}'): '{relative}'. "
            "El archivo puede haber sido manipulado."
        )
    resolved = (base / rel).resolve()
    if not resolved.is_relative_to(base.resolve()):
        raise ValueError(
            f"Ruta inválida en manifiesto ('{field}'): '{relative}'. "
            "El archivo puede haber sido manipulado."
        )
    return resolved


def encrypt_directory(input_dir, output_dir, key: str, algorithm: str = "aes"):
    input_dir = Path(input_dir)
    if not input_dir.is_dir():
        raise ValueError(f"No es un directorio: {input_dir}")

    if output_dir is None:
        output_dir = input_dir.parent / (input_dir.name + ".enc")
    else:
        output_dir = Path(output_dir)

    output_dir.mkdir(parents=True, exist_ok=True)

    files_encrypted = 0
    total_bytes = 0
    manifest_entries = []

    for file_path in sorted([f for f in input_dir.rglob("*") if f.is_file()]):
        relative = file_path.relative_to(input_dir)
        output_file = output_dir / (str(relative) + ".enc")
        output_file.parent.mkdir(parents=True, exist_ok=True)
        file_size = file_path.stat().st_size
        encrypt_file(file_path, output_file, key=key, algorithm=algorithm)
        files_encrypted += 1
        total_bytes += file_size
        manifest_entries.append({
            "original": str(relative),
            "encrypted": str(relative) + ".enc",
            "size": file_size,
        })

    manifest = {
        "version": "1",
        "algorithm": algorithm,
        "original_dir": input_dir.name,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "files": manifest_entries,
        "total_files": files_encrypted,
        "total_bytes": total_bytes,
    }
    (output_dir / MANIFEST_NAME).write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return output_dir, files_encrypted, total_bytes


def decrypt_directory(input_dir, output_dir, key: str):
    input_dir = Path(input_dir)
    if not input_dir.is_dir():
        raise ValueError(f"No es un directorio: {input_dir}")

    manifest_path = input_dir / MANIFEST_NAME
    if not manifest_path.exists():
        raise FileNotFoundError(f"Manifiesto no encontrado: {manifest_path}")

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    files = manifest.get("files")
    if not isinstance(files, list):
        raise ValueError("Manifiesto corrupto: falta la lista de archivos.")

    if output_dir is None:
        original_name = manifest.get("original_dir", input_dir.name.removesuffix(".enc"))
        if (
            not isinstance(original_name, str)
            or not original_name
            or Path(original_name).name != original_name
        ):
            original_name = input_dir.name.removesuffix(".enc")
        output_dir = input_dir.parent / original_name
    else:
        output_dir = Path(output_dir)

    output_dir.mkdir(parents=True, exist_ok=True)
    files_decrypted = 0
    total_bytes = 0

    for entry in files:
        enc_file = _safe_join(input_dir, entry["encrypted"], "encrypted")
        out_file = _safe_join(output_dir, entry["original"], "original")
        if not enc_file.exists():
            raise FileNotFoundError(f"Archivo cifrado no encontrado: {enc_file}")
        out_file.parent.mkdir(parents=True, exist_ok=True)
        decrypt_file(enc_file, out_file, key=key)
        files_decrypted += 1
        total_bytes += entry.get("size", 0)

    return output_dir, files_decrypted, total_bytes


def get_directory_info(input_dir) -> dict:
    manifest_path = Path(input_dir) / MANIFEST_NAME
    if not manifest_path.exists():
        raise FileNotFoundError(f"No es un directorio OctaCrypt: {input_dir}")
    return json.loads(manifest_path.read_text(encoding="utf-8"))
