import json
import os
from pathlib import Path
from datetime import datetime, timezone
from octacrypt.core.crypto import encrypt_file, decrypt_file

MANIFEST_NAME = ".octadir"


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

    for file_path in [f for f in input_dir.rglob("*") if f.is_file()]:
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

    if output_dir is None:
        original_name = manifest.get("original_dir", input_dir.name.removesuffix(".enc"))
        output_dir = input_dir.parent / original_name
    else:
        output_dir = Path(output_dir)

    output_dir.mkdir(parents=True, exist_ok=True)
    files_decrypted = 0
    total_bytes = 0

    for entry in manifest["files"]:
        enc_file = input_dir / entry["encrypted"]
        out_file = output_dir / entry["original"]
        if not enc_file.exists():
            raise FileNotFoundError(f"Archivo no encontrado: {enc_file}")
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


def read_manifest(enc_dir) -> dict:
    """Lee el manifiesto de un directorio cifrado."""
    from pathlib import Path
    manifest_path = Path(enc_dir) / MANIFEST_NAME
    if not manifest_path.exists():
        raise FileNotFoundError(f"Manifiesto no encontrado en: {enc_dir}")
    import json
    return json.loads(manifest_path.read_text())
