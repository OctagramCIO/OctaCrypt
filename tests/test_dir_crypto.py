# tests/test_dir_crypto.py

import pytest
import tempfile
from pathlib import Path

from octacrypt.core.dir_crypto import (
    encrypt_directory,
    decrypt_directory,
    get_directory_info,
    MANIFEST_NAME,
)


@pytest.fixture
def sample_dir():
    """Crea un directorio de prueba con estructura anidada."""
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp) / "docs"
        base.mkdir()

        # Archivos en raiz
        (base / "contrato.txt").write_bytes(b"Contrato confidencial")
        (base / "notas.txt").write_bytes(b"Notas importantes")

        # Subdirectorio
        (base / "fotos").mkdir()
        (base / "fotos" / "imagen.jpg").write_bytes(b"\xff\xd8\xff" + b"fake jpeg data")

        # Subdirectorio anidado
        (base / "fotos" / "raw").mkdir()
        (base / "fotos" / "raw" / "photo.raw").write_bytes(b"raw image data" * 100)

        yield base


@pytest.fixture
def output_dirs():
    with tempfile.TemporaryDirectory() as tmp:
        yield Path(tmp)


def test_encrypt_creates_output_dir(sample_dir, output_dirs):
    enc_dir = output_dirs / "docs.enc"
    result, files, total = encrypt_directory(sample_dir, enc_dir, key="testpass")
    assert result.exists()
    assert result.is_dir()


def test_encrypt_preserves_structure(sample_dir, output_dirs):
    enc_dir = output_dirs / "docs.enc"
    encrypt_directory(sample_dir, enc_dir, key="testpass")

    assert (enc_dir / "contrato.txt.enc").exists()
    assert (enc_dir / "notas.txt.enc").exists()
    assert (enc_dir / "fotos" / "imagen.jpg.enc").exists()
    assert (enc_dir / "fotos" / "raw" / "photo.raw.enc").exists()


def test_encrypt_creates_manifest(sample_dir, output_dirs):
    enc_dir = output_dirs / "docs.enc"
    encrypt_directory(sample_dir, enc_dir, key="testpass")
    assert (enc_dir / MANIFEST_NAME).exists()


def test_encrypt_decrypt_roundtrip(sample_dir, output_dirs):
    enc_dir = output_dirs / "docs.enc"
    dec_dir = output_dirs / "docs_dec"

    encrypt_directory(sample_dir, enc_dir, key="mipassword")
    decrypt_directory(enc_dir, dec_dir, key="mipassword")

    # Verificar que los archivos son identicos
    assert (dec_dir / "contrato.txt").read_bytes() == b"Contrato confidencial"
    assert (dec_dir / "notas.txt").read_bytes() == b"Notas importantes"
    assert (dec_dir / "fotos" / "imagen.jpg").read_bytes() == b"\xff\xd8\xff" + b"fake jpeg data"


def test_encrypt_returns_correct_counts(sample_dir, output_dirs):
    enc_dir = output_dirs / "docs.enc"
    _, files, total = encrypt_directory(sample_dir, enc_dir, key="testpass")
    assert files == 4  # contrato, notas, imagen, photo
    assert total > 0


def test_wrong_password_raises(sample_dir, output_dirs):
    enc_dir = output_dirs / "docs.enc"
    dec_dir = output_dirs / "docs_dec"

    encrypt_directory(sample_dir, enc_dir, key="correcta")
    with pytest.raises(Exception):
        decrypt_directory(enc_dir, dec_dir, key="incorrecta")


def test_chacha20_roundtrip(sample_dir, output_dirs):
    enc_dir = output_dirs / "docs.enc"
    dec_dir = output_dirs / "docs_dec"

    encrypt_directory(sample_dir, enc_dir, key="pw", algorithm="chacha20")
    decrypt_directory(enc_dir, dec_dir, key="pw")

    assert (dec_dir / "contrato.txt").read_bytes() == b"Contrato confidencial"


def test_manifest_contains_correct_info(sample_dir, output_dirs):
    enc_dir = output_dirs / "docs.enc"
    encrypt_directory(sample_dir, enc_dir, key="testpass", algorithm="chacha20")

    info = get_directory_info(enc_dir)
    assert info["algorithm"] == "chacha20"
    assert info["total_files"] == 4
    assert info["original_dir"] == "docs"


def test_missing_manifest_raises(output_dirs):
    fake_dir = output_dirs / "fake.enc"
    fake_dir.mkdir()
    with pytest.raises(FileNotFoundError):
        get_directory_info(fake_dir)


def test_non_directory_raises(output_dirs):
    fake_file = output_dirs / "fake.txt"
    fake_file.write_bytes(b"not a dir")
    with pytest.raises(ValueError):
        encrypt_directory(fake_file, output_dirs / "out", key="pw")


def test_default_output_name(sample_dir):
    """Sin --out, el directorio de salida debe ser input.enc al lado del original."""
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "mis_docs"
        src.mkdir()
        (src / "file.txt").write_bytes(b"data")

        result, _, _ = encrypt_directory(src, None, key="pw")
        assert result.name == "mis_docs.enc"
        assert result.parent == src.parent
