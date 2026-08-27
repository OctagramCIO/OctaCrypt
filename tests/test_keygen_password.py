# tests/test_keygen_password.py

import pytest
import os
import tempfile
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from octacrypt.utils.keygen import (
    generate_rsa,
    generate_ed25519,
    generate_mlkem,
    generate_mldsa,
    save_keys,
    load_private_key,
)


@pytest.fixture
def tmp_dir():
    with tempfile.TemporaryDirectory() as d:
        yield d


def test_rsa_key_without_password(tmp_dir):
    key = generate_rsa(2048)
    priv, pub = save_keys(key, f"{tmp_dir}/testkey")

    # Debe cargarse sin password
    loaded = load_private_key(priv, password=None)
    assert loaded is not None


def test_rsa_key_with_password(tmp_dir):
    key = generate_rsa(2048)
    priv, pub = save_keys(key, f"{tmp_dir}/testkey", password="octagram123")

    # Con password correcto: OK
    loaded = load_private_key(priv, password="octagram123")
    assert loaded is not None


def test_rsa_key_wrong_password_raises(tmp_dir):
    key = generate_rsa(2048)
    priv, pub = save_keys(key, f"{tmp_dir}/testkey", password="correcta")

    # Con password incorrecto: debe fallar
    with pytest.raises(Exception):
        load_private_key(priv, password="incorrecta")


def test_ed25519_key_with_password(tmp_dir):
    key = generate_ed25519()
    priv, pub = save_keys(key, f"{tmp_dir}/signkey", password="signpass")

    loaded = load_private_key(priv, password="signpass")
    assert loaded is not None


def test_public_key_never_encrypted(tmp_dir):
    """La clave publica debe poder leerse sin password siempre."""
    key = generate_rsa(2048)
    priv, pub = save_keys(key, f"{tmp_dir}/testkey", password="secret")

    # La publica se lee sin password
    with open(pub, "rb") as f:
        data = f.read()
    assert b"PUBLIC KEY" in data


def test_encrypted_pem_marker(tmp_dir):
    """Una clave cifrada debe tener ENCRYPTED en el PEM."""
    key = generate_rsa(2048)
    priv, _ = save_keys(key, f"{tmp_dir}/testkey", password="test")

    with open(priv, "rb") as f:
        content = f.read()
    assert b"ENCRYPTED" in content


def test_unencrypted_pem_marker(tmp_dir):
    """Una clave sin password NO debe tener ENCRYPTED en el PEM."""
    key = generate_rsa(2048)
    priv, _ = save_keys(key, f"{tmp_dir}/testkey", password=None)

    with open(priv, "rb") as f:
        content = f.read()
    assert b"ENCRYPTED" not in content


# ─── Post-cuántico ─────────────────────────────────────────

def test_mlkem_key_without_password(tmp_dir):
    key = generate_mlkem("mlkem768")
    priv, pub = save_keys(key, f"{tmp_dir}/pqkem")

    loaded = load_private_key(priv, password=None)
    assert loaded is not None


def test_mlkem_key_with_password(tmp_dir):
    key = generate_mlkem("mlkem768")
    priv, pub = save_keys(key, f"{tmp_dir}/pqkem", password="octagram123")

    loaded = load_private_key(priv, password="octagram123")
    assert loaded is not None


def test_mlkem_key_wrong_password_raises(tmp_dir):
    key = generate_mlkem("mlkem768")
    priv, pub = save_keys(key, f"{tmp_dir}/pqkem", password="correcta")

    with pytest.raises(Exception):
        load_private_key(priv, password="incorrecta")


def test_mldsa_key_with_password(tmp_dir):
    key = generate_mldsa("mldsa65")
    priv, pub = save_keys(key, f"{tmp_dir}/pqsign", password="signpass")

    loaded = load_private_key(priv, password="signpass")
    assert loaded is not None


def test_mlkem_roundtrip(tmp_dir):
    """Generar, guardar y recargar una clave ML-KEM debe ser consistente."""
    key = generate_mlkem("mlkem768")
    priv, pub = save_keys(key, f"{tmp_dir}/pqkem", password="secret")

    loaded = load_private_key(priv, password="secret")
    original_public = key.public_key().public_bytes_raw()
    loaded_public = loaded.public_key().public_bytes_raw()
    assert loaded_public == original_public


def test_mldsa_roundtrip(tmp_dir):
    """Generar, guardar y recargar una clave ML-DSA debe ser consistente."""
    key = generate_mldsa("mldsa65")
    priv, pub = save_keys(key, f"{tmp_dir}/pqsign", password="secret")

    loaded = load_private_key(priv, password="secret")
    # ML-DSA es probabilístico: la firma no se compara byte a byte, se verifica.
    signature = loaded.sign(b"mensaje")
    key.public_key().verify(signature, b"mensaje")
    assert True


def test_invalid_pq_variant_raises():
    with pytest.raises(ValueError):
        generate_mlkem("mlkem256")
    with pytest.raises(ValueError):
        generate_mldsa("mldsa42")