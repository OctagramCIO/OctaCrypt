# tests/test_keygen_password.py

import pytest
import os
import tempfile
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from octacrypt.utils.keygen import generate_rsa, generate_ed25519, save_keys, load_private_key


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