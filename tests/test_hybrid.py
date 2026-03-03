# tests/test_hybrid.py

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from octacrypt.algorithms.hybrid import HybridCipher


# ─────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────

@pytest.fixture(scope="module")
def rsa_keypair_pem():
    """Genera un par de claves RSA 2048 en PEM para los tests."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


# ─────────────────────────────────────────
# Tests
# ─────────────────────────────────────────

def test_encrypt_decrypt_basic(rsa_keypair_pem):
    """El texto descifrado debe coincidir con el original."""
    private_pem, public_pem = rsa_keypair_pem

    plaintext = b"OctaCrypt hybrid encryption test"

    encryptor = HybridCipher(public_key_pem=public_pem)
    decryptor = HybridCipher(private_key_pem=private_pem)

    encrypted = encryptor.encrypt(plaintext)
    decrypted = decryptor.decrypt(encrypted)

    assert decrypted == plaintext


def test_encrypted_differs_from_plaintext(rsa_keypair_pem):
    """El ciphertext no debe ser igual al plaintext."""
    private_pem, public_pem = rsa_keypair_pem

    plaintext = b"datos secretos de octagram"

    encryptor = HybridCipher(public_key_pem=public_pem)
    encrypted = encryptor.encrypt(plaintext)

    assert encrypted != plaintext


def test_large_data(rsa_keypair_pem):
    """Debe funcionar con archivos grandes (RSA solo cifra la session key)."""
    private_pem, public_pem = rsa_keypair_pem

    plaintext = b"A" * 10_000_000  # 10 MB

    encryptor = HybridCipher(public_key_pem=public_pem)
    decryptor = HybridCipher(private_key_pem=private_pem)

    encrypted = encryptor.encrypt(plaintext)
    decrypted = decryptor.decrypt(encrypted)

    assert decrypted == plaintext


def test_empty_data(rsa_keypair_pem):
    """Debe manejar datos vacíos sin error."""
    private_pem, public_pem = rsa_keypair_pem

    plaintext = b""

    encryptor = HybridCipher(public_key_pem=public_pem)
    decryptor = HybridCipher(private_key_pem=private_pem)

    encrypted = encryptor.encrypt(plaintext)
    decrypted = decryptor.decrypt(encrypted)

    assert decrypted == plaintext


def test_tampered_data_raises(rsa_keypair_pem):
    """Modificar el ciphertext debe lanzar excepción (integridad GCM)."""
    private_pem, public_pem = rsa_keypair_pem

    plaintext = b"dato importante"

    encryptor = HybridCipher(public_key_pem=public_pem)
    decryptor = HybridCipher(private_key_pem=private_pem)

    encrypted = bytearray(encryptor.encrypt(plaintext))
    encrypted[-1] ^= 0xFF  # corromper último byte

    with pytest.raises(Exception):
        decryptor.decrypt(bytes(encrypted))


def test_encrypt_without_public_key_raises():
    """Cifrar sin clave pública debe lanzar ValueError."""
    cipher = HybridCipher()
    with pytest.raises(ValueError):
        cipher.encrypt(b"test")


def test_decrypt_without_private_key_raises():
    """Descifrar sin clave privada debe lanzar ValueError."""
    cipher = HybridCipher()
    with pytest.raises(ValueError):
        cipher.decrypt(b"fake_data")


def test_wrong_key_raises(rsa_keypair_pem):
    """Descifrar con una clave privada diferente debe fallar."""
    _, public_pem = rsa_keypair_pem

    # Generar un segundo par de claves diferente
    other_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    other_private_pem = other_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    encryptor = HybridCipher(public_key_pem=public_pem)
    decryptor = HybridCipher(private_key_pem=other_private_pem)

    encrypted = encryptor.encrypt(b"secreto")

    with pytest.raises(Exception):
        decryptor.decrypt(encrypted)