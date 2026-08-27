# tests/test_mlkem.py

import pytest

from octacrypt.algorithms.mlkem import MLKEMCipher


# ─────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────

@pytest.fixture(scope="module")
def mlkem_keypair():
    """Genera un par de claves ML-KEM-768 en PEM para los tests."""
    return MLKEMCipher.generate_keypair(variant="mlkem768")


@pytest.fixture(scope="module")
def mlkem1024_keypair():
    """Genera un par de claves ML-KEM-1024 en PEM para los tests."""
    return MLKEMCipher.generate_keypair(variant="mlkem1024")


# ─────────────────────────────────────────
# Tests
# ─────────────────────────────────────────

def test_encrypt_decrypt_basic(mlkem_keypair):
    """El texto descifrado debe coincidir con el original."""
    private_pem, public_pem = mlkem_keypair

    plaintext = b"OctaCrypt post-quantum encryption test"

    encryptor = MLKEMCipher(public_key_pem=public_pem)
    decryptor = MLKEMCipher(private_key_pem=private_pem)

    encrypted = encryptor.encrypt(plaintext)
    decrypted = decryptor.decrypt(encrypted)

    assert decrypted == plaintext


def test_encrypted_differs_from_plaintext(mlkem_keypair):
    """El ciphertext no debe ser igual al plaintext."""
    _, public_pem = mlkem_keypair

    plaintext = b"datos secretos resistentes a computadoras cuanticas"

    encryptor = MLKEMCipher(public_key_pem=public_pem)
    encrypted = encryptor.encrypt(plaintext)

    assert encrypted != plaintext


def test_large_data(mlkem_keypair):
    """Debe funcionar con archivos grandes (ML-KEM solo encapsula la session key)."""
    private_pem, public_pem = mlkem_keypair

    plaintext = b"A" * 10_000_000  # 10 MB

    encryptor = MLKEMCipher(public_key_pem=public_pem)
    decryptor = MLKEMCipher(private_key_pem=private_pem)

    encrypted = encryptor.encrypt(plaintext)
    decrypted = decryptor.decrypt(encrypted)

    assert decrypted == plaintext


def test_empty_data(mlkem_keypair):
    """Debe manejar datos vacíos sin error."""
    private_pem, public_pem = mlkem_keypair

    plaintext = b""

    encryptor = MLKEMCipher(public_key_pem=public_pem)
    decryptor = MLKEMCipher(private_key_pem=private_pem)

    encrypted = encryptor.encrypt(plaintext)
    decrypted = decryptor.decrypt(encrypted)

    assert decrypted == plaintext


def test_tampered_data_raises(mlkem_keypair):
    """Modificar el ciphertext debe lanzar excepción (integridad GCM)."""
    private_pem, public_pem = mlkem_keypair

    plaintext = b"dato importante"

    encryptor = MLKEMCipher(public_key_pem=public_pem)
    decryptor = MLKEMCipher(private_key_pem=private_pem)

    encrypted = bytearray(encryptor.encrypt(plaintext))
    encrypted[-1] ^= 0xFF  # corromper último byte

    with pytest.raises(Exception):
        decryptor.decrypt(bytes(encrypted))


def test_encrypt_without_public_key_raises():
    """Cifrar sin clave pública debe lanzar ValueError."""
    cipher = MLKEMCipher()
    with pytest.raises(ValueError):
        cipher.encrypt(b"test")


def test_decrypt_without_private_key_raises():
    """Descifrar sin clave privada debe lanzar ValueError."""
    cipher = MLKEMCipher()
    with pytest.raises(ValueError):
        cipher.decrypt(b"fake_data")


def test_wrong_key_raises(mlkem_keypair):
    """Descifrar con una clave privada diferente debe fallar."""
    _, public_pem = mlkem_keypair

    # Generar un segundo par de claves diferente
    other_private_pem, _ = MLKEMCipher.generate_keypair(variant="mlkem768")

    encryptor = MLKEMCipher(public_key_pem=public_pem)
    decryptor = MLKEMCipher(private_key_pem=other_private_pem)

    encrypted = encryptor.encrypt(b"secreto")

    with pytest.raises(Exception):
        decryptor.decrypt(encrypted)


def test_mlkem1024_roundtrip(mlkem1024_keypair):
    """ML-KEM-1024 debe funcionar igual que ML-KEM-768."""
    private_pem, public_pem = mlkem1024_keypair

    plaintext = b"maximo nivel post-cuantico"

    encryptor = MLKEMCipher(public_key_pem=public_pem)
    decryptor = MLKEMCipher(private_key_pem=private_pem)

    assert decryptor.decrypt(encryptor.encrypt(plaintext)) == plaintext


def test_invalid_variant_raises():
    """Una variante desconocida debe lanzar ValueError."""
    with pytest.raises(ValueError):
        MLKEMCipher.generate_keypair(variant="mlkem256")

    with pytest.raises(ValueError):
        MLKEMCipher(variant="mlkem256")


def test_generated_keys_are_pem(mlkem_keypair):
    """Las claves generadas deben ser PEM legibles."""
    private_pem, public_pem = mlkem_keypair

    assert b"PRIVATE KEY" in private_pem
    assert b"PUBLIC KEY" in public_pem