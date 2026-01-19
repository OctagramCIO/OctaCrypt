# tests/test_crypto_engine.py

from octacrypt.core.crypto_engine import CryptoEngine


def test_xor_encrypt_decrypt():
    engine = CryptoEngine(
        algorithm="xor",
        key=b"octagram"
    )

    original = b"Hello OctaCrypt"
    encrypted = engine.encrypt(original)
    decrypted = engine.decrypt(encrypted)

    assert encrypted != original
    assert decrypted == original


def test_invalid_algorithm():
    try:
        CryptoEngine("invalid", b"key")
        assert False
    except ValueError:
        assert True


def test_invalid_key_type():
    try:
        CryptoEngine("xor", "not-bytes")
        assert False
    except TypeError:
        assert True

