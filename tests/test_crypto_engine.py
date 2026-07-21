# tests/test_crypto_engine.py
import pytest
import os
from octacrypt.core.crypto_engine import CryptoEngine


@pytest.mark.parametrize("alg", ["aes", "chacha20", "AES", "ChaCha20"])
def test_encrypt_decrypt(alg):
    key = os.urandom(32)
    engine = CryptoEngine(alg, key)
    data = b"test data octacrypt"
    assert engine.decrypt(engine.encrypt(data)) == data


def test_unsupported_algorithm():
    with pytest.raises(ValueError):
        CryptoEngine("xor", os.urandom(32))


def test_unsupported_algorithm_random():
    with pytest.raises(ValueError):
        CryptoEngine("hacker123", os.urandom(32))


def test_invalid_key_type():
    with pytest.raises(TypeError):
        CryptoEngine("aes", "not bytes")


def test_empty_key():
    with pytest.raises(ValueError):
        CryptoEngine("aes", b"")


def test_empty_data():
    engine = CryptoEngine("aes", os.urandom(32))
    assert engine.decrypt(engine.encrypt(b"")) == b""


def test_large_data():
    engine = CryptoEngine("chacha20", os.urandom(32))
    data = b"Z" * 5_000_000
    assert engine.decrypt(engine.encrypt(data)) == data