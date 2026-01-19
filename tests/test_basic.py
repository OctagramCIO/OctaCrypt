from octacrypt.core.crypto_engine import CryptoEngine


def test_basic_encrypt_decrypt():
    engine = CryptoEngine(
        algorithm="AES",
        key=b"octagram"
    )

    original = b"Octagram vive"
    encrypted = engine.encrypt(original)
    decrypted = engine.decrypt(encrypted)

    assert encrypted != original
    assert decrypted == original

