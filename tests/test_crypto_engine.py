from octacrypt.core.crypto_engine import CryptoEngine

def test_encrypt_and_decrypt():
    engine = CryptoEngine(
        algorithm="xor",
        key=b"octagram"
    )

    original = b"OctaCrypt is alive"
    encrypted = engine.encrypt(original)
    decrypted = engine.decrypt(encrypted)

    assert encrypted != original
    assert decrypted == original
