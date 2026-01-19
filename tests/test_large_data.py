from octacrypt.core.crypto_engine import CryptoEngine


def test_large_data():
    engine = CryptoEngine(
        algorithm="xor",
        key=b"octagram"
    )

    data = b"A" * 10_000
    encrypted = engine.encrypt(data)
    decrypted = engine.decrypt(encrypted)

    assert decrypted == data
