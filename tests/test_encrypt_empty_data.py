def test_encrypt_empty_data():
    engine = CryptoEngine(
        algorithm="xor",
        key=b"octagram"
    )

    data = b""
    encrypted = engine.encrypt(data)
    decrypted = engine.decrypt(encrypted)

    assert decrypted == data
