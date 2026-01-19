class XorCipher:
    def __init__(self, key: bytes):
        self.key = key

    def encrypt(self, data: bytes) -> bytes:
        return bytes(
            data[i] ^ self.key[i % len(self.key)]
            for i in range(len(data))
        )

    def decrypt(self, data: bytes) -> bytes:
        # XOR es simétrico
        return self.encrypt(data)
