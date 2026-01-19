# octacrypt/algorithms/xor.py

class XORCipher:
    """
    Simple XOR cipher.
    ⚠️ For educational and architectural testing purposes only.
    """

    def __init__(self, key: bytes):
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("Key must be bytes")
        if len(key) == 0:
            raise ValueError("Key must not be empty")

        self.key = key

    def _xor_bytes(self, data: bytes) -> bytes:
        result = bytearray()
        key_len = len(self.key)

        for i, byte in enumerate(data):
            result.append(byte ^ self.key[i % key_len])

        return bytes(result)

    def encrypt(self, plaintext: bytes) -> bytes:
        if not isinstance(plaintext, (bytes, bytearray)):
            raise TypeError("Plaintext must be bytes")

        return self._xor_bytes(plaintext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        if not isinstance(ciphertext, (bytes, bytearray)):
            raise TypeError("Ciphertext must be bytes")

        # XOR is symmetric
        return self._xor_bytes(ciphertext)
