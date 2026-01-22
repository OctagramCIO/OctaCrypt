from octacrypt.algorithms.xor import XORCipher
from octacrypt.algorithms.aes import AESAlgorithm


class CryptoEngine:
    _ALGORITHMS = {
        "xor": XORCipher,
        "aes": AESAlgorithm,
    }

    def __init__(self, algorithm: str, key: bytes):
        if algorithm not in self._ALGORITHMS:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

        if not isinstance(key, bytes):
            raise TypeError("Key must be bytes")

        self.cipher = self._ALGORITHMS[algorithm](key)

    def encrypt(self, data: bytes) -> bytes:
        return self.cipher.encrypt(data)

    def decrypt(self, data: bytes) -> bytes:
        return self.cipher.decrypt(data)
