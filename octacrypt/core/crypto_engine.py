# octacrypt/core/crypto_engine.py

from octacrypt.algorithms.xor import XORCipher


class CryptoEngine:
    """
    Central cryptographic engine for OctaCrypt.
    """

    _ALGORITHMS = {
        "xor": XORCipher,
    }

    def __init__(self, algorithm: str, key: bytes):
        if not isinstance(algorithm, str):
            raise TypeError("Algorithm must be a string")

        algorithm = algorithm.lower()

        if algorithm not in self._ALGORITHMS:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("Key must be bytes")

        self.algorithm_name = algorithm
        self.cipher = self._ALGORITHMS[algorithm](key)

    def encrypt(self, data: bytes) -> bytes:
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("Data must be bytes")

        return self.cipher.encrypt(data)

    def decrypt(self, data: bytes) -> bytes:
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("Data must be bytes")

        return self.cipher.decrypt(data)