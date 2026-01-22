from octacrypt.algorithms.xor import XORCipher


class CryptoEngine:
    """
    Central cryptographic engine for OctaCrypt.
    """

    _ALGORITHMS = {
        "xor": XORCipher,
    }

    def __init__(self, algorithm: str, key):
        # --- algorithm validation ---
        if not isinstance(algorithm, str):
            raise TypeError("Algorithm must be a string")

        algorithm = algorithm.lower()

        if algorithm not in self._ALGORITHMS:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

        # --- key validation ---
        if not key:
            raise ValueError("Key cannot be empty")

        if isinstance(key, str):
            key = key.encode()

        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("Key must be bytes or string")

        self.algorithm_name = algorithm
        self.key = bytes(key)
        self.cipher = self._ALGORITHMS[algorithm](self.key)

    def encrypt(self, data: bytes) -> bytes:
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("Data must be bytes")

        return self.cipher.encrypt(bytes(data))

    def decrypt(self, data: bytes) -> bytes:
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("Data must be bytes")

        return self.cipher.decrypt(bytes(data))
