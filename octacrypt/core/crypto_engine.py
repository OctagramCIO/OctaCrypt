from octacrypt.algorithms.aes import AESAlgorithm
from octacrypt.algorithms.chacha import ChaChaAlgorithm

class CryptoEngine:
    _SYMMETRIC = {
        "aes": AESAlgorithm,
        "chacha20": ChaChaAlgorithm,
    }

    def __init__(self, algorithm: str, key: bytes):
        algorithm = algorithm.lower()
        if algorithm not in self._SYMMETRIC:
            raise ValueError(f"Algoritmo no soportado: '{algorithm}'. Disponibles: {list(self._SYMMETRIC.keys())}")
        if not isinstance(key, bytes):
            raise TypeError("La clave debe ser bytes")
        if len(key) == 0:
            raise ValueError("La clave no puede estar vacia")
        self.algorithm = algorithm
        self.cipher = self._SYMMETRIC[algorithm](key)

    def encrypt(self, data: bytes) -> bytes:
        return self.cipher.encrypt(data)

    def decrypt(self, data: bytes) -> bytes:
        return self.cipher.decrypt(data)