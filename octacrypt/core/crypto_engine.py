from octacrypt.algorithms.aes import AESAlgorithm
from octacrypt.algorithms.hybrid import HybridCipher


class CryptoEngine:
    """
    Motor criptográfico central de OctaCrypt.
    Soporta: AES-256-GCM, RSA+AES Híbrido.

    XOR fue removido — no apto para uso real.
    """

    _SYMMETRIC = {
        "aes": AESAlgorithm,
    }

    def __init__(self, algorithm: str, key: bytes):
        algorithm = algorithm.lower()

        if algorithm not in self._SYMMETRIC:
            raise ValueError(
                f"Algoritmo no soportado: '{algorithm}'. "
                f"Disponibles: {list(self._SYMMETRIC.keys())}"
            )

        if not isinstance(key, bytes):
            raise TypeError("La clave debe ser bytes")

        if len(key) == 0:
            raise ValueError("La clave no puede estar vacía")

        self.algorithm = algorithm
        self.cipher = self._SYMMETRIC[algorithm](key)

    def encrypt(self, data: bytes) -> bytes:
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("Los datos deben ser bytes")
        return self.cipher.encrypt(data)

    def decrypt(self, data: bytes) -> bytes:
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("Los datos deben ser bytes")
        return self.cipher.decrypt(data)
