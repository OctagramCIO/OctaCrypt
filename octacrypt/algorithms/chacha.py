import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

class ChaChaAlgorithm:
    KEY_SIZE = 32
    NONCE_SIZE = 12

    def __init__(self, key: bytes):
        if not isinstance(key, bytes):
            raise TypeError("La clave debe ser bytes.")
        if len(key) != self.KEY_SIZE:
            raise ValueError(f"ChaCha20-Poly1305 requiere exactamente 32 bytes, se recibieron {len(key)}.")
        self._chacha = ChaCha20Poly1305(key)

    def encrypt(self, data: bytes) -> bytes:
        nonce = os.urandom(self.NONCE_SIZE)
        return nonce + self._chacha.encrypt(nonce, data, None)

    def decrypt(self, data: bytes) -> bytes:
        if len(data) < self.NONCE_SIZE + 16:
            raise ValueError("Datos demasiado cortos.")
        return self._chacha.decrypt(data[:self.NONCE_SIZE], data[self.NONCE_SIZE:], None)