from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os


class AESAlgorithm:
    def __init__(self, key: bytes):
        if len(key) not in (16, 24, 32):
            raise ValueError("AES key must be 128, 192, or 256 bits")

        self.aesgcm = AESGCM(key)

    def encrypt(self, data: bytes) -> bytes:
        nonce = os.urandom(12)  # 96-bit nonce (estándar GCM)
        ciphertext = self.aesgcm.encrypt(nonce, data, None)
        return nonce + ciphertext  # se guarda todo junto

    def decrypt(self, data: bytes) -> bytes:
        nonce = data[:12]
        ciphertext = data[12:]
        return self.aesgcm.decrypt(nonce, ciphertext, None)
