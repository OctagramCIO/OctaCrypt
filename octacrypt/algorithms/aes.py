from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os


class AESAlgorithm:
    NONCE_SIZE = 12  # recomendado para GCM

    def __init__(self, key: bytes):
        if not isinstance(key, bytes):
            raise TypeError("Key must be bytes")

        if len(key) != 32:
            raise ValueError("AES key must be 32 bytes (AES-256)")

        self.aes = AESGCM(key)

    def encrypt(self, data: bytes) -> bytes:
        nonce = os.urandom(self.NONCE_SIZE)
        ciphertext = self.aes.encrypt(nonce, data, None)
        return nonce + ciphertext

    def decrypt(self, data: bytes) -> bytes:
        nonce = data[:self.NONCE_SIZE]
        ciphertext = data[self.NONCE_SIZE:]
        return self.aes.decrypt(nonce, ciphertext, None)
