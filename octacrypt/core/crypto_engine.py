from octacrypt.algorithms.aes_cipher import AESCipher
from octacrypt.algorithms.xor import XORCipher


class CryptoEngine:
    SUPPORTED_ALGORITHMS = {
        "AES": AESCipher,
        "xor": XORCipher,
    }

    def __init__(self, algorithm: str, key: bytes):
        if not key:
            raise ValueError("Key cannot be empty")

        if algorithm not in self.SUPPORTED_ALGORITHMS:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

        cipher_class = self.SUPPORTED_ALGORITHMS[algorithm]
        self.cipher = cipher_class(key)

    def encrypt(self, plaintext: bytes) -> bytes:
        return self.cipher.encrypt(plaintext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        return self.cipher.decrypt(ciphertext)
