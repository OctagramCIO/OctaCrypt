from octacrypt.algorithms.xor import XORAlgorithm
from octacrypt.algorithms.aes import AESAlgorithm


class CryptoEngine:
    def __init__(self, algorithm: str, key: bytes):
        self.algorithm = algorithm.lower()

        if self.algorithm == "xor":
            self.engine = XORAlgorithm(key)

        elif self.algorithm == "aes":
            self.engine = AESAlgorithm(key)

        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

    def encrypt(self, data: bytes) -> bytes:
        return self.engine.encrypt(data)

    def decrypt(self, data: bytes) -> bytes:
        return self.engine.decrypt(data)
