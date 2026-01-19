# octacrypt/core/crypto_engine.py

from octacrypt.algorithms.aes_cipher import AESCipher

class CryptoEngine:
    def __init__(self, algorithm="AES"):
        if algorithm == "AES":
            self.cipher = AESCipher()
        else:
            raise ValueError("Algoritmo no soportado")

    def encrypt(self, plaintext: str) -> dict:
        return self.cipher.encrypt(plaintext)

    def decrypt(self, encrypted_data: dict) -> str:
        return self.cipher.decrypt(encrypted_data)
