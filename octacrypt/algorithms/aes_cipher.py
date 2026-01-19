# octacrypt/algorithms/aes_cipher.py

from cryptography.fernet import Fernet

class AESCipher:
    def __init__(self):
        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)

    def encrypt(self, plaintext: str) -> dict:
        encrypted = self.cipher.encrypt(plaintext.encode())
        return {
            "ciphertext": encrypted,
            "key": self.key
        }

    def decrypt(self, encrypted_data: dict) -> str:
        cipher = Fernet(encrypted_data["key"])
        decrypted = cipher.decrypt(encrypted_data["ciphertext"])
        return decrypted.decode()
