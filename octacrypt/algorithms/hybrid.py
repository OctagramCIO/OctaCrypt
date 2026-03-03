# octacrypt/algorithms/hybrid.py
#
# Cifrado híbrido: RSA-OAEP + AES-256-GCM
#
# Formato del mensaje cifrado:
#   [2 bytes: tamaño de la clave cifrada] [clave AES cifrada con RSA] [nonce 12 bytes] [ciphertext + tag GCM]
#
# Flujo:
#   Encrypt: genera session key AES aleatoria → cifra datos con AES-GCM → cifra session key con RSA-OAEP
#   Decrypt: descifra session key con RSA → descifra datos con AES-GCM

import os
import struct

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import (
    load_pem_public_key,
    load_pem_private_key,
)


class HybridCipher:
    """
    Cifrado híbrido RSA-OAEP + AES-256-GCM.

    Para cifrar se usa la clave pública RSA.
    Para descifrar se usa la clave privada RSA.
    """

    SESSION_KEY_SIZE = 32   # AES-256
    NONCE_SIZE = 12         # GCM estándar

    def __init__(
        self,
        public_key_pem: bytes | None = None,
        private_key_pem: bytes | None = None,
        private_key_password: bytes | None = None,
    ):
        """
        Args:
            public_key_pem:       Clave pública RSA en formato PEM (para cifrar).
            private_key_pem:      Clave privada RSA en formato PEM (para descifrar).
            private_key_password: Contraseña de la clave privada (si está cifrada).
        """
        self._public_key = None
        self._private_key = None

        if public_key_pem:
            self._public_key = load_pem_public_key(public_key_pem)

        if private_key_pem:
            self._private_key = load_pem_private_key(
                private_key_pem,
                password=private_key_password,
            )

    # ------------------------------------------------------------------
    # Encrypt
    # ------------------------------------------------------------------

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Cifra datos con cifrado híbrido RSA + AES-GCM.

        Args:
            plaintext: Datos a cifrar (cualquier tamaño).

        Returns:
            Blob cifrado con formato:
            [2B key_len][encrypted_session_key][12B nonce][ciphertext+tag]
        """
        if self._public_key is None:
            raise ValueError("Se necesita una clave pública RSA para cifrar.")

        if not isinstance(plaintext, (bytes, bytearray)):
            raise TypeError("plaintext debe ser bytes.")

        # 1. Generar session key AES aleatoria
        session_key = os.urandom(self.SESSION_KEY_SIZE)

        # 2. Cifrar la session key con RSA-OAEP
        encrypted_session_key = self._public_key.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # 3. Cifrar los datos con AES-256-GCM
        nonce = os.urandom(self.NONCE_SIZE)
        aesgcm = AESGCM(session_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        # 4. Empaquetar todo:
        #    [2B: longitud de la clave RSA cifrada][clave RSA cifrada][nonce][ciphertext+tag]
        key_len = struct.pack(">H", len(encrypted_session_key))

        return key_len + encrypted_session_key + nonce + ciphertext

    # ------------------------------------------------------------------
    # Decrypt
    # ------------------------------------------------------------------

    def decrypt(self, data: bytes) -> bytes:
        """
        Descifra un blob cifrado con HybridCipher.encrypt().

        Args:
            data: Blob cifrado.

        Returns:
            Plaintext original.
        """
        if self._private_key is None:
            raise ValueError("Se necesita una clave privada RSA para descifrar.")

        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("data debe ser bytes.")

        # 1. Leer longitud de la session key cifrada
        key_len = struct.unpack(">H", data[:2])[0]
        offset = 2

        # 2. Extraer session key cifrada
        encrypted_session_key = data[offset : offset + key_len]
        offset += key_len

        # 3. Extraer nonce
        nonce = data[offset : offset + self.NONCE_SIZE]
        offset += self.NONCE_SIZE

        # 4. Extraer ciphertext
        ciphertext = data[offset:]

        # 5. Descifrar session key con RSA-OAEP
        session_key = self._private_key.decrypt(
            encrypted_session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # 6. Descifrar datos con AES-256-GCM
        aesgcm = AESGCM(session_key)
        return aesgcm.decrypt(nonce, ciphertext, None)