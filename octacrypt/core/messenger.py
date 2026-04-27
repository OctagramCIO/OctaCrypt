# octacrypt/core/messenger.py
#
# Cifrado y firma de mensajes (texto o bytes)
# No requiere archivos — ideal para mensajes, strings, payloads.
#
# Modos:
#   - Simétrico: AES-256-GCM con KDF (password → key)
#   - Híbrido:   RSA-OAEP + AES-256-GCM (clave pública/privada)
#   - Con firma: cifrado + firma Ed25519 opcional

import base64

from octacrypt.algorithms.aes import AESAlgorithm
from octacrypt.algorithms.hybrid import HybridCipher
from octacrypt.algorithms.signer import Ed25519Signer
from octacrypt.utils.kdf import derive_key, generate_salt

# Separador interno para mensajes firmados
_SIG_SEPARATOR = b"||SIG||"
SALT_SIZE = 16


class MessageCipher:
    """
    Cifrado de mensajes de texto o bytes.

    Soporta:
      - Modo simétrico (password)
      - Modo híbrido (RSA)
      - Firma Ed25519 opcional en ambos modos

    Todos los outputs son bytes crudos.
    Usa to_base64() / from_base64() para texto imprimible.
    """

    # ------------------------------------------------------------------
    # Simétrico: password → AES-256-GCM
    # ------------------------------------------------------------------

    @staticmethod
    def encrypt_symmetric(
        message: bytes | str,
        password: str,
        signer: Ed25519Signer | None = None,
    ) -> bytes:
        """
        Cifra un mensaje con AES-256-GCM derivando la key desde un password.

        Formato: [16B salt][12B nonce][ciphertext+tag]
        Si signer: [datos_cifrados][_SIG_SEPARATOR][64B firma]

        Args:
            message:  Texto o bytes a cifrar.
            password: Contraseña (se deriva con PBKDF2).
            signer:   Ed25519Signer opcional para firmar el ciphertext.
        """
        if isinstance(message, str):
            message = message.encode()

        salt = generate_salt()
        key = derive_key(password, salt)
        cipher = AESAlgorithm(key)
        encrypted = cipher.encrypt(message)

        payload = salt + encrypted

        if signer:
            signature = signer.sign(payload)
            payload = payload + _SIG_SEPARATOR + signature

        return payload

    @staticmethod
    def decrypt_symmetric(
        data: bytes,
        password: str,
        verifier: Ed25519Signer | None = None,
    ) -> bytes:
        """
        Descifra un mensaje cifrado con encrypt_symmetric.

        Args:
            data:     Bytes cifrados.
            password: Contraseña original.
            verifier: Ed25519Signer con clave pública para verificar firma.

        Raises:
            ValueError: Si la firma es inválida.
        """
        # Separar firma si existe
        if _SIG_SEPARATOR in data:
            payload, signature = data.split(_SIG_SEPARATOR, 1)
            if verifier:
                if not verifier.verify(payload, signature):
                    raise ValueError("❌ Firma inválida — mensaje comprometido.")
        else:
            payload = data

        salt = payload[:SALT_SIZE]
        encrypted = payload[SALT_SIZE:]

        key = derive_key(password, salt)
        cipher = AESAlgorithm(key)
        return cipher.decrypt(encrypted)

    # ------------------------------------------------------------------
    # Híbrido: RSA + AES-256-GCM
    # ------------------------------------------------------------------

    @staticmethod
    def encrypt_hybrid(
        message: bytes | str,
        public_key_pem: bytes,
        signer: Ed25519Signer | None = None,
    ) -> bytes:
        """
        Cifra un mensaje con cifrado híbrido RSA-OAEP + AES-256-GCM.

        Args:
            message:        Texto o bytes a cifrar.
            public_key_pem: Clave pública RSA en PEM.
            signer:         Ed25519Signer opcional para firmar.
        """
        if isinstance(message, str):
            message = message.encode()

        cipher = HybridCipher(public_key_pem=public_key_pem)
        payload = cipher.encrypt(message)

        if signer:
            signature = signer.sign(payload)
            payload = payload + _SIG_SEPARATOR + signature

        return payload

    @staticmethod
    def decrypt_hybrid(
        data: bytes,
        private_key_pem: bytes,
        private_key_password: bytes | None = None,
        verifier: Ed25519Signer | None = None,
    ) -> bytes:
        """
        Descifra un mensaje cifrado con encrypt_hybrid.

        Args:
            data:                 Bytes cifrados.
            private_key_pem:      Clave privada RSA en PEM.
            private_key_password: Contraseña de la clave privada (si aplica).
            verifier:             Ed25519Signer con clave pública para verificar.

        Raises:
            ValueError: Si la firma es inválida.
        """
        if _SIG_SEPARATOR in data:
            payload, signature = data.split(_SIG_SEPARATOR, 1)
            if verifier:
                if not verifier.verify(payload, signature):
                    raise ValueError("❌ Firma inválida — mensaje comprometido.")
        else:
            payload = data

        cipher = HybridCipher(
            private_key_pem=private_key_pem,
            private_key_password=private_key_password,
        )
        return cipher.decrypt(payload)

    # ------------------------------------------------------------------
    # Helpers: base64
    # ------------------------------------------------------------------

    @staticmethod
    def to_base64(data: bytes) -> str:
        """Convierte bytes cifrados a string base64 imprimible."""
        return base64.b64encode(data).decode()

    @staticmethod
    def from_base64(text: str) -> bytes:
        """Convierte string base64 de vuelta a bytes."""
        return base64.b64decode(text.encode())