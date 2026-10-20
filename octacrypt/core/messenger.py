# octacrypt/core/messenger.py
#
# Cifrado y firma de mensajes (texto o bytes)
# No requiere archivos — ideal para mensajes, strings, payloads.
#
# Modos:
#   - Simétrico: AES-256-GCM o ChaCha20-Poly1305 con KDF (password → key)
#   - Híbrido:   RSA-OAEP + AES-256-GCM (clave pública/privada)
#   - Post-cuántico: ML-KEM + AES-256-GCM (clave pública/privada)
#   - Con firma: cifrado + firma Ed25519 opcional

import base64

from octacrypt.algorithms.aes import AESAlgorithm
from octacrypt.algorithms.chacha import ChaChaAlgorithm
from octacrypt.algorithms.hybrid import HybridCipher
from octacrypt.algorithms.mlkem import MLKEMCipher
from octacrypt.algorithms.signer import Ed25519Signer
from octacrypt.utils.kdf import derive_key, generate_salt

# Separador interno para mensajes firmados
_SIG_SEPARATOR = b"||SIG||"
SALT_SIZE = 16
ALGO_PREFIX_SIZE = 10

_SYMMETRIC_ALGORITHMS = ("aes", "chacha20")


def _make_cipher(algorithm: str, key: bytes):
    if algorithm == "aes":
        return AESAlgorithm(key)
    if algorithm == "chacha20":
        return ChaChaAlgorithm(key)
    raise ValueError(
        f"Algoritmo no soportado: '{algorithm}'. Disponibles: {list(_SYMMETRIC_ALGORITHMS)}"
    )


def _split_signed_payload(data: bytes, verifier: Ed25519Signer | None) -> bytes:
    """
    Separa la firma Ed25519 del payload si el mensaje está firmado.

    Si el mensaje lleva firma y no se proporciona verificador, lanza
    ValueError: nunca se debe ignorar una firma en silencio.
    """
    if _SIG_SEPARATOR not in data:
        return data

    payload, signature = data.split(_SIG_SEPARATOR, 1)
    if verifier is None:
        raise ValueError(
            "El mensaje está firmado pero no se proporcionó clave pública "
            "de verificación. Usa --verify-pub (CLI) para verificar la firma."
        )
    if not verifier.verify(payload, signature):
        raise ValueError("❌ Firma inválida — mensaje comprometido.")
    return payload


class MessageCipher:
    """
    Cifrado de mensajes de texto o bytes.

    Soporta:
      - Modo simétrico (password): AES-256-GCM o ChaCha20-Poly1305
      - Modo híbrido (RSA)
      - Modo post-cuántico (ML-KEM)
      - Firma Ed25519 opcional en todos los modos

    Todos los outputs son bytes crudos.
    Usa to_base64() / from_base64() para texto imprimible.
    """

    # ------------------------------------------------------------------
    # Simétrico: password → AES-256-GCM / ChaCha20-Poly1305
    # ------------------------------------------------------------------

    @staticmethod
    def encrypt_symmetric(
        message: bytes | str,
        password: str,
        signer: Ed25519Signer | None = None,
        algorithm: str = "aes",
    ) -> bytes:
        """
        Cifra un mensaje derivando la key desde un password.

        Formato: [10B prefijo algoritmo][16B salt][12B nonce][ciphertext+tag]
        Si signer: [datos_cifrados][_SIG_SEPARATOR][64B firma]

        Args:
            message:   Texto o bytes a cifrar.
            password:  Contraseña (se deriva con PBKDF2).
            signer:    Ed25519Signer opcional para firmar el ciphertext.
            algorithm: "aes" (AES-256-GCM) o "chacha20" (ChaCha20-Poly1305).
        """
        if isinstance(message, str):
            message = message.encode()

        salt = generate_salt()
        key = derive_key(password, salt)
        cipher = _make_cipher(algorithm, key)
        encrypted = cipher.encrypt(message)

        algo_prefix = algorithm.encode().ljust(ALGO_PREFIX_SIZE, b"\x00")
        payload = algo_prefix + salt + encrypted

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

        El algoritmo se determina automáticamente desde el prefijo del
        mensaje (formato v0.4+). Los mensajes en formato antiguo
        ([16B salt][nonce][ciphertext], sin prefijo) se descifran con AES.

        Args:
            data:     Bytes cifrados.
            password: Contraseña original.
            verifier: Ed25519Signer con clave pública para verificar firma.

        Raises:
            ValueError: Si la firma es inválida o falta el verificador.
        """
        payload = _split_signed_payload(data, verifier)

        prefix = payload[:ALGO_PREFIX_SIZE].rstrip(b"\x00").decode(errors="replace")
        if prefix in _SYMMETRIC_ALGORITHMS:
            algorithm = prefix
            salt = payload[ALGO_PREFIX_SIZE : ALGO_PREFIX_SIZE + SALT_SIZE]
            encrypted = payload[ALGO_PREFIX_SIZE + SALT_SIZE :]
        else:
            # Compatibilidad con formato antiguo: sin prefijo, siempre AES
            algorithm = "aes"
            salt = payload[:SALT_SIZE]
            encrypted = payload[SALT_SIZE:]

        if len(salt) != SALT_SIZE:
            raise ValueError("Mensaje corrupto: salt inválido.")

        key = derive_key(password, salt)
        cipher = _make_cipher(algorithm, key)
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
            ValueError: Si la firma es inválida o falta el verificador.
        """
        payload = _split_signed_payload(data, verifier)

        cipher = HybridCipher(
            private_key_pem=private_key_pem,
            private_key_password=private_key_password,
        )
        return cipher.decrypt(payload)

    # ------------------------------------------------------------------
    # Post-cuántico: ML-KEM + AES-256-GCM
    # ------------------------------------------------------------------

    @staticmethod
    def encrypt_pq(
        message: bytes | str,
        public_key_pem: bytes,
        signer: Ed25519Signer | None = None,
    ) -> bytes:
        """
        Cifra un mensaje con cifrado híbrido ML-KEM + AES-256-GCM (post-cuántico).

        Args:
            message:        Texto o bytes a cifrar.
            public_key_pem: Clave pública ML-KEM en PEM.
            signer:         Ed25519Signer opcional para firmar.
        """
        if isinstance(message, str):
            message = message.encode()

        cipher = MLKEMCipher(public_key_pem=public_key_pem)
        payload = cipher.encrypt(message)

        if signer:
            signature = signer.sign(payload)
            payload = payload + _SIG_SEPARATOR + signature

        return payload

    @staticmethod
    def decrypt_pq(
        data: bytes,
        private_key_pem: bytes,
        private_key_password: bytes | None = None,
        verifier: Ed25519Signer | None = None,
    ) -> bytes:
        """
        Descifra un mensaje cifrado con encrypt_pq.

        Args:
            data:                 Bytes cifrados.
            private_key_pem:      Clave privada ML-KEM en PEM.
            private_key_password: Contraseña de la clave privada (si aplica).
            verifier:             Ed25519Signer con clave pública para verificar.

        Raises:
            ValueError: Si la firma es inválida o falta el verificador.
        """
        payload = _split_signed_payload(data, verifier)

        cipher = MLKEMCipher(
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
