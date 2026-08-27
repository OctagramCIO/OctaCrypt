# octacrypt/algorithms/mlkem.py
#
# Cifrado híbrido post-cuántico: ML-KEM (FIPS 203) + AES-256-GCM
#
# ML-KEM (Módulo-Lattice Key Encapsulation Mechanism, antes CRYSTALS-Kyber)
# es el estándar NIST FIPS 203 para intercambio de claves resistente a
# computadoras cuánticas. Reemplaza a RSA/X25519 en el paso de envoltura
# de la session key.
#
# Formato del mensaje cifrado (idéntico a HybridCipher, RSA + AES):
#   [2 bytes: tamaño del ciphertext ML-KEM] [ciphertext KEM] [nonce 12 bytes] [ciphertext + tag GCM]
#
# Flujo:
#   Encrypt: encapsula una session key AES con la clave pública → cifra datos con AES-GCM
#   Decrypt: desencapsula la session key con la clave privada → descifra datos con AES-GCM

import os
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)

# Importación del submódulo (no re-exportado en `asymmetric/__init__`).
from cryptography.hazmat.primitives.asymmetric import mlkem

# Variantes oficiales de ML-KEM (NIST FIPS 203).
# ML-KEM-768: recomendado por NIST para uso general (~192 bits de seguridad)
# ML-KEM-1024: máximo nivel (~256 bits de seguridad)
MLKEM_VARIANTS = {
    "mlkem768": {
        "private_key_class": mlkem.MLKEM768PrivateKey,
        "public_key_class": mlkem.MLKEM768PublicKey,
        "description": "ML-KEM-768 (~192 bits, recomendado)",
        "security_level": 192,
    },
    "mlkem1024": {
        "private_key_class": mlkem.MLKEM1024PrivateKey,
        "public_key_class": mlkem.MLKEM1024PublicKey,
        "description": "ML-KEM-1024 (~256 bits, máximo)",
        "security_level": 256,
    },
}


class MLKEMCipher:
    """
    Cifrado híbrido post-cuántico ML-KEM + AES-256-GCM.

    Para cifrar se usa la clave pública ML-KEM (encapsulación de la
    session key). Para descifrar se usa la clave privada ML-KEM.

    El secreto compartido derivado por el KEM es de 32 bytes (AES-256).
    """

    SESSION_KEY_SIZE = 32   # AES-256 (tamaño del secreto compartido ML-KEM)
    NONCE_SIZE = 12         # GCM estándar

    def __init__(
        self,
        public_key_pem: bytes | None = None,
        private_key_pem: bytes | None = None,
        private_key_password: bytes | None = None,
        variant: str = "mlkem768",
    ):
        """
        Args:
            public_key_pem:       Clave pública ML-KEM en formato PEM (para cifrar).
            private_key_pem:      Clave privada ML-KEM en formato PEM (para descifrar).
            private_key_password: Contraseña de la clave privada (si está cifrada).
            variant:              Variante ML-KEM ("mlkem768" o "mlkem1024"). Solo se usa
                                  al generar un par de claves nuevo.
        """
        if variant not in MLKEM_VARIANTS:
            raise ValueError(
                f"Variante ML-KEM no soportada: '{variant}'. "
                f"Disponibles: {list(MLKEM_VARIANTS.keys())}"
            )

        self.variant = variant
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
    # Generación de claves
    # ------------------------------------------------------------------

    @staticmethod
    def generate_keypair(variant: str = "mlkem768") -> tuple[bytes, bytes]:
        """
        Genera un par de claves ML-KEM.

        Args:
            variant: "mlkem768" (recomendado) o "mlkem1024".

        Returns:
            (private_key_pem, public_key_pem) como bytes PEM.
        """
        if variant not in MLKEM_VARIANTS:
            raise ValueError(
                f"Variante ML-KEM no soportada: '{variant}'. "
                f"Disponibles: {list(MLKEM_VARIANTS.keys())}"
            )

        private_key_class = MLKEM_VARIANTS[variant]["private_key_class"]
        private_key = private_key_class.generate()
        public_key = private_key.public_key()

        from cryptography.hazmat.primitives import serialization

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return private_pem, public_pem

    # ------------------------------------------------------------------
    # Encrypt
    # ------------------------------------------------------------------

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Cifra datos con cifrado híbrido ML-KEM + AES-GCM.

        Args:
            plaintext: Datos a cifrar (cualquier tamaño).

        Returns:
            Blob cifrado con formato:
            [2B ciphertext_len][ciphertext KEM][12B nonce][ciphertext+tag]
        """
        if self._public_key is None:
            raise ValueError("Se necesita una clave pública ML-KEM para cifrar.")

        if not isinstance(plaintext, (bytes, bytearray)):
            raise TypeError("plaintext debe ser bytes.")

        # 1. Encapsular una session key AES con ML-KEM
        session_key, kem_ciphertext = self._public_key.encapsulate()

        # 2. Cifrar los datos con AES-256-GCM
        nonce = os.urandom(self.NONCE_SIZE)
        aesgcm = AESGCM(session_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        # 3. Empaquetar todo:
        #    [2B: longitud del ciphertext KEM][ciphertext KEM][nonce][ciphertext+tag]
        kem_len = struct.pack(">H", len(kem_ciphertext))

        return kem_len + kem_ciphertext + nonce + ciphertext

    # ------------------------------------------------------------------
    # Decrypt
    # ------------------------------------------------------------------

    def decrypt(self, data: bytes) -> bytes:
        """
        Descifra un blob cifrado con MLKEMCipher.encrypt().

        Args:
            data: Blob cifrado.

        Returns:
            Plaintext original.

        Raises:
            InvalidTag: Si la decapsulación o el tag GCM fallan (datos manipulados
                        o clave incorrecta).
        """
        if self._private_key is None:
            raise ValueError("Se necesita una clave privada ML-KEM para descifrar.")

        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("data debe ser bytes.")

        # 1. Leer longitud del ciphertext KEM
        kem_len = struct.unpack(">H", data[:2])[0]
        offset = 2

        # 2. Extraer ciphertext KEM
        kem_ciphertext = data[offset : offset + kem_len]
        offset += kem_len

        # 3. Extraer nonce
        nonce = data[offset : offset + self.NONCE_SIZE]
        offset += self.NONCE_SIZE

        # 4. Extraer ciphertext
        ciphertext = data[offset:]

        # 5. Desencapsular la session key con ML-KEM
        session_key = self._private_key.decapsulate(kem_ciphertext)

        # 6. Descifrar datos con AES-256-GCM
        aesgcm = AESGCM(session_key)
        return aesgcm.decrypt(nonce, ciphertext, None)
