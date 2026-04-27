# octacrypt/algorithms/signer.py
#
# Firmas digitales con Ed25519
#
# Ed25519 es el estándar moderno para firmas digitales:
#   - Rápido, seguro, claves pequeñas (32 bytes)
#   - Resistente a ataques de canal lateral
#   - Usado en SSH, TLS 1.3, Signal, etc.
#
# Formato de firma: raw bytes (64 bytes)

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
)
from cryptography.exceptions import InvalidSignature


class Ed25519Signer:
    """
    Firma y verificación de mensajes/archivos con Ed25519.

    Uso para firmar (necesita clave privada):
        signer = Ed25519Signer(private_key_pem=pem_bytes)
        signature = signer.sign(data)

    Uso para verificar (solo necesita clave pública):
        verifier = Ed25519Signer(public_key_pem=pem_bytes)
        valid = verifier.verify(data, signature)
    """

    def __init__(
        self,
        private_key_pem: bytes | None = None,
        public_key_pem: bytes | None = None,
        private_key_password: bytes | None = None,
    ):
        self._private_key = None
        self._public_key = None

        if private_key_pem:
            self._private_key = load_pem_private_key(
                private_key_pem,
                password=private_key_password,
            )
            # Derivar clave pública automáticamente
            self._public_key = self._private_key.public_key()

        if public_key_pem:
            self._public_key = load_pem_public_key(public_key_pem)

    # ------------------------------------------------------------------
    # Generación de claves
    # ------------------------------------------------------------------

    @staticmethod
    def generate_keypair() -> tuple[bytes, bytes]:
        """
        Genera un par de claves Ed25519.

        Returns:
            (private_key_pem, public_key_pem) como bytes PEM.
        """
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        private_pem = private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption(),
        )
        public_pem = public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo,
        )
        return private_pem, public_pem

    # ------------------------------------------------------------------
    # Sign
    # ------------------------------------------------------------------

    def sign(self, data: bytes) -> bytes:
        """
        Firma datos con la clave privada Ed25519.

        Args:
            data: Datos a firmar (cualquier tamaño).

        Returns:
            Firma de 64 bytes.

        Raises:
            ValueError: Si no hay clave privada cargada.
        """
        if self._private_key is None:
            raise ValueError("Se necesita una clave privada Ed25519 para firmar.")

        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("Los datos deben ser bytes.")

        return self._private_key.sign(data)

    # ------------------------------------------------------------------
    # Verify
    # ------------------------------------------------------------------

    def verify(self, data: bytes, signature: bytes) -> bool:
        """
        Verifica una firma Ed25519.

        Args:
            data:      Datos originales.
            signature: Firma de 64 bytes.

        Returns:
            True si la firma es válida, False si no.

        Raises:
            ValueError: Si no hay clave pública cargada.
        """
        if self._public_key is None:
            raise ValueError("Se necesita una clave pública Ed25519 para verificar.")

        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("Los datos deben ser bytes.")

        if not isinstance(signature, (bytes, bytearray)):
            raise TypeError("La firma debe ser bytes.")

        try:
            self._public_key.verify(signature, data)
            return True
        except InvalidSignature:
            return False