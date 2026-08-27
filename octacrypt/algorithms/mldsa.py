# octacrypt/algorithms/mldsa.py
#
# Firmas digitales post-cuánticas con ML-DSA (FIPS 204)
#
# ML-DSA (Module-Lattice Digital Signature Algorithm, antes CRYSTALS-Dilithium)
# es el estándar NIST FIPS 204 para firmas digitales resistente a
# computadoras cuánticas. Reemplaza a Ed25519/ECDSA en escenarios post-cuánticos.
#
# Formato de firma: bytes crudos de longitud variable según la variante.

from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
)
from cryptography.exceptions import InvalidSignature

# Importación del submódulo (no re-exportado en `asymmetric/__init__`).
from cryptography.hazmat.primitives.asymmetric import mldsa

# Variantes oficiales de ML-DSA (NIST FIPS 204).
# ML-DSA-44: ~128 bits | ML-DSA-65: ~192 bits (recomendado)
# ML-DSA-87: ~256 bits (máximo)
MLDSA_VARIANTS = {
    "mldsa44": {
        "private_key_class": mldsa.MLDSA44PrivateKey,
        "public_key_class": mldsa.MLDSA44PublicKey,
        "description": "ML-DSA-44 (~128 bits)",
        "security_level": 128,
    },
    "mldsa65": {
        "private_key_class": mldsa.MLDSA65PrivateKey,
        "public_key_class": mldsa.MLDSA65PublicKey,
        "description": "ML-DSA-65 (~192 bits, recomendado)",
        "security_level": 192,
    },
    "mldsa87": {
        "private_key_class": mldsa.MLDSA87PrivateKey,
        "public_key_class": mldsa.MLDSA87PublicKey,
        "description": "ML-DSA-87 (~256 bits, máximo)",
        "security_level": 256,
    },
}


class MLDSASigner:
    """
    Firma y verificación de mensajes/archivos con ML-DSA.

    Uso para firmar (necesita clave privada):
        signer = MLDSASigner(private_key_pem=pem_bytes)
        signature = signer.sign(data)

    Uso para verificar (solo necesita clave pública):
        verifier = MLDSASigner(public_key_pem=pem_bytes)
        valid = verifier.verify(data, signature)
    """

    def __init__(
        self,
        private_key_pem: bytes | None = None,
        public_key_pem: bytes | None = None,
        private_key_password: bytes | None = None,
        variant: str | None = None,
    ):
        self._private_key = None
        self._public_key = None
        self.variant = variant

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
    def generate_keypair(variant: str = "mldsa65") -> tuple[bytes, bytes]:
        """
        Genera un par de claves ML-DSA.

        Args:
            variant: "mldsa44", "mldsa65" (recomendado) o "mldsa87".

        Returns:
            (private_key_pem, public_key_pem) como bytes PEM.
        """
        if variant not in MLDSA_VARIANTS:
            raise ValueError(
                f"Variante ML-DSA no soportada: '{variant}'. "
                f"Disponibles: {list(MLDSA_VARIANTS.keys())}"
            )

        private_key_class = MLDSA_VARIANTS[variant]["private_key_class"]
        private_key = private_key_class.generate()

        private_pem = private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption(),
        )
        public_pem = private_key.public_key().public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo,
        )
        return private_pem, public_pem

    # ------------------------------------------------------------------
    # Sign
    # ------------------------------------------------------------------

    def sign(self, data: bytes) -> bytes:
        """
        Firma datos con la clave privada ML-DSA.

        Args:
            data: Datos a firmar (cualquier tamaño).

        Returns:
            Firma en bytes crudos.

        Raises:
            ValueError: Si no hay clave privada cargada.
        """
        if self._private_key is None:
            raise ValueError("Se necesita una clave privada ML-DSA para firmar.")

        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("Los datos deben ser bytes.")

        return self._private_key.sign(data)

    # ------------------------------------------------------------------
    # Verify
    # ------------------------------------------------------------------

    def verify(self, data: bytes, signature: bytes) -> bool:
        """
        Verifica una firma ML-DSA.

        Args:
            data:      Datos originales.
            signature: Firma en bytes crudos.

        Returns:
            True si la firma es válida, False si no.

        Raises:
            ValueError: Si no hay clave pública cargada.
        """
        if self._public_key is None:
            raise ValueError("Se necesita una clave pública ML-DSA para verificar.")

        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("Los datos deben ser bytes.")

        if not isinstance(signature, (bytes, bytearray)):
            raise TypeError("La firma debe ser bytes.")

        try:
            self._public_key.verify(signature, data)
            return True
        except InvalidSignature:
            return False
