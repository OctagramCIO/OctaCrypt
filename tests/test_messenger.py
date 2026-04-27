# tests/test_messenger.py

import pytest
from octacrypt.core.messenger import MessageCipher
from octacrypt.algorithms.signer import Ed25519Signer
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


@pytest.fixture(scope="module")
def rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


@pytest.fixture(scope="module")
def ed25519_keypair():
    return Ed25519Signer.generate_keypair()


# ─── Simétrico ───────────────────────────────────────────

def test_symmetric_encrypt_decrypt():
    msg = b"Mensaje secreto de Octagram"
    password = "supersecreta123"

    encrypted = MessageCipher.encrypt_symmetric(msg, password)
    decrypted = MessageCipher.decrypt_symmetric(encrypted, password)

    assert decrypted == msg


def test_symmetric_string_input():
    msg = "Texto como string"
    password = "clave"

    encrypted = MessageCipher.encrypt_symmetric(msg, password)
    decrypted = MessageCipher.decrypt_symmetric(encrypted, password)

    assert decrypted == msg.encode()


def test_symmetric_wrong_password_raises():
    encrypted = MessageCipher.encrypt_symmetric(b"secreto", "correcta")
    with pytest.raises(Exception):
        MessageCipher.decrypt_symmetric(encrypted, "incorrecta")


def test_symmetric_with_signature(ed25519_keypair):
    private_pem, public_pem = ed25519_keypair
    signer = Ed25519Signer(private_key_pem=private_pem)
    verifier = Ed25519Signer(public_key_pem=public_pem)

    msg = b"mensaje firmado"
    encrypted = MessageCipher.encrypt_symmetric(msg, "pw", signer=signer)
    decrypted = MessageCipher.decrypt_symmetric(encrypted, "pw", verifier=verifier)

    assert decrypted == msg


def test_symmetric_tampered_signature_raises(ed25519_keypair):
    _, public_pem = ed25519_keypair
    _, other_public_pem = Ed25519Signer.generate_keypair()

    # Firmar con una clave, verificar con otra → debe fallar
    private_pem, _ = ed25519_keypair
    signer = Ed25519Signer(private_key_pem=private_pem)
    wrong_verifier = Ed25519Signer(public_key_pem=other_public_pem)

    encrypted = MessageCipher.encrypt_symmetric(b"test", "pw", signer=signer)
    with pytest.raises(ValueError, match="Firma inválida"):
        MessageCipher.decrypt_symmetric(encrypted, "pw", verifier=wrong_verifier)


# ─── Híbrido ─────────────────────────────────────────────

def test_hybrid_encrypt_decrypt(rsa_keypair):
    private_pem, public_pem = rsa_keypair
    msg = b"Mensaje hibrido RSA + AES"

    encrypted = MessageCipher.encrypt_hybrid(msg, public_pem)
    decrypted = MessageCipher.decrypt_hybrid(encrypted, private_pem)

    assert decrypted == msg


def test_hybrid_with_signature(rsa_keypair, ed25519_keypair):
    private_pem, public_pem = rsa_keypair
    sign_priv, sign_pub = ed25519_keypair

    signer = Ed25519Signer(private_key_pem=sign_priv)
    verifier = Ed25519Signer(public_key_pem=sign_pub)

    msg = b"cifrado y firmado"
    encrypted = MessageCipher.encrypt_hybrid(msg, public_pem, signer=signer)
    decrypted = MessageCipher.decrypt_hybrid(encrypted, private_pem, verifier=verifier)

    assert decrypted == msg


# ─── Base64 ──────────────────────────────────────────────

def test_base64_roundtrip():
    data = b"\x00\x01\x02\xff\xfe"
    b64 = MessageCipher.to_base64(data)
    assert isinstance(b64, str)
    assert MessageCipher.from_base64(b64) == data