# tests/test_signer.py

import pytest
from octacrypt.algorithms.signer import Ed25519Signer


@pytest.fixture(scope="module")
def keypair():
    private_pem, public_pem = Ed25519Signer.generate_keypair()
    return private_pem, public_pem


def test_sign_and_verify(keypair):
    private_pem, public_pem = keypair
    signer = Ed25519Signer(private_key_pem=private_pem)
    verifier = Ed25519Signer(public_key_pem=public_pem)

    data = b"OctaCrypt firma esto"
    signature = signer.sign(data)

    assert verifier.verify(data, signature) is True


def test_tampered_data_fails(keypair):
    private_pem, public_pem = keypair
    signer = Ed25519Signer(private_key_pem=private_pem)
    verifier = Ed25519Signer(public_key_pem=public_pem)

    data = b"mensaje original"
    signature = signer.sign(data)

    assert verifier.verify(b"mensaje alterado", signature) is False


def test_wrong_key_fails(keypair):
    private_pem, _ = keypair
    _, other_public_pem = Ed25519Signer.generate_keypair()

    signer = Ed25519Signer(private_key_pem=private_pem)
    verifier = Ed25519Signer(public_key_pem=other_public_pem)

    data = b"datos"
    signature = signer.sign(data)

    assert verifier.verify(data, signature) is False


def test_sign_without_private_key_raises():
    signer = Ed25519Signer()
    with pytest.raises(ValueError):
        signer.sign(b"test")


def test_verify_without_public_key_raises():
    signer = Ed25519Signer()
    with pytest.raises(ValueError):
        signer.verify(b"test", b"fakesig" * 9)


def test_private_key_auto_derives_public(keypair):
    """Con solo la clave privada, también se puede verificar."""
    private_pem, _ = keypair
    signer = Ed25519Signer(private_key_pem=private_pem)

    data = b"auto derive test"
    signature = signer.sign(data)

    assert signer.verify(data, signature) is True


def test_large_data(keypair):
    private_pem, public_pem = keypair
    signer = Ed25519Signer(private_key_pem=private_pem)
    verifier = Ed25519Signer(public_key_pem=public_pem)

    data = b"X" * 10_000_000  # 10 MB
    signature = signer.sign(data)

    assert verifier.verify(data, signature) is True