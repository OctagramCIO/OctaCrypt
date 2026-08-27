# tests/test_mldsa.py

import pytest
from octacrypt.algorithms.mldsa import MLDSASigner


@pytest.fixture(scope="module")
def keypair():
    private_pem, public_pem = MLDSASigner.generate_keypair(variant="mldsa65")
    return private_pem, public_pem


def test_sign_and_verify(keypair):
    private_pem, public_pem = keypair
    signer = MLDSASigner(private_key_pem=private_pem)
    verifier = MLDSASigner(public_key_pem=public_pem)

    data = b"OctaCrypt firma esto post-cuanticamente"
    signature = signer.sign(data)

    assert verifier.verify(data, signature) is True


def test_tampered_data_fails(keypair):
    private_pem, public_pem = keypair
    signer = MLDSASigner(private_key_pem=private_pem)
    verifier = MLDSASigner(public_key_pem=public_pem)

    data = b"mensaje original"
    signature = signer.sign(data)

    assert verifier.verify(b"mensaje alterado", signature) is False


def test_tampered_signature_fails(keypair):
    private_pem, public_pem = keypair
    signer = MLDSASigner(private_key_pem=private_pem)
    verifier = MLDSASigner(public_key_pem=public_pem)

    data = b"datos"
    signature = bytearray(signer.sign(data))
    signature[len(signature) // 2] ^= 0xFF

    assert verifier.verify(data, bytes(signature)) is False


def test_wrong_key_fails(keypair):
    private_pem, _ = keypair
    _, other_public_pem = MLDSASigner.generate_keypair(variant="mldsa65")

    signer = MLDSASigner(private_key_pem=private_pem)
    verifier = MLDSASigner(public_key_pem=other_public_pem)

    data = b"datos"
    signature = signer.sign(data)

    assert verifier.verify(data, signature) is False


def test_sign_without_private_key_raises():
    signer = MLDSASigner()
    with pytest.raises(ValueError):
        signer.sign(b"test")


def test_verify_without_public_key_raises():
    signer = MLDSASigner()
    with pytest.raises(ValueError):
        signer.verify(b"test", b"\x00" * 2000)


def test_private_key_auto_derives_public(keypair):
    """Con solo la clave privada, también se puede verificar."""
    private_pem, _ = keypair
    signer = MLDSASigner(private_key_pem=private_pem)

    data = b"auto derive test"
    signature = signer.sign(data)

    assert signer.verify(data, signature) is True


def test_large_data(keypair):
    private_pem, public_pem = keypair
    signer = MLDSASigner(private_key_pem=private_pem)
    verifier = MLDSASigner(public_key_pem=public_pem)

    data = b"X" * 10_000_000  # 10 MB
    signature = signer.sign(data)

    assert verifier.verify(data, signature) is True


def test_mldsa44_and_87_roundtrip():
    for variant in ("mldsa44", "mldsa65", "mldsa87"):
        private_pem, public_pem = MLDSASigner.generate_keypair(variant=variant)
        signer = MLDSASigner(private_key_pem=private_pem)
        verifier = MLDSASigner(public_key_pem=public_pem)

        data = f"mensaje firmado con {variant}".encode()
        assert verifier.verify(data, signer.sign(data)) is True


def test_invalid_variant_raises():
    with pytest.raises(ValueError):
        MLDSASigner.generate_keypair(variant="mldsa9000")


def test_generated_keys_are_pem(keypair):
    private_pem, public_pem = keypair

    assert b"PRIVATE KEY" in private_pem
    assert b"PUBLIC KEY" in public_pem