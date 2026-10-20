# tests/test_fixes.py
#
# Cobertura de las correcciones de integridad (v0.4.x post-auditoria).

import json
import tempfile
from pathlib import Path

import pytest
from click.testing import CliRunner
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from octacrypt.algorithms.aes import AESAlgorithm
from octacrypt.algorithms.hybrid import HybridCipher
from octacrypt.algorithms.signer import Ed25519Signer
from octacrypt.cli.cli import cli
from octacrypt.core.dir_crypto import (
    MANIFEST_NAME,
    decrypt_directory,
    encrypt_directory,
)
from octacrypt.core.messenger import MessageCipher
from octacrypt.utils.hash import scrypt_hash, scrypt_verify


# ─── Messenger: selección de algoritmo simétrico ─────────

@pytest.mark.parametrize("algorithm", ["aes", "chacha20"])
def test_symmetric_algorithm_roundtrip(algorithm):
    msg = b"mensaje para " + algorithm.encode()
    enc = MessageCipher.encrypt_symmetric(msg, "pw", algorithm=algorithm)
    assert enc[:10].rstrip(b"\x00").decode() == algorithm
    assert MessageCipher.decrypt_symmetric(enc, "pw") == msg


def test_symmetric_detects_algorithm_from_prefix():
    enc = MessageCipher.encrypt_symmetric(b"x", "pw", algorithm="chacha20")
    # Debe descifrarse sin indicar el algoritmo
    assert MessageCipher.decrypt_symmetric(enc, "pw") == b"x"


def test_legacy_unprefixed_message_still_decrypts_with_aes():
    # Simular formato antiguo: [16B salt][nonce+ct+tag], sin prefijo
    from octacrypt.utils.kdf import derive_key, generate_salt

    salt = generate_salt()
    key = derive_key("pw", salt)
    payload = salt + AESAlgorithm(key).encrypt(b"viejo")
    assert MessageCipher.decrypt_symmetric(payload, "pw") == b"viejo"


def test_signed_message_without_verifier_raises():
    priv, _ = Ed25519Signer.generate_keypair()
    signer = Ed25519Signer(private_key_pem=priv)
    enc = MessageCipher.encrypt_symmetric(b"firmado", "pw", signer=signer)
    with pytest.raises(ValueError, match="firmado"):
        MessageCipher.decrypt_symmetric(enc, "pw")


# ─── Validaciones de longitud ────────────────────────────

def test_aes_rejects_too_short_data():
    cipher = AESAlgorithm(b"0" * 32)
    with pytest.raises(ValueError):
        cipher.decrypt(b"corto")


def test_hybrid_rejects_truncated_blob():
    cipher = HybridCipher()
    cipher._private_key = object()  # evitar el "no key" antes de la longitud
    with pytest.raises(ValueError):
        cipher.decrypt(b"\x00\x01")


# ─── Directory: sanitización del manifiesto ──────────────

def test_directory_manifest_path_traversal_raises(tmp_path):
    src = tmp_path / "docs"
    src.mkdir()
    (src / "a.txt").write_bytes(b"AAA")
    enc = tmp_path / "docs.enc"
    encrypt_directory(src, enc, key="pw")

    manifest_path = enc / MANIFEST_NAME
    manifest = json.loads(manifest_path.read_text())
    manifest["files"][0]["original"] = "../../evil.txt"
    manifest_path.write_text(json.dumps(manifest))

    with pytest.raises(ValueError):
        decrypt_directory(enc, tmp_path / "out", key="pw")


# ─── scrypt ──────────────────────────────────────────────

def test_scrypt_new_format_and_verify():
    h = scrypt_hash("secreto")
    assert h.startswith("scrypt$")
    assert scrypt_verify("secreto", h)
    assert not scrypt_verify("otra", h)


def test_scrypt_verify_does_not_crash_on_bcrypt_hash():
    from octacrypt.utils.hash import bcrypt_hash

    assert scrypt_verify("secreto", bcrypt_hash("secreto")) is False


# ─── CLI: decrypt hybrid con --password ──────────────────

def _rsa_pems(key_password: bytes | None):
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if key_password:
        enc_alg = serialization.BestAvailableEncryption(key_password)
    else:
        enc_alg = serialization.NoEncryption()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc_alg,
    )
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, pub_pem


def test_cli_decrypt_hybrid_with_password(tmp_path):
    priv_pem, pub_pem = _rsa_pems(b"keypw")
    privf = tmp_path / "priv.pem"
    privf.write_bytes(priv_pem)
    pubf = tmp_path / "pub.pem"
    pubf.write_bytes(pub_pem)

    data = tmp_path / "h.txt"
    data.write_bytes(b"hibrido secreto")
    henc = tmp_path / "h.txt.henc"

    runner = CliRunner()
    r = runner.invoke(cli, ["hybrid-encrypt", str(data), "--pub", str(pubf), "--out", str(henc)])
    assert r.exit_code == 0, r.output

    out = tmp_path / "out.txt"
    r = runner.invoke(
        cli,
        ["decrypt", str(henc), "--alg", "hybrid", "--priv", str(privf),
         "--password", "keypw", "--out", str(out)],
    )
    assert r.exit_code == 0, r.output
    assert out.read_bytes() == b"hibrido secreto"


def test_cli_decrypt_no_traceback_on_wrong_password(tmp_path):
    priv_pem, pub_pem = _rsa_pems(b"keypw")
    privf = tmp_path / "priv.pem"
    privf.write_bytes(priv_pem)
    pubf = tmp_path / "pub.pem"
    pubf.write_bytes(pub_pem)

    data = tmp_path / "h.txt"
    data.write_bytes(b"contenido")
    henc = tmp_path / "h.txt.henc"

    runner = CliRunner()
    runner.invoke(cli, ["hybrid-encrypt", str(data), "--pub", str(pubf), "--out", str(henc)])

    r = runner.invoke(
        cli,
        ["hybrid-decrypt", str(henc), "--priv", str(privf), "--password", "mala",
         "--out", str(tmp_path / "nope.txt")],
    )
    assert r.exit_code != 0
    assert "Traceback" not in r.output


# ─── CLI: msg-encrypt --alg ──────────────────────────────

def test_cli_msg_encrypt_chacha20_roundtrip():
    runner = CliRunner()
    r = runner.invoke(cli, ["msg-encrypt", "hola mundo", "--password", "pw", "--alg", "chacha20"])
    assert r.exit_code == 0, r.output
    b64 = r.output.strip().splitlines()[-1]

    r = runner.invoke(cli, ["msg-decrypt", b64, "--password", "pw"])
    assert r.exit_code == 0, r.output
    assert "hola mundo" in r.output
