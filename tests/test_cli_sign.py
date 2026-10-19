# tests/test_cli_sign.py
#
# CLI de firma con claves protegidas por password.

from click.testing import CliRunner

from octacrypt.algorithms.signer import Ed25519Signer
from octacrypt.cli.message import msg_decrypt, msg_encrypt
from octacrypt.cli.sign import sign, verify
from octacrypt.utils.keygen import generate_ed25519, save_keys


def _encrypted_key(tmp_path):
    key = generate_ed25519()
    priv, pub = save_keys(key, str(tmp_path / "signkey"), password="secreto")
    return priv, pub


def test_sign_with_encrypted_key_and_password(tmp_path):
    priv, pub = _encrypted_key(tmp_path)
    archivo = tmp_path / "doc.txt"
    archivo.write_text("contenido")

    result = CliRunner().invoke(
        sign,
        [str(archivo), "--priv", priv, "--password", "secreto"],
    )
    assert result.exit_code == 0, result.output
    sig_path = tmp_path / "doc.txt.sig"
    assert sig_path.exists()

    result = CliRunner().invoke(
        verify,
        [str(archivo), "--pub", pub, "--sig", str(sig_path)],
    )
    assert result.exit_code == 0, result.output


def test_sign_encrypted_key_without_password_fails(tmp_path):
    priv, _ = _encrypted_key(tmp_path)
    archivo = tmp_path / "doc.txt"
    archivo.write_text("contenido")

    result = CliRunner().invoke(sign, [str(archivo), "--priv", priv])
    assert result.exit_code != 0


def test_sign_wrong_password_fails(tmp_path):
    priv, _ = _encrypted_key(tmp_path)
    archivo = tmp_path / "doc.txt"
    archivo.write_text("contenido")

    result = CliRunner().invoke(
        sign,
        [str(archivo), "--priv", priv, "--password", "incorrecta"],
    )
    assert result.exit_code != 0


def test_sign_without_password_on_plain_key(tmp_path):
    key = generate_ed25519()
    priv, pub = save_keys(key, str(tmp_path / "plain"))
    archivo = tmp_path / "doc.txt"
    archivo.write_text("contenido")

    result = CliRunner().invoke(sign, [str(archivo), "--priv", priv])
    assert result.exit_code == 0, result.output


def test_msg_encrypt_with_sign_password(tmp_path):
    priv, pub = _encrypted_key(tmp_path)

    result = CliRunner().invoke(
        msg_encrypt,
        ["hola", "--password", "pw", "--sign-priv", priv, "--sign-password", "secreto"],
    )
    assert result.exit_code == 0, result.output
    b64 = result.output.strip().splitlines()[-1]

    result = CliRunner().invoke(
        msg_decrypt,
        [b64, "--password", "pw", "--verify-pub", pub],
    )
    assert result.exit_code == 0, result.output
    assert "hola" in result.output


def test_msg_encrypt_encrypted_sign_key_without_password_fails(tmp_path):
    priv, _ = _encrypted_key(tmp_path)

    result = CliRunner().invoke(
        msg_encrypt,
        ["hola", "--password", "pw", "--sign-priv", priv],
    )
    assert result.exit_code != 0


def test_ed25519_signer_accepts_password(tmp_path):
    priv, _ = _encrypted_key(tmp_path)
    signer = Ed25519Signer(
        private_key_pem=open(priv, "rb").read(),
        private_key_password=b"secreto",
    )
    assert len(signer.sign(b"datos")) == 64
