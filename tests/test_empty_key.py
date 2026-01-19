import pytest
from octacrypt.core.crypto_engine import CryptoEngine


def test_empty_key():
    with pytest.raises(ValueError):
        CryptoEngine(
            algorithm="xor",
            key=b""
        )