import pytest
from octacrypt.core.crypto_engine import CryptoEngine

def test_invalid_algorithm():
    with pytest.raises(ValueError):
        CryptoEngine(
            algorithm="hacker123",
            key=b"octagram"
        )
