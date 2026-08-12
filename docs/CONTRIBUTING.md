# 🤝 Contributing to OctaCrypt

Thank you for your interest in contributing to OctaCrypt. This document explains how to contribute effectively and safely.

---

## Before You Start

OctaCrypt is a cryptographic tool. Contributions that touch cryptographic code require extra care. Please read [CRYPTOGRAPHY.md](CRYPTOGRAPHY.md) before making changes to any algorithm or key handling code.

**Golden rule: never implement your own cryptography.** All cryptographic operations must use the `cryptography` library.

---

## Development Setup

```bash
git clone https://github.com/OctagramCIO/OctaCrypt.git
cd OctaCrypt
pip install -e ".[dev]"
pip install pytest ruff
```

---

## Running Tests

```bash
# Full test suite
pytest tests/ -v

# Specific module
pytest tests/test_aes.py -v

# With coverage
pytest tests/ --cov=octacrypt --cov-report=term-missing
```

All tests must pass before submitting a pull request. Tests run automatically via GitHub Actions on Windows, Linux and macOS.

---

## Code Style

OctaCrypt uses **Ruff** for linting:

```bash
python -m ruff check octacrypt/ --select E,F,W --ignore E501
```

Key conventions:
- Type hints on all public functions
- Docstrings on all public classes and functions
- Explicit error messages — never silent failures
- No bare `except:` — always catch specific exceptions or at minimum `except Exception as e`

---

## Adding a New Algorithm

1. Create `octacrypt/algorithms/your_algorithm.py`
2. Implement `encrypt(data: bytes) -> bytes` and `decrypt(data: bytes) -> bytes`
3. Add to `CryptoEngine._SYMMETRIC` in `core/crypto_engine.py`
4. Add tests in `tests/test_your_algorithm.py` covering:
   - Basic roundtrip
   - Empty data
   - Large data (5+ MB)
   - Tampered ciphertext raises exception
   - Invalid key raises exception
5. Add to `encrypt` and `decrypt` CLI commands
6. Document in `docs/CRYPTOGRAPHY.md`

---

## Pull Request Guidelines

- One feature or fix per PR
- Write tests for all new code
- Update `CHANGELOG.md` under `[Unreleased]`
- Keep commit messages clear: `feat:`, `fix:`, `docs:`, `test:`, `chore:`
- Never commit private keys or sensitive data

---

## Reporting Security Issues

Do NOT open a public issue for security vulnerabilities. Follow the process in [SECURITY.md](../SECURITY.md).

