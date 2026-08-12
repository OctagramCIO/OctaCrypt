# 🔐 OctaCrypt

<div align="center">

**Maximum-grade encryption by Octagram**

*security through transparency*

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://python.org)
[![Version](https://img.shields.io/badge/Version-0.3.1-brightgreen.svg)]()
[![CI](https://github.com/OctagramCIO/OctaCrypt/actions/workflows/ci.yml/badge.svg)](https://github.com/OctagramCIO/OctaCrypt/actions)
[![Status](https://img.shields.io/badge/Status-Active%20Development-orange.svg)]()

</div>

---

> "True security is not achieved by hiding systems, but by allowing them to be examined and still remain strong."

⚠️ **Project status: Active development- do NOT use in production yet.**

---

## 🧭 Philosophy

OctaCrypt is built on one belief: **your data belongs to you**.

- 🔍 **Auditability** — open-source, readable, testable code
- 🔐 **Explicit Cryptography** — no hidden behavior, no magic, no obscurity
- 🧠 **Simplicity** — minimal and understandable design
- 🌍 **Privacy First** — no telemetry, no tracking, no data collection
- 🛡️ **Ethical Security** — built to protect users, not to exploit them

---

## ✨ What's New in v0.3.1

- 🔧 **Critical bug fix** — ChaCha20-Poly1305 now works correctly in CLI encrypt/decrypt
- 🖥️ **TUI** — directory encryption added to the menu
- 🖥️ **TUI** — improved error handling across all flows
- 📋 **CHANGELOG.md** — full project history documented
- 🧹 **Code audit** — duplicate code removed, error messages improved

---

## 🔑 Cryptographic Stack

| Operation | Algorithm | Standard |
|---|---|---|
| Symmetric encryption | AES-256-GCM | NIST FIPS 197 |
| Symmetric encryption | ChaCha20-Poly1305 | RFC 8439 |
| Asymmetric encryption | RSA-OAEP (SHA-256) | PKCS#1 v2.2 |
| Hybrid encryption | RSA-OAEP + AES-256-GCM | — |
| Digital signatures | Ed25519 | RFC 8032 |
| Key derivation | PBKDF2-HMAC-SHA256 (200k iter.) | NIST SP 800-132 |
| Password hashing | bcrypt / scrypt | — |
| File integrity | SHA-256 / SHA-512 | NIST FIPS 180-4 |
| Private key storage | AES-256-CBC (BestAvailableEncryption) | PKCS#8 |

---

## 🧱 Architecture

```
OctaCrypt/
├── octacrypt/
│   ├── algorithms/
│   │   ├── aes.py            # AES-256-GCM
│   │   ├── chacha.py         # ChaCha20-Poly1305
│   │   ├── hybrid.py         # RSA-OAEP + AES-256-GCM
│   │   └── signer.py         # Ed25519 signatures
│   ├── core/
│   │   ├── crypto_engine.py  # Central engine (AES + ChaCha20)
│   │   ├── crypto.py         # File encrypt/decrypt
│   │   ├── dir_crypto.py     # Directory encrypt/decrypt
│   │   └── messenger.py      # Message encrypt/decrypt + signing
│   ├── cli/
│   │   ├── cli.py            # Main CLI entry point
│   │   ├── cli_entry.py      # Entry point for portable executable
│   │   ├── encrypt.py        # octacrypt encrypt
│   │   ├── decrypt.py        # octacrypt decrypt
│   │   ├── encrypt_dir.py    # octacrypt encrypt-dir / decrypt-dir
│   │   ├── hybrid.py         # octacrypt hybrid-encrypt/decrypt
│   │   ├── sign.py           # octacrypt sign/verify
│   │   ├── message.py        # octacrypt msg-encrypt/decrypt
│   │   ├── hash.py           # octacrypt hash
│   │   └── keygen.py         # octacrypt keygen
│   ├── tui/
│   │   ├── tui.py            # Interactive terminal UI
│   │   └── tui_entry.py      # Entry point for portable executable
│   └── utils/
│       ├── kdf.py            # PBKDF2 key derivation
│       ├── hash.py           # Hashing functions
│       ├── keygen.py         # Key generation + protected storage
│       └── logger.py         # Internal logger
├── tests/                    # Full test suite (CI on 3 OS)
├── .github/
│   └── workflows/
│       └── ci.yml            # GitHub Actions CI/CD
├── build.py                  # Portable executable build script
├── CHANGELOG.md              # Full version history
├── README.md
├── SECURITY.md
└── pyproject.toml
```

---

## 🚀 Installation

### From source

```bash
git clone https://github.com/OctagramCIO/OctaCrypt.git
cd OctaCrypt
pip install -e .
```

Requires **Python 3.10+**

### Portable executable (no Python required)

Download the latest release from the [Releases](https://github.com/OctagramCIO/OctaCrypt/releases) page:

- `octacrypt.exe` — CLI for Windows
- `octacrypt-tui.exe` — TUI for Windows

Or build it yourself:

```bash
pip install pyinstaller
python build.py
```

---

## 🖥️ Interactive TUI (recommended)

The easiest way to use OctaCrypt — no commands to memorize:

```bash
# From source
octacrypt-tui

# Portable
.\dist\octacrypt-tui.exe
```

Features available in the TUI:
- 🔒 Encrypt / decrypt files
- 📁 Encrypt / decrypt directories
- ✉️ Encrypt / decrypt messages
- 🔏 Sign and verify files
- 🔑 Generate keypairs (with password protection)
- #️⃣ Hash files and strings
- ℹ️ About / version info

---

## 📖 CLI Usage

### 🔑 Generate Keys

```bash
# RSA-4096 keypair — with password protection
octacrypt keygen --type rsa --bits 4096 --out mykey --prompt-password

# Ed25519 keypair
octacrypt keygen --type ed25519 --out signkey --prompt-password
```

---

### 📁 File Encryption

```bash
# AES-256-GCM (default)
octacrypt encrypt document.pdf --key mypassword

# ChaCha20-Poly1305
octacrypt encrypt document.pdf --alg chacha20 --key mypassword

# Hybrid RSA + AES
octacrypt encrypt document.pdf --alg hybrid --pub recipient_public.pem

# Decrypt
octacrypt decrypt document.pdf.enc --key mypassword
octacrypt decrypt document.pdf.enc --alg chacha20 --key mypassword
octacrypt decrypt document.pdf.enc --alg hybrid --priv mykey_private.pem
```

---

### 📂 Directory Encryption

```bash
# Encrypt entire directory (preserves structure)
octacrypt encrypt-dir documents/ --key mypassword
octacrypt encrypt-dir documents/ --alg chacha20 --key mypassword

# Decrypt
octacrypt decrypt-dir documents.enc/ --key mypassword

# Inspect encrypted directory
octacrypt dir-info documents.enc/
```

---

### ✉️ Message Encryption

```bash
# Symmetric
octacrypt msg-encrypt "top secret message" --password mypassword

# Hybrid RSA
octacrypt msg-encrypt "top secret" --pub recipient_public.pem

# With Ed25519 signature
octacrypt msg-encrypt "top secret" --password pw --sign-priv signkey_private.pem

# Decrypt
octacrypt msg-decrypt "<base64>" --password mypassword

# Decrypt + verify signature
octacrypt msg-decrypt "<base64>" --password pw --verify-pub signkey_public.pem
```

---

### 🔏 Digital Signatures

```bash
# Sign a file
octacrypt sign document.pdf --priv signkey_private.pem

# Verify signature
octacrypt verify document.pdf --pub signkey_public.pem --sig document.pdf.sig

# Sign a message
octacrypt sign "hello octagram" --priv signkey_private.pem --message

# Verify a message
octacrypt verify "hello octagram" --pub signkey_public.pem --signature <hex> --message
```

---

### #️⃣ Hashing

```bash
octacrypt hash document.pdf --sha256
octacrypt hash document.pdf --sha512
octacrypt hash mypassword --bcrypt
octacrypt hash mypassword --scrypt
```

---

## 🧪 Running Tests

```bash
pip install pytest
pytest tests/ -v
```

Tests run automatically on every push via GitHub Actions across:
- **OS:** Windows, Linux, macOS
- **Python:** 3.10, 3.11, 3.12

---

## 🗺️ Roadmap

### v0.2.0 ✅
- AES-256-GCM + ChaCha20-Poly1305
- RSA hybrid encryption
- Ed25519 digital signatures
- Password-protected private keys
- Interactive TUI

### v0.3.x ✅ Current
- Directory encryption
- Portable executable (.exe)
- GitHub Actions CI/CD
- Security policy
- Internal code audit
- CHANGELOG.md

### v1.0.0 🎯 Planned
- Post-quantum cryptography (KYBER / ML-KEM, DILITHIUM / ML-DSA)
- Technical documentation
- Independent security audit
- Stable API
- Hardware key support (YubiKey)

---

## ⚠️ Security Notice

- OctaCrypt has **not been independently audited**
- ❌ Do NOT use in production environments yet
- 🔑 **Never commit private keys** — they are in `.gitignore`
- 📢 Report vulnerabilities **privately** — see [SECURITY.md](SECURITY.md)

---

## 🤝 Contributing

Contributions are welcome.

- Follow secure coding practices
- Write tests for new features
- Keep commit messages clear and descriptive
- Document cryptographic decisions

---

## 📜 License

MIT License — see [LICENSE](LICENSE)

---

## 🔺 About Octagram

Octagram is an international community focused on cybersecurity, privacy, and ethical technology. OctaCrypt is one of its core open-source initiatives.

---

<div align="center">

*Built with responsibility. Audited by transparency. Protected by ethics.*

</div>
