# 🔐 OctaCrypt

<div align="center">

**Maximum-grade encryption by Octagram**

*security through transparency*

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://python.org)
[![Version](https://img.shields.io/badge/Version-0.4.0-brightgreen.svg)]()
[![CI](https://github.com/OctagramCIO/OctaCrypt/actions/workflows/ci.yml/badge.svg)](https://github.com/OctagramCIO/OctaCrypt/actions)
[![Status](https://img.shields.io/badge/Status-Active%20Development-orange.svg)]()

</div>

---

> "True security is not achieved by hiding systems, but by allowing them to be examined and still remain strong."

⚠️ **Project status: Active development- do NOT use in production yet.**

---

📖 **¿Primera vez usando OctaCrypt?** Lee la [Guía de Usuario](GUIA_USUARIO.md)

## 🧭 Philosophy

OctaCrypt is built on one belief: **your data belongs to you**.

- 🔍 **Auditability** — open-source, readable, testable code
- 🔐 **Explicit Cryptography** — no hidden behavior, no magic, no obscurity
- 🧠 **Simplicity** — minimal and understandable design
- 🌍 **Privacy First** — no telemetry, no tracking, no data collection
- 🛡️ **Ethical Security** — built to protect users, not to exploit them

---

## ✨ What's New in v0.4.0

- 🔐 **Post-quantum cryptography** — ML-KEM (FIPS 203) + AES-256-GCM hybrid encryption
- 🔏 **Post-quantum signatures** — ML-DSA (FIPS 204)
- 🗝️ **Keygen** — new key types `mlkem` and `mldsa` (with `--variant`)
- 🖥️ **CLI** — new commands `pq-encrypt`, `pq-decrypt`, `pq-sign`, `pq-verify`
- ✉️ **Messages** — post-quantum modes in `msg-encrypt` / `msg-decrypt` (`--pub-pq` / `--priv-pq`)
- 🖥️ **TUI** — post-quantum options across file, message, sign and keygen menus

---

## 🔑 Cryptographic Stack

| Operation | Algorithm | Standard |
|---|---|---|
| Symmetric encryption | AES-256-GCM | NIST FIPS 197 |
| Symmetric encryption | ChaCha20-Poly1305 | RFC 8439 |
| Asymmetric encryption | RSA-OAEP (SHA-256) | PKCS#1 v2.2 |
| Hybrid encryption | RSA-OAEP + AES-256-GCM | — |
| **Post-quantum encryption** | **ML-KEM-768 / ML-KEM-1024 + AES-256-GCM** | **NIST FIPS 203** |
| Digital signatures | Ed25519 | RFC 8032 |
| **Post-quantum signatures** | **ML-DSA-44 / ML-DSA-65 / ML-DSA-87** | **NIST FIPS 204** |
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
│   │   ├── mlkem.py          # ML-KEM (FIPS 203) + AES-256-GCM (post-cuántico)
│   │   ├── mldsa.py          # ML-DSA (FIPS 204) signatures (post-cuántico)
│   │   └── signer.py         # Ed25519 signatures
│   ├── core/
│   │   ├── crypto_engine.py  # Central engine (AES + ChaCha20)
│   │   ├── crypto.py         # File encrypt/decrypt
│   │   ├── dir_crypto.py     # Directory encrypt/decrypt
│   │   └── messenger.py      # Message encrypt/decrypt + signing + PQ
│   ├── cli/
│   │   ├── cli.py            # Main CLI entry point
│   │   ├── cli_entry.py      # Entry point for portable executable
│   │   ├── encrypt.py        # octacrypt encrypt
│   │   ├── decrypt.py        # octacrypt decrypt
│   │   ├── encrypt_dir.py    # octacrypt encrypt-dir / decrypt-dir
│   │   ├── hybrid.py         # octacrypt hybrid-encrypt/decrypt
│   │   ├── pq.py             # octacrypt pq-encrypt/decrypt/sign/verify
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

# ML-KEM-768 keypair (post-quantum encryption)
octacrypt keygen --type mlkem --out pqenc --prompt-password

# ML-KEM-1024 keypair (maximum security)
octacrypt keygen --type mlkem --variant mlkem1024 --out pqenc --prompt-password

# ML-DSA-65 keypair (post-quantum signatures)
octacrypt keygen --type mldsa --out pqsign --prompt-password

# ML-DSA-44 / ML-DSA-87 keypairs
octacrypt keygen --type mldsa --variant mldsa44 --out pqsign --prompt-password
octacrypt keygen --type mldsa --variant mldsa87 --out pqsign --prompt-password
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

### 🔐 Post-Quantum File Encryption (ML-KEM + AES)

```bash
# Encrypt with ML-KEM-768 public key (resistant to quantum computers)
octacrypt pq-encrypt document.pdf --pub pqenc_public.pem

# Decrypt
octacrypt pq-decrypt document.pdf.pqenc --priv pqenc_private.pem --password mypassword

# Sign with ML-DSA (post-quantum)
octacrypt pq-sign document.pdf --priv pqsign_private.pem --password mypassword

# Verify
octacrypt pq-verify document.pdf --pub pqsign_public.pem --sig document.pdf.pqsig
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

# Post-quantum (ML-KEM)
octacrypt msg-encrypt "top secret" --pub-pq pqenc_public.pem

# With Ed25519 signature
octacrypt msg-encrypt "top secret" --password pw --sign-priv signkey_private.pem

# Decrypt
octacrypt msg-decrypt "<base64>" --password mypassword

# Decrypt post-quantum (with password-protected private key)
octacrypt msg-decrypt "<base64>" --priv-pq pqenc_private.pem --priv-password mypassword

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

### v0.3.x ✅
- Directory encryption
- Portable executable (.exe)
- GitHub Actions CI/CD
- Security policy
- Internal code audit
- CHANGELOG.md

### v0.4.0 ✅ Current
- Post-quantum cryptography: ML-KEM (FIPS 203) encryption
- Post-quantum signatures: ML-DSA (FIPS 204)
- Keygen for ML-KEM / ML-DSA keys
- CLI + TUI support for post-quantum operations

### v1.0.0 🎯 Planned
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
