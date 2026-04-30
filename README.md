# 🔐 OctaCrypt

OctaCrypt is an open-source cryptographic command-line toolkit developed by **Octagram**, built for maximum-grade encryption of files and messages.

> "True security is not achieved by hiding systems, but by allowing them to be examined — and still remain strong."

⚠️ **Project status: Active development — do NOT use in production yet.**

---

## 🧭 Philosophy

- 🔍 **Auditability** — open-source, readable, testable
- 🔐 **Explicit Cryptography** — no hidden behavior, no magic
- 🧠 **Simplicity** — minimal and understandable design
- 🌍 **Privacy First** — no telemetry, no tracking, no data collection
- 🛡️ **Ethical Security** — built to protect users, not to exploit them

---

## ✨ Features

### Current (v0.2)

- **File encryption** — AES-256-GCM with PBKDF2 key derivation
- **Hybrid encryption** — RSA-OAEP + AES-256-GCM (encrypt files for a recipient)
- **Message encryption** — encrypt text/bytes directly, no files required
- **Digital signatures** — Ed25519 sign and verify (files and messages)
- **Key generation** — RSA (2048/4096) and Ed25519 keypairs
- **Hashing** — SHA-256, SHA-512, bcrypt, scrypt
- **Signed messages** — encrypt + sign in a single step

### Planned

- ChaCha20-Poly1305 support
- Encrypted key storage (password-protected private keys)
- HMAC file integrity verification
- GUI / TUI interface
- Key fingerprint and trust model

---

## 🔑 Cryptographic Stack

| Operation | Algorithm |
|---|---|
| Symmetric encryption | AES-256-GCM |
| Asymmetric encryption | RSA-OAEP (SHA-256) |
| Hybrid encryption | RSA-OAEP + AES-256-GCM |
| Digital signatures | Ed25519 |
| Key derivation | PBKDF2-HMAC-SHA256 (200k iterations) |
| Password hashing | bcrypt / scrypt |
| File integrity | SHA-256 / SHA-512 |

---

## 🧱 Architecture

```
OctaCrypt/
├── octacrypt/
│   ├── algorithms/
│   │   ├── aes.py          # AES-256-GCM
│   │   ├── hybrid.py       # RSA-OAEP + AES-256-GCM
│   │   └── signer.py       # Ed25519 signatures
│   ├── core/
│   │   ├── crypto_engine.py  # Central engine
│   │   ├── crypto.py         # File encrypt/decrypt
│   │   └── messenger.py      # Message encrypt/decrypt
│   ├── cli/
│   │   ├── cli.py            # Main CLI entry point
│   │   ├── encrypt.py        # octacrypt encrypt
│   │   ├── decrypt.py        # octacrypt decrypt
│   │   ├── hybrid.py         # octacrypt hybrid-encrypt/decrypt
│   │   ├── sign.py           # octacrypt sign/verify
│   │   ├── message.py        # octacrypt msg-encrypt/decrypt
│   │   ├── hash.py           # octacrypt hash
│   │   └── keygen.py         # octacrypt keygen
│   └── utils/
│       ├── kdf.py            # Key derivation
│       ├── hash.py           # Hashing functions
│       ├── keygen.py         # Key generation helpers
│       └── logger.py         # Internal logger
├── tests/
├── README.md
└── pyproject.toml
```

---

## 🚀 Getting Started

### Install

```bash
git clone https://github.com/Octagram/OctaCrypt.git
cd OctaCrypt
pip install -e .
```

Requires **Python 3.10+**

---

## 📖 Usage

### 🔑 Generate Keys

```bash
# RSA keypair (for hybrid encryption)
octacrypt keygen --type rsa --bits 2048 --out mykey

# Ed25519 keypair (for signatures)
octacrypt keygen --type ed25519 --out signkey
```

---

### 📁 File Encryption

```bash
# Encrypt with password (AES-256-GCM + PBKDF2)
octacrypt encrypt document.pdf --key mypassword

# Decrypt
octacrypt decrypt document.pdf.enc --key mypassword

# Encrypt for a recipient (hybrid RSA + AES)
octacrypt encrypt document.pdf --alg hybrid --pub recipient_public.pem

# Decrypt with private key
octacrypt decrypt document.pdf.enc --alg hybrid --priv mykey_private.pem
```

---

### ✉️ Message Encryption

```bash
# Encrypt a message with password
octacrypt msg-encrypt "top secret message" --password mypassword

# Decrypt
octacrypt msg-decrypt "<base64>" --password mypassword

# Encrypt for recipient (hybrid)
octacrypt msg-encrypt "top secret" --pub recipient_public.pem

# Encrypt and sign
octacrypt msg-encrypt "top secret" --password pw --sign-priv signkey_private.pem

# Decrypt and verify signature
octacrypt msg-decrypt "<base64>" --password pw --verify-pub signkey_public.pem
```

---

### 🔏 Digital Signatures

```bash
# Sign a file
octacrypt sign document.pdf --priv signkey_private.pem

# Verify signature
octacrypt verify document.pdf --pub signkey_public.pem --sig document.pdf.sig

# Sign a message directly
octacrypt sign "hello octagram" --priv signkey_private.pem --message

# Verify a message signature
octacrypt verify "hello octagram" --pub signkey_public.pem --signature <hex> --message
```

---

### #️⃣ Hashing

```bash
# SHA-256
octacrypt hash document.pdf --sha256

# SHA-512
octacrypt hash document.pdf --sha512

# bcrypt (for passwords)
octacrypt hash mypassword --bcrypt

# Verify bcrypt
octacrypt hash mypassword --bcrypt --verify <hash>
```

---

### 🔀 Hybrid Encryption (advanced)

```bash
# Encrypt file for recipient
octacrypt hybrid-encrypt document.pdf --pub recipient_public.pem

# Decrypt with your private key
octacrypt hybrid-decrypt document.pdf.henc --priv mykey_private.pem
```

---

## ⚠️ Security Notice

- OctaCrypt has **not been independently audited**
- ❌ Do NOT use in production environments yet
- 🔎 Always review cryptographic configurations
- 📢 Report vulnerabilities **privately** — do not open public issues
- 🔑 **Never commit private keys to version control**

---

## 🤝 Contributing

Contributions are welcome.

- Follow secure coding practices
- Write clear commit messages
- Add tests for new features
- Document cryptographic decisions

---

## 📜 License

MIT License — see [LICENSE](LICENSE)

---

## 🔺 About Octagram

Octagram is an international community focused on cybersecurity, privacy, and ethical technology. OctaCrypt is one of its core open-source initiatives.

---

*Built with responsibility. Audited by transparency. Protected by ethics.*