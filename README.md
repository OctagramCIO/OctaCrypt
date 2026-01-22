# 🔐 OctaCrypt

**OctaCrypt** is an open-source cryptographic CLI toolkit developed by **Octagram**, focused on secure file encryption, clean architecture, and responsible key handling.

OctaCrypt follows a clear philosophy: **security through transparency**. All cryptographic mechanisms are explicit, auditable, and modular. The project prioritizes correctness, clarity, and extensibility over obscurity.

> ⚠️ OctaCrypt is currently in early development. Do **not** use pre-release versions in production environments.

---

## 🧭 Project Philosophy

> "True security is not achieved by hiding systems, but by allowing them to be examined — and still remain strong."

OctaCrypt is built on these principles:

* 🔍 **Auditability** – Open-source, readable, and testable code
* 🔐 **Explicit Cryptography** – No hidden behavior or opaque flows
* 🧠 **Simplicity** – Minimal, understandable design
* 🌍 **Privacy First** – No telemetry, tracking, or data collection
* 🛡️ **Ethical Security** – Built to protect users, not to exploit them

---

## ✨ Features

### Current (v0.1)

* File encryption and decryption
* Modular cryptographic engine
* Command-line interface (CLI)
* Algorithm abstraction layer
* Automated test coverage

### Planned

* AES encryption
* Key derivation (KDF)
* Integrity verification (HMAC / AEAD)
* Message encryption
* Digital signatures
* Global CLI entry point

---

## 🧱 Architecture Overview

OctaCrypt is designed as a **modular toolkit**, allowing each component to be reviewed, tested, and extended independently.

```
OctaCrypt/
├── octacrypt/
│   ├── algorithms/   # Cryptographic algorithms (XOR, future AES)
│   ├── core/         # Crypto engine and file operations
│   ├── cli/          # Command-line interface
│   └── __init__.py
├── tests/            # Automated tests
├── README.md
└── pyproject.toml / setup.cfg (future)
```

---

## 🚀 Getting Started

Clone the repository:

```bash
git clone https://github.com/Octagram/OctaCrypt.git
cd OctaCrypt
```

Ensure you are using **Python 3.10+**.

### Encrypt a file

```bash
python -m octacrypt.cli encrypt file.txt --key mysecret --alg xor
```

### Decrypt a file

```bash
python -m octacrypt.cli decrypt file.txt.enc --key mysecret --alg xor
```

---

## ⚠️ Security Notice

OctaCrypt is under active development.

* ❌ Do **NOT** use in production
* 🔎 Always review cryptographic configurations
* 📢 Report vulnerabilities responsibly

If you discover a security issue, **do not open a public issue**. Please contact the Octagram team directly.

---

## 🤝 Contributing

Contributions are welcome.

Guidelines:

* Follow secure coding practices
* Write clear and descriptive commit messages
* Add tests when applicable

A full CONTRIBUTING guide will be added in a future release.

---

## 📜 License

This project is licensed under the **MIT License**.

---

## 🔺 About Octagram

**Octagram** is an international community focused on cybersecurity, privacy, and ethical technology.

OctaCrypt is one of its core open-source initiatives.

---

> Built with responsibility. Audited by transparency. Protected by ethics.
