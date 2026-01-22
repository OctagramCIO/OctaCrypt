🔐 OctaCrypt

OctaCrypt is an open-source cryptographic command-line (CLI) toolkit developed by Octagram, focused on secure file encryption, clean architecture, and responsible key handling.

The project follows a clear philosophy: security through transparency.
All cryptographic operations are explicit, auditable, and modular. OctaCrypt prioritizes correctness, clarity, and extensibility over obscurity or convenience.

⚠️ Project status: Early development
Do NOT use pre-release versions in production environments.

---

## 🧭 Project Philosophy

"True security is not achieved by hiding systems, but by allowing them to be examined — and still remain strong."

OctaCrypt is built on the following principles:

🔍 Auditability – Open-source, readable, and testable code

🔐 Explicit Cryptography – No hidden behavior or opaque processes

🧠 Simplicity – Minimal and understandable design

🌍 Privacy First – No telemetry, tracking, or data collection

🛡️ Ethical Security – Built to protect users, not to exploit them

---

## ✨ Features

**Current (v0.1)**

File encryption and decryption

Modular cryptographic engine

Command-line interface (CLI)

Algorithm abstraction layer

Basic input validation and error handling

Automated test coverage (in progress)


**PLANED**

AES encryption (secure default)

Key derivation functions (KDF)

Integrity verification (HMAC / AEAD)

Message encryption

Digital signatures

Global CLI entry point (octacrypt)

**⚠️ Note:**
The current XOR algorithm is implemented for educational and structural purposes only and must NOT be used for real-world security.

---

## 🧱 Architecture Overview

OctaCrypt is designed as a **modular toolkit**, allowing each component to be reviewed, tested, and extended independently.

OctaCrypt/
├── octacrypt/
│   ├── algorithms/   # Cryptographic algorithms (XOR, future AES)
│   ├── core/         # Crypto engine and file operations
│   ├── cli/          # Command-line interface
│   └── __init__.py
├── tests/            # Automated tests
├── README.md
└── pyproject.toml    # Packaging configuration (planned)

---

## 🚀 Getting Started

Clone the repository:

git clone https://github.com/Octagram/OctaCrypt.git
cd OctaCrypt

Ensure you are using **Python 3.10+**.

### Encrypt a file

python -m octacrypt.cli encrypt file.txt --key mysecret --alg xor

### Decrypt a file

python -m octacrypt.cli decrypt file.txt.enc --key mysecret --alg xor

---

## ⚠️ Security Notice

OctaCrypt is under active development and has not been independently audited.

❌ Do NOT use in production environments

🔎 Always review cryptographic configurations and code

📢 Report vulnerabilities responsibly

If you discover a security issue, do not open a public issue.
Please contact the Octagram team directly through official channels.

---

## 🤝 Contributing

Contributions are welcome and encouraged.

Guidelines:

Follow secure coding practices

Write clear and descriptive commit messages

Add tests when applicable

A full CONTRIBUTING.md guide will be added in a future release.

---

## 📜 License

This project is licensed under the **MIT License**.

---

## 🔺 About Octagram

Octagram is an international community focused on cybersecurity, privacy, and ethical technology.

OctaCrypt is one of its core open-source initiatives.

---

Built with responsibility.
Audited by transparency.
Protected by ethics.
