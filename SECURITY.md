# 🔐 Security Policy — OctaCrypt

## Supported Versions

The following versions currently receive security updates:

| Version | Supported |
|---------|-----------|
| 0.2.x   | ✅ Active |
| 0.1.x   | ❌ No longer supported |

---

## ⚠️ Important Notice

OctaCrypt is currently in **active development** and has **not been independently audited**.

- ❌ Do NOT use in production environments
- ❌ Do NOT use to protect sensitive data in real-world scenarios
- ✅ Safe for testing, learning, and development purposes

---

## 🔍 Scope

The following are considered **in scope** for security reports:

- Cryptographic implementation flaws (AES-GCM, ChaCha20-Poly1305, RSA-OAEP, Ed25519)
- Key derivation weaknesses (PBKDF2 configuration)
- Private key exposure or mishandling
- Authentication bypass in any module
- Data integrity failures (tampered ciphertext not detected)
- Insecure defaults in CLI or TUI
- Dependency vulnerabilities with direct impact on OctaCrypt

The following are **out of scope**:

- Vulnerabilities in dependencies without direct exploitability in OctaCrypt
- Social engineering attacks
- Physical access attacks
- Issues in unsupported versions (< 0.2.0)

---

## 📢 Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

Public disclosure before a fix is available puts all users at risk.

### How to report

1. **Email:** Send a detailed report to the Octagram security team.
   Contact via the official Octagram community channels.

2. **Include in your report:**
   - Description of the vulnerability
   - Steps to reproduce
   - Affected version(s)
   - Potential impact assessment
   - Suggested fix (optional but appreciated)

3. **Expected response time:**
   - Acknowledgement within **48 hours**
   - Status update within **7 days**
   - Fix timeline communicated within **14 days**

---

## 🤝 Responsible Disclosure

OctaCrypt follows responsible disclosure principles:

- We will acknowledge your report promptly
- We will keep you informed of our progress
- We will credit you in the fix (unless you prefer anonymity)
- We ask that you give us reasonable time to fix the issue before public disclosure
- We will never take legal action against researchers acting in good faith

---

## 🔑 Cryptographic Standards

OctaCrypt uses the following algorithms and configurations:

| Component | Algorithm | Notes |
|---|---|---|
| Symmetric encryption | AES-256-GCM | 256-bit key, 96-bit nonce, 128-bit tag |
| Symmetric encryption | ChaCha20-Poly1305 | 256-bit key, 96-bit nonce, 128-bit tag |
| Asymmetric encryption | RSA-OAEP + SHA-256 | Minimum 2048-bit keys, recommended 4096 |
| Digital signatures | Ed25519 | 256-bit security level |
| Key derivation | PBKDF2-HMAC-SHA256 | 200,000 iterations, 128-bit salt |
| Password hashing | bcrypt / scrypt | Adaptive cost factors |
| Private key storage | AES-256-CBC | PKCS#8 with BestAvailableEncryption |

Any report suggesting these configurations are insufficient or misconfigured is welcome.

---

## 🚫 Known Limitations

The following are known limitations, not bugs:

- OctaCrypt has not been independently audited
- Key management is the user's responsibility — lost keys mean lost data
- The TUI does not currently support hardware security keys (YubiKey, etc.)
- No forward secrecy in file encryption (planned for v1.0)

---

## 📜 Attribution

Security researchers who responsibly disclose vulnerabilities will be credited in:
- The release notes of the fixing version
- A dedicated `HALL_OF_FAME.md` (coming soon)

---

## 🔺 About Octagram

Octagram is an international community focused on cybersecurity, privacy, and ethical technology.

*security through transparency*