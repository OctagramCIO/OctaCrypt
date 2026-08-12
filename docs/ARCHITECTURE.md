# 🧱 OctaCrypt — Architecture & Design Decisions

This document explains the technical architecture of OctaCrypt, the reasoning behind every cryptographic decision, and how the components interact.

---

## Overview

OctaCrypt is structured as a layered toolkit:

```
┌─────────────────────────────────────────┐
│           User Interface Layer          │
│         CLI (Click) + TUI (Rich)        │
├─────────────────────────────────────────┤
│              Core Layer                 │
│   CryptoEngine · crypto.py · messenger  │
│         dir_crypto · kdf                │
├─────────────────────────────────────────┤
│           Algorithm Layer               │
│   AES-GCM · ChaCha20 · Hybrid · Signer │
├─────────────────────────────────────────┤
│           Utilities Layer               │
│     keygen · hash · kdf · logger        │
└─────────────────────────────────────────┘
```

Each layer only communicates with the layer directly below it. This makes each component independently testable and replaceable.

---

## Algorithm Layer

### AES-256-GCM (`algorithms/aes.py`)

**Why AES-256-GCM?**

AES-256-GCM is an Authenticated Encryption with Associated Data (AEAD) cipher. It provides both confidentiality and integrity in a single operation — making it impossible to tamper with ciphertext without detection.

- Key size: 256 bits (maximum security level)
- Nonce: 96 bits, randomly generated per operation
- Tag: 128 bits (authentication tag, appended to ciphertext)
- Standard: NIST FIPS 197 + SP 800-38D

**Output format:**
```
[12 bytes nonce][ciphertext + 16 bytes tag]
```

The nonce is prepended to the ciphertext so it travels with the encrypted data. A new nonce is generated for every encryption operation — reusing nonces with the same key would be catastrophic.

**Why not AES-CBC or AES-CTR?**

CBC and CTR modes do not provide authentication — an attacker can modify the ciphertext without detection. GCM solves this by including an integrity tag.

---

### ChaCha20-Poly1305 (`algorithms/chacha.py`)

**Why ChaCha20-Poly1305?**

ChaCha20-Poly1305 is the modern alternative to AES-GCM, used by Google, Signal, WireGuard, and TLS 1.3. It offers equivalent security with better performance on devices that lack AES hardware acceleration (mobile, IoT, older CPUs).

- Key size: 256 bits (only valid size)
- Nonce: 96 bits, randomly generated per operation
- Tag: 128 bits (Poly1305 MAC)
- Standard: RFC 8439

**Output format:**
```
[12 bytes nonce][ciphertext + 16 bytes tag]
```

Identical structure to AES-GCM — this was intentional to simplify the `CryptoEngine` interface.

**When to prefer ChaCha20 over AES:**
- Mobile devices or ARM processors without AES-NI
- Environments where timing side-channel attacks are a concern
- Any case where AES hardware acceleration is unavailable

---

### RSA-OAEP + AES-256-GCM Hybrid (`algorithms/hybrid.py`)

**Why hybrid encryption?**

RSA can only encrypt small amounts of data (limited by key size). For large files, we use RSA to encrypt a randomly generated AES session key, then use AES to encrypt the actual data.

**Flow:**
```
Encrypt:
  1. Generate random 32-byte session key
  2. Encrypt session key with RSA-OAEP (recipient's public key)
  3. Encrypt data with AES-256-GCM using session key
  4. Output: [2B key_len][encrypted_session_key][12B nonce][ciphertext+tag]

Decrypt:
  1. Read encrypted session key length (2 bytes, big-endian)
  2. Decrypt session key with RSA private key
  3. Decrypt data with AES-256-GCM using recovered session key
```

**Why RSA-OAEP and not RSA-PKCS1v15?**

PKCS#1 v1.5 padding is vulnerable to Bleichenbacher's attack (1998). OAEP (Optimal Asymmetric Encryption Padding) is the modern, secure alternative. OctaCrypt uses OAEP with SHA-256 as the hash function.

**Minimum key size: 2048 bits. Recommended: 4096 bits.**

---

### Ed25519 Signatures (`algorithms/signer.py`)

**Why Ed25519?**

Ed25519 is a modern elliptic curve signature scheme offering:
- 128-bit security level with 32-byte keys (much smaller than RSA)
- Fast signing and verification
- Resistance to timing side-channel attacks (constant-time implementation)
- No random number generator needed during signing (deterministic)
- Standard: RFC 8032

**Why not RSA signatures or ECDSA?**

- RSA signatures require large keys (2048+ bits) for equivalent security
- ECDSA requires a random nonce per signature — if the RNG is weak, private keys can be recovered (this broke PlayStation 3's security)
- Ed25519 avoids both problems

**Auto-derivation of public key:**
When a private key is loaded, `Ed25519Signer` automatically derives the public key from it. This means you can sign and verify with only the private key loaded.

---

## Core Layer

### CryptoEngine (`core/crypto_engine.py`)

The central engine abstracts algorithm selection. It accepts an algorithm name and key, validates both, and delegates to the appropriate algorithm class.

```python
_SYMMETRIC = {
    "aes": AESAlgorithm,
    "chacha20": ChaChaAlgorithm,
}
```

**Design decision:** algorithm names are lowercased on input, making the engine case-insensitive. Adding a new algorithm requires only adding an entry to `_SYMMETRIC`.

---

### Key Derivation (`utils/kdf.py`)

**Why PBKDF2?**

User passwords are weak. PBKDF2-HMAC-SHA256 stretches a password into a cryptographically strong key by applying SHA-256 200,000 times with a random salt.

- Iterations: 200,000 (NIST recommends ≥ 10,000; 200k provides strong resistance against GPU attacks)
- Salt: 16 bytes (128 bits), randomly generated per file
- Output key: 32 bytes (256 bits)
- Standard: NIST SP 800-132

**Why not bcrypt or scrypt for file encryption?**

bcrypt has a 72-byte password limit and is designed for passwords, not key derivation. scrypt is memory-hard (better against ASICs) but more complex to configure correctly. PBKDF2 is simpler, well-standardized, and sufficient for OctaCrypt's threat model.

**The salt is always stored with the ciphertext** — without the salt, key derivation cannot be reproduced and the file cannot be decrypted.

---

### File Format (`core/crypto.py`)

Every file encrypted by OctaCrypt has this format:

```
[10 bytes: algorithm name, null-padded]
[16 bytes: PBKDF2 salt]
[12 bytes: nonce]
[N bytes: ciphertext]
[16 bytes: authentication tag]
```

The algorithm prefix makes encrypted files self-describing — OctaCrypt reads the algorithm from the file itself rather than requiring the user to specify it on decryption.

---

### Directory Encryption (`core/dir_crypto.py`)

Directory encryption processes files individually and creates a `.octadir` manifest:

```json
{
  "version": "1",
  "algorithm": "aes",
  "original_dir": "documents",
  "created_at": "2026-07-21T17:00:00+00:00",
  "files": [
    {"original": "file.txt", "encrypted": "file.txt.enc", "size": 1024}
  ],
  "total_files": 1,
  "total_bytes": 1024
}
```

**Why encrypt files individually instead of creating a single archive?**

- Allows partial recovery if some files are corrupted
- No size limit (a single encrypted blob would require loading everything into memory)
- Structure is transparent and auditable

**Trade-off:** metadata (file names, directory structure, file sizes) is visible in the manifest. For high-security use cases, consider encrypting the manifest separately.

---

### Message Encryption (`core/messenger.py`)

Messages use a 10-byte algorithm prefix before the salt, allowing the decryption function to automatically select the correct algorithm:

```
[10 bytes: algorithm prefix]
[16 bytes: salt]
[12 bytes: nonce]
[N bytes: ciphertext + tag]
[optional: ||SIG|| separator + 64 bytes Ed25519 signature]
```

The `||SIG||` separator is used when a message is signed. The signature covers the encrypted payload — meaning the signature proves authenticity of the ciphertext, not the plaintext.

---

## Private Key Storage

Private keys are stored in PKCS#8 PEM format. When a password is provided, `BestAvailableEncryption` from the `cryptography` library is used, which applies AES-256-CBC with PBKDF2.

**Never store private keys in the repository.** The `.gitignore` excludes `*_private.pem` patterns.

---

## Threat Model

OctaCrypt is designed to protect against:

- **Passive adversaries** reading encrypted files or messages
- **Active adversaries** tampering with ciphertext (detected via authentication tags)
- **Weak passwords** (mitigated by PBKDF2 with 200k iterations)
- **Key compromise** (mitigated by password-protected private keys)

OctaCrypt does NOT currently protect against:

- **Compromised endpoints** — if your machine is infected, all bets are off
- **Metadata analysis** — file names and sizes are visible in directory manifests
- **Quantum computers** — post-quantum algorithms are planned for v1.0
- **Forward secrecy** — if a key is compromised, past messages can be decrypted

---

## Dependencies

| Library | Purpose | Why this library |
|---|---|---|
| `cryptography` | All cryptographic primitives | Industry standard, maintained by PyCA, FIPS-validated |
| `click` | CLI framework | Clean API, good help text generation |
| `rich` | Terminal UI rendering | Best Python terminal formatting library |
| `questionary` | Interactive TUI prompts | Clean API, keyboard navigation |
| `bcrypt` | Password hashing | Reference implementation |

All cryptographic operations use the `cryptography` library. No custom cryptographic implementations exist in OctaCrypt — this is intentional. Implementing your own cryptography is a well-known path to vulnerabilities.

---

## Testing Strategy

Every cryptographic module is tested with:

1. **Happy path** — encrypt then decrypt, verify roundtrip
2. **Tampered ciphertext** — modified bytes must raise an exception
3. **Wrong key/password** — must raise an exception
4. **Empty data** — must work without errors
5. **Large data** — 5-10 MB to verify no memory issues
6. **Invalid inputs** — wrong types, empty keys, unsupported algorithms

Tests run on Windows, Linux and macOS with Python 3.10, 3.11 and 3.12 via GitHub Actions.

