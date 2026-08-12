# 🔐 OctaCrypt — Cryptography Reference

Quick reference for every cryptographic primitive used in OctaCrypt, with parameters, standards, and security notes.

---

## Symmetric Encryption

### AES-256-GCM

| Parameter | Value |
|---|---|
| Key size | 256 bits (32 bytes) |
| Nonce size | 96 bits (12 bytes) |
| Tag size | 128 bits (16 bytes) |
| Mode | Galois/Counter Mode (GCM) |
| Standard | NIST FIPS 197, SP 800-38D |
| Security level | 128-bit equivalent |

**Key properties:**
- Authenticated encryption — detects tampering automatically
- Nonce must be unique per (key, message) pair — OctaCrypt uses `os.urandom(12)`
- Tag is appended to ciphertext and verified on decryption

**Output:** `nonce (12B) || ciphertext || tag (16B)`

---

### ChaCha20-Poly1305

| Parameter | Value |
|---|---|
| Key size | 256 bits (32 bytes) — only valid size |
| Nonce size | 96 bits (12 bytes) |
| Tag size | 128 bits (16 bytes) |
| Standard | RFC 8439 |
| Security level | 128-bit equivalent |

**Key properties:**
- Equivalent security to AES-256-GCM
- Faster on devices without AES hardware acceleration (ARM, mobile)
- Constant-time implementation — resistant to timing attacks
- Used by: TLS 1.3, Signal Protocol, WireGuard, SSH

**Output:** `nonce (12B) || ciphertext || tag (16B)`

---

## Asymmetric Encryption

### RSA-OAEP

| Parameter | Value |
|---|---|
| Key sizes | 2048 bits (minimum), 4096 bits (recommended) |
| Padding | OAEP (Optimal Asymmetric Encryption Padding) |
| Hash function | SHA-256 |
| MGF | MGF1 with SHA-256 |
| Standard | PKCS#1 v2.2 (RFC 8017) |

**Key properties:**
- Only used to encrypt the AES session key (hybrid mode)
- Maximum plaintext size: `(key_size / 8) - 2 * hash_size - 2` bytes
  - RSA-2048 → max 190 bytes
  - RSA-4096 → max 446 bytes
- OAEP is probabilistic — same plaintext encrypts differently each time

**Why 4096 bits recommended?**
RSA-2048 provides ~112-bit security. RSA-4096 provides ~140-bit security. Given that private keys may be stored for years, 4096 bits provides a larger safety margin against future advances in factoring algorithms.

---

## Digital Signatures

### Ed25519

| Parameter | Value |
|---|---|
| Curve | Edwards25519 |
| Key size | 32 bytes private, 32 bytes public |
| Signature size | 64 bytes |
| Standard | RFC 8032 |
| Security level | 128-bit equivalent |

**Key properties:**
- Deterministic — same message + key always produces same signature
- No random number generator needed during signing (unlike ECDSA)
- Constant-time implementation — immune to timing attacks
- Fast: ~70,000 signatures/second on modern hardware

**Verification:**
A valid signature proves that:
1. The signer had access to the private key
2. The signed data has not been modified since signing

---

## Key Derivation

### PBKDF2-HMAC-SHA256

| Parameter | Value |
|---|---|
| Hash function | SHA-256 |
| Iterations | 200,000 |
| Salt size | 128 bits (16 bytes) |
| Output key size | 256 bits (32 bytes) |
| Standard | NIST SP 800-132, RFC 8018 |

**Why 200,000 iterations?**

Each iteration adds computational cost for an attacker trying to brute-force the password. At 200,000 iterations:
- Legitimate user: ~0.1 seconds on modern hardware (acceptable)
- Attacker with GPU: ~1,000,000 guesses/second per GPU (slowed significantly)

NIST recommends ≥ 10,000 iterations. OctaCrypt uses 200,000 for stronger resistance.

**The salt:**
- 16 random bytes generated per encryption operation
- Stored at the beginning of the encrypted file
- Prevents precomputed rainbow table attacks
- Even the same password produces different keys for different files

---

## Password Hashing

### bcrypt

| Parameter | Value |
|---|---|
| Cost factor | Default (bcrypt.gensalt()) |
| Output | 60-character hash string |
| Standard | Niels Provos and David Mazières (1999) |

Used for: password storage verification (`octacrypt hash --bcrypt`)

**Key properties:**
- Adaptive — cost factor can be increased as hardware gets faster
- Memory-hard — more resistant to GPU attacks than PBKDF2
- Built-in salt (embedded in the output string)

---

### scrypt

| Parameter | Value |
|---|---|
| N (CPU/memory cost) | 2^14 (16,384) |
| r (block size) | 8 |
| p (parallelization) | 1 |
| Output | Variable (key derivation) |
| Standard | RFC 7914 |

Used for: password hashing (`octacrypt hash --scrypt`)

**Key properties:**
- Memory-hard — requires significant RAM, making ASIC attacks expensive
- More resistant to hardware acceleration than bcrypt
- Slower than bcrypt on the same hardware (by design)

---

## Private Key Storage

| Parameter | Value |
|---|---|
| Format | PKCS#8 PEM |
| Encryption | AES-256-CBC (when password set) |
| Key derivation | PBKDF2 (via BestAvailableEncryption) |
| Standard | RFC 5958 |

**BestAvailableEncryption** from the `cryptography` library selects the strongest available encryption scheme for the platform. Currently this is AES-256-CBC with PBKDF2.

Private keys without a password are stored as `BEGIN PRIVATE KEY`. With a password: `BEGIN ENCRYPTED PRIVATE KEY`.

---

## File Integrity

### SHA-256 / SHA-512

| Algorithm | Output size | Standard |
|---|---|---|
| SHA-256 | 256 bits (32 bytes) | NIST FIPS 180-4 |
| SHA-512 | 512 bits (64 bytes) | NIST FIPS 180-4 |

Used for: file integrity verification (`octacrypt hash --sha256`)

**Note:** SHA hashes verify integrity but not authenticity. Anyone can compute a SHA hash. For authenticated integrity, use AES-GCM or ChaCha20-Poly1305 (which include authentication tags) or Ed25519 signatures.

---

## Random Number Generation

All random values in OctaCrypt (nonces, salts, session keys) are generated using `os.urandom()`, which uses the operating system's cryptographically secure random number generator:

- Linux/macOS: `/dev/urandom` (seeded from kernel entropy pool)
- Windows: `CryptGenRandom` / `BCryptGenRandom`

**Never use `random` module for cryptographic purposes.** OctaCrypt does not.

---

## Security Levels Summary

| Operation | Security Level | Quantum Resistance |
|---|---|---|
| AES-256-GCM | 128-bit | ~128-bit (Grover's algorithm halves it) |
| ChaCha20-Poly1305 | 128-bit | ~128-bit |
| RSA-4096 | ~140-bit | ❌ Broken by Shor's algorithm |
| Ed25519 | 128-bit | ❌ Broken by Shor's algorithm |
| PBKDF2-HMAC-SHA256 | Password-dependent | Partially resistant |

**Post-quantum note:** RSA and Ed25519 are vulnerable to quantum computers running Shor's algorithm. OctaCrypt plans to add ML-KEM (KYBER) and ML-DSA (DILITHIUM) in v1.0 as quantum-resistant alternatives.

