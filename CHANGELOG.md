# Changelog

All notable changes to OctaCrypt are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- TUI: cifrado de mensajes simétricos fallaba con `TypeError` y la opción
  ChaCha20-Poly1305 no tenía efecto. `MessageCipher.encrypt_symmetric` ahora
  acepta `algorithm` y el mensaje guarda un prefijo de algoritmo para
  selección automática en el descifrado.
- TUI: `ask_password` con `"Enter si no tiene"` mostraba un error falso para
  claves privadas sin contraseña.
- `python -m octacrypt` y `python -m octacrypt.cli` ofrecían un parser
  obsoleto con `--alg xor` (algoritmo inexistente). Ahora delegan en la CLI real.
- `decrypt --alg hybrid` no aceptaba `--password`, imposibilitando descifrar
  claves privadas protegidas (flujo documentado en las guías).
- `decrypt` sobrescribía el archivo de entrada cuando el cifrado no tenía
  extensión `.enc`.
- Los comandos `hybrid-*`, `pq-*`, `sign`, `verify` y `msg-decrypt`
  mostraban trazas de Python ante errores de contraseña, clave o datos. Ahora
  emiten mensajes claros.
- `msg-encrypt`/`msg-decrypt`: el modo simétrico soporta `--alg aes|chacha20`.
- `hash --bcrypt/--scrypt` ahora hashea el contenido del archivo (coherente con
  SHA-256/SHA-512), no la ruta.
- `scrypt` usa un salt propio y comparación en tiempo constante; se mantiene
  compatibilidad con hashes del formato antiguo.
- `decrypt_directory`: se valida el manifiesto y se previene path traversal
  (rutas `..` o absolutas).
- Validación de longitud mínima en `AESAlgorithm.decrypt`, `HybridCipher.decrypt`
  y `MLKEMCipher.decrypt`.
- `MessageCipher`: un mensaje firmado descifrado sin clave de verificación ya
  no ignora la firma en silencio; lanza `ValueError`.
- Logger interno bajado de `DEBUG` a `INFO`.

### Changed
- `decrypt --alg` valida contra el algoritmo embebido en el archivo en lugar de
  ser ignorado.
- `pyproject.toml`: añadido extra `[dev]` (pytest, pytest-cov, ruff).
- `build.py`: `hiddenimports` completos para ML-KEM, ML-DSA y todos los comandos CLI.

### Documentation
- Añadido `CHANGELOG.md`.
- Corregido el formato de mensajes en `docs/ARCHITECTURE.md`.
- Corregidos ejemplos con `--password` en claves protegidas.
- Corregido `bcrypt` descrito erróneamente como "memory-hard".
- Corregidos comandos de desarrollo en `docs/CONTRIBUTING.md`.

## [0.4.0] - Current

### Added
- Post-quantum encryption: ML-KEM (FIPS 203), variants `mlkem768` and `mlkem1024`.
- Post-quantum signatures: ML-DSA (FIPS 204), variants `mldsa44`, `mldsa65`, `mldsa87`.
- `keygen` support for ML-KEM / ML-DSA keys.
- CLI + TUI support for post-quantum operations (`pq-encrypt`, `pq-decrypt`,
  `pq-sign`, `pq-verify`).

## [0.3.x]

### Added
- Directory encryption (`encrypt-dir`, `decrypt-dir`, `dir-info`).
- Portable executables (`.exe`) via PyInstaller.
- GitHub Actions CI/CD across Windows, Linux and macOS.
- Security policy (`SECURITY.md`).
- Internal code audit.
