//! Cifrado simétrico AEAD (AES-256-GCM y ChaCha20-Poly1305).
//!
//! Formato de salida idéntico al de la capa Python histórica:
//!   [nonce 12 bytes] [ciphertext || tag 16 bytes]
//! Esto permite que los ficheros cifrados por Rust y por Python sean
//! intercambiables en la dirección de descifrado.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce as AesNonce};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNonce};

pub const NONCE_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;

/// AES-256-GCM. `key` debe tener 32 bytes. Se obtiene `nonce || ct`.
pub fn aes_gcm_encrypt(key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    if key.len() != 32 {
        return Err(format!(
            "AES-256-GCM requiere una clave de 32 bytes, se recibieron {}.",
            key.len()
        ));
    }

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    getrandom::fill(&mut nonce_bytes).map_err(|e| format!("RNG: {e}"))?;
    let nonce = AesNonce::from(nonce_bytes);

    let ct = cipher
        .encrypt(
            &nonce,
            aes_gcm::aead::Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| "Fallo de cifrado AES-GCM.".to_string())?;

    let mut out = Vec::with_capacity(NONCE_SIZE + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// AES-256-GCM. Entrada `nonce || ct` en `data`.
pub fn aes_gcm_decrypt(key: &[u8], data: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    if key.len() != 32 {
        return Err(format!(
            "AES-256-GCM requiere una clave de 32 bytes, se recibieron {}.",
            key.len()
        ));
    }
    if data.len() < NONCE_SIZE + TAG_SIZE {
        return Err("Datos demasiado cortos para AES-256-GCM.".to_string());
    }

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
    let nonce = AesNonce::from_slice(&data[..NONCE_SIZE]);
    let ct = &data[NONCE_SIZE..];

    cipher
        .decrypt(
            nonce,
            aes_gcm::aead::Payload { msg: ct, aad },
        )
        .map_err(|_| "Tag de autenticación inválido (AES-256-GCM).".to_string())
}

/// ChaCha20-Poly1305. `key` debe tener 32 bytes. Se obtiene `nonce || ct`.
pub fn chacha_encrypt(key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    if key.len() != 32 {
        return Err(format!(
            "ChaCha20-Poly1305 requiere una clave de 32 bytes, se recibieron {}.",
            key.len()
        ));
    }

    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|e| e.to_string())?;
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    getrandom::fill(&mut nonce_bytes).map_err(|e| format!("RNG: {e}"))?;
    let nonce = ChaChaNonce::from(nonce_bytes);

    let ct = cipher
        .encrypt(
            &nonce,
            chacha20poly1305::aead::Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| "Fallo de cifrado ChaCha20-Poly1305.".to_string())?;

    let mut out = Vec::with_capacity(NONCE_SIZE + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// ChaCha20-Poly1305. Entrada `nonce || ct` en `data`.
pub fn chacha_decrypt(key: &[u8], data: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    if key.len() != 32 {
        return Err(format!(
            "ChaCha20-Poly1305 requiere una clave de 32 bytes, se recibieron {}.",
            key.len()
        ));
    }
    if data.len() < NONCE_SIZE + TAG_SIZE {
        return Err("Datos demasiado cortos para ChaCha20-Poly1305.".to_string());
    }

    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|e| e.to_string())?;
    let nonce = ChaChaNonce::from_slice(&data[..NONCE_SIZE]);
    let ct = &data[NONCE_SIZE..];

    cipher
        .decrypt(
            nonce,
            chacha20poly1305::aead::Payload { msg: ct, aad },
        )
        .map_err(|_| "Tag de autenticación inválido (ChaCha20-Poly1305).".to_string())
}
