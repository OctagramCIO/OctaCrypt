//! Firmas Ed25519 (RFC 8032) usando ed25519-dalek.

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use getrandom::rand_core::UnwrapErr;
use getrandom::SysRng;

/// Genera un par (seed_privada 32B, clave_publica 32B).
pub fn ed25519_keypair() -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut rng = UnwrapErr(SysRng);
    let sk = SigningKey::generate(&mut rng);
    let vk = sk.verifying_key();
    Ok((sk.to_bytes().to_vec(), vk.to_bytes().to_vec()))
}

/// Firma 64 bytes sobre `message`.
pub fn ed25519_sign(private_key_seed: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
    if private_key_seed.len() != 32 {
        return Err(format!(
            "La clave privada Ed25519 debe tener 32 bytes, se recibieron {}.",
            private_key_seed.len()
        ));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(private_key_seed);
    let sk = SigningKey::from_bytes(&seed);
    Ok(sk.sign(message).to_bytes().to_vec())
}

/// Verifica una firma Ed25519 de 64 bytes.
pub fn ed25519_verify(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, String> {
    if public_key.len() != 32 {
        return Err(format!(
            "La clave pública Ed25519 debe tener 32 bytes, se recibieron {}.",
            public_key.len()
        ));
    }
    if signature.len() != 64 {
        return Err(format!(
            "La firma Ed25519 debe tener 64 bytes, se recibieron {}.",
            signature.len()
        ));
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(public_key);
    let vk = VerifyingKey::from_bytes(&pk)
        .map_err(|_| "Clave pública Ed25519 inválida.".to_string())?;

    let sig = ed25519_dalek::Signature::from_slice(signature)
        .map_err(|_| "Firma Ed25519 de longitud inválida.".to_string())?;

    Ok(vk.verify(message, &sig).is_ok())
}

/// Deriva la clave pública a partir del seed privado.
pub fn ed25519_public_from_private(private_key_seed: &[u8]) -> Result<Vec<u8>, String> {
    if private_key_seed.len() != 32 {
        return Err(format!(
            "La clave privada Ed25519 debe tener 32 bytes, se recibieron {}.",
            private_key_seed.len()
        ));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(private_key_seed);
    let sk = SigningKey::from_bytes(&seed);
    Ok(sk.verifying_key().to_bytes().to_vec())
}
