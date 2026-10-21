//! Firmas digitales post-cuánticas ML-DSA (FIPS 204).
//!
//! Formatos de bytes estables:
//!   - Clave privada (signing): 32-byte seed (forma preferida, igual across niveles).
//!   - Clave pública (verifying): clave encoded (~1952 bytes para ML-DSA-65).
//!   - Firma: encoded signature (~3309 bytes para ML-DSA-65).

use ml_dsa::{
    EncodedVerifyingKey, Generate, KeyExport, KeyInit, Keypair, MlDsa44, MlDsa65, MlDsa87,
    Signature, Signer, SigningKey, Verifier, VerifyingKey,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlDsaVariant {
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

impl MlDsaVariant {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "mldsa44" => Ok(MlDsaVariant::MlDsa44),
            "mldsa65" => Ok(MlDsaVariant::MlDsa65),
            "mldsa87" => Ok(MlDsaVariant::MlDsa87),
            other => Err(format!(
                "Variante ML-DSA no soportada: '{other}'. Disponibles: mldsa44, mldsa65, mldsa87."
            )),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            MlDsaVariant::MlDsa44 => "mldsa44",
            MlDsaVariant::MlDsa65 => "mldsa65",
            MlDsaVariant::MlDsa87 => "mldsa87",
        }
    }
}

pub fn mldsa_keypair(variant: MlDsaVariant) -> Result<(Vec<u8>, Vec<u8>), String> {
    match variant {
        MlDsaVariant::MlDsa44 => dsa_keypair::<MlDsa44>(),
        MlDsaVariant::MlDsa65 => dsa_keypair::<MlDsa65>(),
        MlDsaVariant::MlDsa87 => dsa_keypair::<MlDsa87>(),
    }
}

fn dsa_keypair<P>() -> Result<(Vec<u8>, Vec<u8>), String>
where
    P: ml_dsa::MlDsaParams,
{
    let sk = SigningKey::<P>::generate();
    let vk = sk.verifying_key();
    let sk_bytes = sk.to_bytes();
    let vk_bytes = vk.encode();
    Ok((sk_bytes.as_slice().to_vec(), vk_bytes.as_slice().to_vec()))
}

pub fn mldsa_sign(variant: MlDsaVariant, private_key_seed: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
    match variant {
        MlDsaVariant::MlDsa44 => dsa_sign::<MlDsa44>(private_key_seed, message),
        MlDsaVariant::MlDsa65 => dsa_sign::<MlDsa65>(private_key_seed, message),
        MlDsaVariant::MlDsa87 => dsa_sign::<MlDsa87>(private_key_seed, message),
    }
}

fn dsa_sign<P>(private_key_seed: &[u8], message: &[u8]) -> Result<Vec<u8>, String>
where
    P: ml_dsa::MlDsaParams,
{
    if private_key_seed.len() != 32 {
        return Err(format!(
            "La clave privada ML-DSA debe tener 32 bytes (seed), se recibieron {}.",
            private_key_seed.len()
        ));
    }
    let sk = SigningKey::<P>::new_from_slice(private_key_seed)
        .map_err(|_| "Seed ML-DSA de longitud inválida.".to_string())?;
    let sig = sk.sign(message);
    Ok(sig.encode().as_slice().to_vec())
}

pub fn mldsa_verify(
    variant: MlDsaVariant,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, String> {
    match variant {
        MlDsaVariant::MlDsa44 => dsa_verify::<MlDsa44>(public_key, message, signature),
        MlDsaVariant::MlDsa65 => dsa_verify::<MlDsa65>(public_key, message, signature),
        MlDsaVariant::MlDsa87 => dsa_verify::<MlDsa87>(public_key, message, signature),
    }
}

fn dsa_verify<P>(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, String>
where
    P: ml_dsa::MlDsaParams,
{
    let enc = EncodedVerifyingKey::<P>::try_from(public_key)
        .map_err(|_| "Clave pública ML-DSA de longitud inválida.".to_string())?;
    let vk = VerifyingKey::<P>::decode(&enc);

    let sig = Signature::<P>::try_from(signature)
        .map_err(|_| "Firma ML-DSA de longitud inválida.".to_string())?;

    Ok(vk.verify(message, &sig).is_ok())
}
