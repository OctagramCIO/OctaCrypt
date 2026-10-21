//! Encapsulación de claves post-cuántica (ML-KEM, FIPS 203).
//!
//! Formatos de bytes estables y compactos:
//!   - Clave privada (decapsulation): 64-byte seed (forma recomendada por FIPS 203).
//!   - Clave pública (encapsulation): clave serializada (~1184 bytes para 768).
//!   - Ciphertext: ~1088 bytes para ML-KEM-768.
//!   - Shared secret: 32 bytes.

use ml_kem::kem::Encapsulate;
use ml_kem::{
    ml_kem_1024, ml_kem_512, ml_kem_768, Ciphertext, Decapsulate, Generate, KeyExport, Seed,
    TryKeyInit,
};

/// Identificador de variante admitido por la capa Python.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlKemVariant {
    MlKem512,
    MlKem768,
    MlKem1024,
}

impl MlKemVariant {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "mlkem512" => Ok(MlKemVariant::MlKem512),
            "mlkem768" => Ok(MlKemVariant::MlKem768),
            "mlkem1024" => Ok(MlKemVariant::MlKem1024),
            other => Err(format!(
                "Variante ML-KEM no soportada: '{other}'. Disponibles: mlkem512, mlkem768, mlkem1024."
            )),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            MlKemVariant::MlKem512 => "mlkem512",
            MlKemVariant::MlKem768 => "mlkem768",
            MlKemVariant::MlKem1024 => "mlkem1024",
        }
    }
}

pub fn mlkem_keypair(variant: MlKemVariant) -> Result<(Vec<u8>, Vec<u8>), String> {
    match variant {
        MlKemVariant::MlKem512 => {
            let dk = ml_kem_512::DecapsulationKey::generate();
            let seed = dk
                .to_seed()
                .ok_or_else(|| "La clave generada no expone seed.".to_string())?;
            let ek = dk.encapsulation_key();
            Ok((seed.as_slice().to_vec(), ek.to_bytes().as_slice().to_vec()))
        }
        MlKemVariant::MlKem768 => {
            let dk = ml_kem_768::DecapsulationKey::generate();
            let seed = dk
                .to_seed()
                .ok_or_else(|| "La clave generada no expone seed.".to_string())?;
            let ek = dk.encapsulation_key();
            Ok((seed.as_slice().to_vec(), ek.to_bytes().as_slice().to_vec()))
        }
        MlKemVariant::MlKem1024 => {
            let dk = ml_kem_1024::DecapsulationKey::generate();
            let seed = dk
                .to_seed()
                .ok_or_else(|| "La clave generada no expone seed.".to_string())?;
            let ek = dk.encapsulation_key();
            Ok((seed.as_slice().to_vec(), ek.to_bytes().as_slice().to_vec()))
        }
    }
}

pub fn mlkem_encapsulate(
    variant: MlKemVariant,
    public_key: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    match variant {
        MlKemVariant::MlKem512 => {
            let ek = ml_kem_512::EncapsulationKey::new_from_slice(public_key)
                .map_err(|_| "Clave pública ML-KEM-512 inválida.".to_string())?;
            let (ct, shared) = ek.encapsulate();
            Ok((shared.as_slice().to_vec(), ct.as_slice().to_vec()))
        }
        MlKemVariant::MlKem768 => {
            let ek = ml_kem_768::EncapsulationKey::new_from_slice(public_key)
                .map_err(|_| "Clave pública ML-KEM-768 inválida.".to_string())?;
            let (ct, shared) = ek.encapsulate();
            Ok((shared.as_slice().to_vec(), ct.as_slice().to_vec()))
        }
        MlKemVariant::MlKem1024 => {
            let ek = ml_kem_1024::EncapsulationKey::new_from_slice(public_key)
                .map_err(|_| "Clave pública ML-KEM-1024 inválida.".to_string())?;
            let (ct, shared) = ek.encapsulate();
            Ok((shared.as_slice().to_vec(), ct.as_slice().to_vec()))
        }
    }
}

pub fn mlkem_decapsulate(
    variant: MlKemVariant,
    private_key_seed: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, String> {
    if ciphertext.is_empty() {
        return Err("Ciphertext ML-KEM vacío.".to_string());
    }
    let seed = seed_from_slice(private_key_seed)?;
    match variant {
        MlKemVariant::MlKem512 => {
            let dk = ml_kem_512::DecapsulationKey::from_seed(seed);
            let ct = Ciphertext::<ml_kem_512::MlKem512>::try_from(ciphertext)
                .map_err(|_| "Ciphertext ML-KEM-512 de longitud inválida.".to_string())?;
            let shared = dk.decapsulate(&ct);
            Ok(shared.as_slice().to_vec())
        }
        MlKemVariant::MlKem768 => {
            let dk = ml_kem_768::DecapsulationKey::from_seed(seed);
            let ct = Ciphertext::<ml_kem_768::MlKem768>::try_from(ciphertext)
                .map_err(|_| "Ciphertext ML-KEM-768 de longitud inválida.".to_string())?;
            let shared = dk.decapsulate(&ct);
            Ok(shared.as_slice().to_vec())
        }
        MlKemVariant::MlKem1024 => {
            let dk = ml_kem_1024::DecapsulationKey::from_seed(seed);
            let ct = Ciphertext::<ml_kem_1024::MlKem1024>::try_from(ciphertext)
                .map_err(|_| "Ciphertext ML-KEM-1024 de longitud inválida.".to_string())?;
            let shared = dk.decapsulate(&ct);
            Ok(shared.as_slice().to_vec())
        }
    }
}

fn seed_from_slice(private_key_seed: &[u8]) -> Result<Seed, String> {
    if private_key_seed.len() != 64 {
        return Err(format!(
            "La clave privada ML-KEM debe tener 64 bytes (seed), se recibieron {}.",
            private_key_seed.len()
        ));
    }
    let mut seed = Seed::default();
    seed.copy_from_slice(private_key_seed);
    Ok(seed)
}
