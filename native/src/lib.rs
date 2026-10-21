//! Núcleo criptográfico nativo de OctaCrypt expuesto a Python vía PyO3.
//!
//! Todas las funciones trabajan con `bytes`/`bytearray` de Python y devuelven
//! `bytes`, o lanzan `ValueError` con mensajes descriptivos en caso de error.
//! La capa Python (CLI/TUI) detecta este módulo y lo usa cuando está disponible.

mod dsa;
mod envelope;
mod kem;
mod sign;
mod symmetric;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use dsa::MlDsaVariant;
use envelope::Algo;
use kem::MlKemVariant;

type BytesOut = Py<PyBytes>;

fn err(e: String) -> PyErr {
    PyValueError::new_err(e)
}

fn as_bytes(py: Python<'_>, data: &[u8]) -> BytesOut {
    PyBytes::new(py, data).unbind()
}

// ---------------------------------------------------------------------------
// Simétrico
// ---------------------------------------------------------------------------

#[pyfunction]
#[pyo3(signature = (key, plaintext, aad=None))]
fn aes_gcm_encrypt(py: Python<'_>, key: &[u8], plaintext: &[u8], aad: Option<&[u8]>) -> PyResult<BytesOut> {
    let out = symmetric::aes_gcm_encrypt(key, plaintext, aad.unwrap_or(&[])).map_err(err)?;
    Ok(as_bytes(py, &out))
}

#[pyfunction]
#[pyo3(signature = (key, data, aad=None))]
fn aes_gcm_decrypt(py: Python<'_>, key: &[u8], data: &[u8], aad: Option<&[u8]>) -> PyResult<BytesOut> {
    let out = symmetric::aes_gcm_decrypt(key, data, aad.unwrap_or(&[])).map_err(err)?;
    Ok(as_bytes(py, &out))
}

#[pyfunction]
#[pyo3(signature = (key, plaintext, aad=None))]
fn chacha20_encrypt(py: Python<'_>, key: &[u8], plaintext: &[u8], aad: Option<&[u8]>) -> PyResult<BytesOut> {
    let out = symmetric::chacha_encrypt(key, plaintext, aad.unwrap_or(&[])).map_err(err)?;
    Ok(as_bytes(py, &out))
}

#[pyfunction]
#[pyo3(signature = (key, data, aad=None))]
fn chacha20_decrypt(py: Python<'_>, key: &[u8], data: &[u8], aad: Option<&[u8]>) -> PyResult<BytesOut> {
    let out = symmetric::chacha_decrypt(key, data, aad.unwrap_or(&[])).map_err(err)?;
    Ok(as_bytes(py, &out))
}

// ---------------------------------------------------------------------------
// ML-KEM (FIPS 203)
// ---------------------------------------------------------------------------

#[pyfunction]
#[pyo3(signature = (variant = "mlkem768"))]
fn mlkem_keypair(py: Python<'_>, variant: &str) -> PyResult<(BytesOut, BytesOut)> {
    let v = MlKemVariant::from_str(variant).map_err(err)?;
    let (sk, pk) = kem::mlkem_keypair(v).map_err(err)?;
    Ok((as_bytes(py, &sk), as_bytes(py, &pk)))
}

#[pyfunction]
#[pyo3(signature = (public_key, variant = "mlkem768"))]
fn mlkem_encapsulate(
    py: Python<'_>,
    public_key: &[u8],
    variant: &str,
) -> PyResult<(BytesOut, BytesOut)> {
    let v = MlKemVariant::from_str(variant).map_err(err)?;
    let (shared, ct) = kem::mlkem_encapsulate(v, public_key).map_err(err)?;
    Ok((as_bytes(py, &shared), as_bytes(py, &ct)))
}

#[pyfunction]
#[pyo3(signature = (private_key, ciphertext, variant = "mlkem768"))]
fn mlkem_decapsulate(
    py: Python<'_>,
    private_key: &[u8],
    ciphertext: &[u8],
    variant: &str,
) -> PyResult<BytesOut> {
    let v = MlKemVariant::from_str(variant).map_err(err)?;
    let shared = kem::mlkem_decapsulate(v, private_key, ciphertext).map_err(err)?;
    Ok(as_bytes(py, &shared))
}

// ---------------------------------------------------------------------------
// ML-DSA (FIPS 204)
// ---------------------------------------------------------------------------

#[pyfunction]
#[pyo3(signature = (variant = "mldsa65"))]
fn mldsa_keypair(py: Python<'_>, variant: &str) -> PyResult<(BytesOut, BytesOut)> {
    let v = MlDsaVariant::from_str(variant).map_err(err)?;
    let (sk, pk) = dsa::mldsa_keypair(v).map_err(err)?;
    Ok((as_bytes(py, &sk), as_bytes(py, &pk)))
}

#[pyfunction]
#[pyo3(signature = (private_key, message, variant = "mldsa65"))]
fn mldsa_sign(py: Python<'_>, private_key: &[u8], message: &[u8], variant: &str) -> PyResult<BytesOut> {
    let v = MlDsaVariant::from_str(variant).map_err(err)?;
    let sig = dsa::mldsa_sign(v, private_key, message).map_err(err)?;
    Ok(as_bytes(py, &sig))
}

#[pyfunction]
#[pyo3(signature = (public_key, message, signature, variant = "mldsa65"))]
fn mldsa_verify(public_key: &[u8], message: &[u8], signature: &[u8], variant: &str) -> PyResult<bool> {
    let v = MlDsaVariant::from_str(variant).map_err(err)?;
    dsa::mldsa_verify(v, public_key, message, signature).map_err(err)
}

// ---------------------------------------------------------------------------
// Ed25519
// ---------------------------------------------------------------------------

#[pyfunction]
fn ed25519_keypair(py: Python<'_>) -> PyResult<(BytesOut, BytesOut)> {
    let (sk, pk) = sign::ed25519_keypair().map_err(err)?;
    Ok((as_bytes(py, &sk), as_bytes(py, &pk)))
}

#[pyfunction]
fn ed25519_sign(py: Python<'_>, private_key: &[u8], message: &[u8]) -> PyResult<BytesOut> {
    let sig = sign::ed25519_sign(private_key, message).map_err(err)?;
    Ok(as_bytes(py, &sig))
}

#[pyfunction]
fn ed25519_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> PyResult<bool> {
    sign::ed25519_verify(public_key, message, signature).map_err(err)
}

#[pyfunction]
fn ed25519_public_from_private(py: Python<'_>, private_key: &[u8]) -> PyResult<BytesOut> {
    let pk = sign::ed25519_public_from_private(private_key).map_err(err)?;
    Ok(as_bytes(py, &pk))
}

// ---------------------------------------------------------------------------
// Sobre v0.5
// ---------------------------------------------------------------------------

#[pyfunction]
fn envelope_build_header(py: Python<'_>, algo: &str, nonce: &[u8], aad: &[u8]) -> PyResult<BytesOut> {
    let algo = match algo.to_ascii_lowercase().as_str() {
        "aes" | "aes-gcm" | "aes256gcm" => Algo::AesGcm,
        "chacha" | "chacha20" | "chacha20poly1305" => Algo::ChaCha20Poly1305,
        other => return Err(err(format!("Algoritmo desconocido para sobre: '{other}'."))),
    };
    let header = envelope::build_header(algo, nonce, aad).map_err(err)?;
    Ok(as_bytes(py, &header))
}

#[pyfunction]
fn envelope_is_v05(data: &[u8]) -> bool {
    envelope::is_v05(data)
}

/// Devuelve (algo_id, version, aad, nonce, ct_offset) o lanza ValueError.
#[pyfunction]
fn envelope_parse_header(
    py: Python<'_>,
    data: &[u8],
) -> PyResult<(u8, u8, BytesOut, BytesOut, usize)> {
    let h = envelope::parse_header(data).map_err(err)?;
    Ok((h.algo.id(), h.version, as_bytes(py, &h.aad), as_bytes(py, &h.nonce), h.ct_offset))
}

// ---------------------------------------------------------------------------
// Metadatos
// ---------------------------------------------------------------------------

#[pyfunction]
fn core_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[pymodule]
fn octacrypt_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(aes_gcm_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(aes_gcm_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(chacha20_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(chacha20_decrypt, m)?)?;

    m.add_function(wrap_pyfunction!(mlkem_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(mlkem_encapsulate, m)?)?;
    m.add_function(wrap_pyfunction!(mlkem_decapsulate, m)?)?;

    m.add_function(wrap_pyfunction!(mldsa_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(mldsa_sign, m)?)?;
    m.add_function(wrap_pyfunction!(mldsa_verify, m)?)?;

    m.add_function(wrap_pyfunction!(ed25519_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(ed25519_sign, m)?)?;
    m.add_function(wrap_pyfunction!(ed25519_verify, m)?)?;
    m.add_function(wrap_pyfunction!(ed25519_public_from_private, m)?)?;

    m.add_function(wrap_pyfunction!(envelope_build_header, m)?)?;
    m.add_function(wrap_pyfunction!(envelope_is_v05, m)?)?;
    m.add_function(wrap_pyfunction!(envelope_parse_header, m)?)?;

    m.add_function(wrap_pyfunction!(core_version, m)?)?;

    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
