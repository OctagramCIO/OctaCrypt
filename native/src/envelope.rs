//! Formato de sobre v0.5 de OctaCrypt.
//!
//! Layout binario (todo big-endian en los enteros):
//! ```text
//!   magic        4 bytes   "OCX1"
//!   version      1 byte    = 5
//!   algo_id      1 byte    identificador de algoritmo simétrico
//!   flags        1 byte    reservado (debe ser 0)
//!   reserved     1 byte    reservado (debe ser 0)
//!   aad_len      4 bytes   longitud del AAD (metadatos autenticados)
//!   aad          aad_len bytes
//!   nonce_len    1 byte    longitud del nonce (<= 32)
//!   nonce        nonce_len bytes
//!   ct           resto      ciphertext + tag (AEAD)
//! ```
//!
//! El AAD del AEAD es exactamente la cabecera fija + campos de longitud y el
//! propio AAD; de este modo cualquier manipulación del encabezado invalida el
//! tag. Esto hace el formato v0.5 intrínsecamente autenticado.

pub const MAGIC: [u8; 4] = *b"OCX1";
pub const VERSION: u8 = 5;
pub const HEADER_FIXED_LEN: usize = 12; // magic(4)+ver(1)+algo(1)+flags(1)+reserv(1)+aad_len(4)

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algo {
    AesGcm = 1,
    ChaCha20Poly1305 = 2,
}

impl Algo {
    pub fn from_id(id: u8) -> Result<Self, String> {
        match id {
            1 => Ok(Algo::AesGcm),
            2 => Ok(Algo::ChaCha20Poly1305),
            other => Err(format!("algo_id desconocido en sobre v0.5: {other}")),
        }
    }

    pub fn id(&self) -> u8 {
        match self {
            Algo::AesGcm => 1,
            Algo::ChaCha20Poly1305 => 2,
        }
    }
}

/// Construye la cabecera de sobre v0.5. Devuelve (header_bytes, aad_autenticado).
pub fn build_header(algo: Algo, nonce: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    if nonce.len() > 32 {
        return Err("El nonce no puede superar 32 bytes.".to_string());
    }
    if aad.len() > u32::MAX as usize {
        return Err("AAD demasiado grande.".to_string());
    }

    let mut header = Vec::with_capacity(HEADER_FIXED_LEN + aad.len() + 1 + nonce.len());
    header.extend_from_slice(&MAGIC);
    header.push(VERSION);
    header.push(algo.id());
    header.push(0); // flags
    header.push(0); // reserved
    header.extend_from_slice(&(aad.len() as u32).to_be_bytes());
    header.extend_from_slice(aad);
    header.push(nonce.len() as u8);
    header.extend_from_slice(nonce);
    Ok(header)
}

/// Cabecera parseada de un sobre v0.5.
#[derive(Debug, Clone)]
pub struct ParsedHeader {
    pub algo: Algo,
    pub version: u8,
    pub aad: Vec<u8>,
    pub nonce: Vec<u8>,
    /// Offset donde comienza el ciphertext (después del header).
    pub ct_offset: usize,
    /// Parte de la cabecera usada como AAD del AEAD.
    pub authenticated: Vec<u8>,
}

/// Indica si `data` empieza con el magic + versión de v0.5.
pub fn is_v05(data: &[u8]) -> bool {
    data.len() >= 5 && data[..4] == MAGIC && data[4] == VERSION
}

/// Parsea una cabecera de sobre v0.5.
pub fn parse_header(data: &[u8]) -> Result<ParsedHeader, String> {
    if data.len() < HEADER_FIXED_LEN {
        return Err("Sobre v0.5 demasiado corto para la cabecera.".to_string());
    }
    if data[..4] != MAGIC {
        return Err("Magic de sobre v0.5 inválido.".to_string());
    }
    let version = data[4];
    if version != VERSION {
        return Err(format!(
            "Versión de sobre no soportada: {version} (se esperaba {VERSION})."
        ));
    }
    let algo = Algo::from_id(data[5])?;
    // data[6]=flags, data[7]=reserved (reservados)

    let mut aad_len_bytes = [0u8; 4];
    aad_len_bytes.copy_from_slice(&data[8..12]);
    let aad_len = u32::from_be_bytes(aad_len_bytes) as usize;

    let aad_start = HEADER_FIXED_LEN;
    let aad_end = aad_start
        .checked_add(aad_len)
        .ok_or_else(|| "Longitud de AAD desborda.".to_string())?;
    if data.len() < aad_end + 1 {
        return Err("Sobre v0.5 truncado en el AAD o en la longitud del nonce.".to_string());
    }
    let aad = data[aad_start..aad_end].to_vec();

    let nonce_len = data[aad_end] as usize;
    let nonce_start = aad_end + 1;
    let nonce_end = nonce_start
        .checked_add(nonce_len)
        .ok_or_else(|| "Longitud de nonce desborda.".to_string())?;
    if data.len() < nonce_end {
        return Err("Sobre v0.5 truncado en el nonce.".to_string());
    }
    let nonce = data[nonce_start..nonce_end].to_vec();

    let authenticated = data[..nonce_end].to_vec();

    Ok(ParsedHeader {
        algo,
        version,
        aad,
        nonce,
        ct_offset: nonce_end,
        authenticated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_header() {
        let aad = b"filename.txt";
        let nonce = [7u8; 12];
        let header = build_header(Algo::AesGcm, &nonce, aad).unwrap();
        let parsed = parse_header(&header).unwrap();
        assert_eq!(parsed.algo, Algo::AesGcm);
        assert_eq!(parsed.aad, aad);
        assert_eq!(parsed.nonce, nonce);
        assert_eq!(parsed.ct_offset, header.len());
        assert!(is_v05(&header));
    }

    #[test]
    fn rejects_bad_magic() {
        let mut header = build_header(Algo::ChaCha20Poly1305, &[0u8; 12], b"").unwrap();
        header[0] = b'X';
        assert!(parse_header(&header).is_err());
    }
}
