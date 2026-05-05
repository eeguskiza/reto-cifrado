//! Carga y validación del fichero objetivo (`cifrado.txt`).
//!
//! Formato: una línea base64 que tras decodificar produce **1616 bytes**
//! binarios = 16 B IV + 1600 B ciphertext (100 bloques AES de 16 B).
//! Tolerante a padding ausente y a salto de línea final.

use std::fs;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine as _;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Tamaño exacto del binario tras decodificar base64.
pub const TOTAL_BIN_LEN: usize = 1616;
/// Tamaño del IV (también tamaño de bloque AES-128).
pub const IV_LEN: usize = 16;
/// Tamaño del ciphertext.
pub const CT_LEN: usize = TOTAL_BIN_LEN - IV_LEN;
/// Bloques AES en el ciphertext.
pub const CT_BLOCKS: usize = CT_LEN / 16;

/// Errores de carga del ciphertext.
#[derive(Debug, Error)]
pub enum CiphertextError {
    #[error("no se pudo leer el fichero {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("base64 inválido: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error(
        "tamaño binario inesperado: {actual} bytes (se esperaban {expected}, \
         = {iv_len} IV + {ct_len} CT)"
    )]
    WrongSize {
        actual: usize,
        expected: usize,
        iv_len: usize,
        ct_len: usize,
    },

    #[error(
        "el ciphertext debe ser múltiplo de 16 (bloque AES); tiene {0} bytes"
    )]
    NotBlockAligned(usize),
}

/// Ciphertext objetivo cargado en memoria.
#[derive(Debug, Clone)]
pub struct Ciphertext {
    /// SHA-256 de los bytes **del fichero original** (no del binario decodificado).
    /// Esto es lo que persistimos en `plan.toml` para detectar si el usuario
    /// ha cambiado el fichero entre sesiones (§7.4).
    pub source_sha256: [u8; 32],

    /// Path original, útil para mensajes de error y persistencia.
    pub source_path: PathBuf,

    /// Bytes binarios completos, 1616 B = `iv ‖ ct`.
    pub raw: Vec<u8>,
}

impl Ciphertext {
    /// Carga, decodifica y valida el fichero indicado.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, CiphertextError> {
        let path = path.as_ref();
        let file_bytes = fs::read(path).map_err(|source| CiphertextError::Read {
            path: path.to_path_buf(),
            source,
        })?;

        let source_sha256 = sha256(&file_bytes);
        let raw = decode_base64_padding_tolerant(&file_bytes)?;

        if raw.len() != TOTAL_BIN_LEN {
            return Err(CiphertextError::WrongSize {
                actual: raw.len(),
                expected: TOTAL_BIN_LEN,
                iv_len: IV_LEN,
                ct_len: CT_LEN,
            });
        }
        if (raw.len() - IV_LEN) % 16 != 0 {
            return Err(CiphertextError::NotBlockAligned(raw.len() - IV_LEN));
        }

        Ok(Self {
            source_sha256,
            source_path: path.to_path_buf(),
            raw,
        })
    }

    /// IV (primeros 16 bytes).
    pub fn iv(&self) -> &[u8; IV_LEN] {
        // raw.len() == TOTAL_BIN_LEN garantizado en `load`.
        self.raw[..IV_LEN].try_into().expect("iv slice size")
    }

    /// Ciphertext (los 1600 bytes restantes).
    pub fn ct(&self) -> &[u8] {
        &self.raw[IV_LEN..]
    }

    /// Primer bloque del ciphertext (16 B), el que valida el kernel.
    pub fn ct_first_block(&self) -> &[u8; 16] {
        self.raw[IV_LEN..IV_LEN + 16]
            .try_into()
            .expect("first ct block size")
    }
}

/// Decodifica base64 tolerando:
/// - saltos de línea internos (`\n`, `\r`)
/// - espacios en blanco
/// - padding ausente o presente
fn decode_base64_padding_tolerant(input: &[u8]) -> Result<Vec<u8>, base64::DecodeError> {
    // Quita whitespace.
    let mut clean = Vec::with_capacity(input.len());
    for &b in input {
        if b != b'\n' && b != b'\r' && b != b' ' && b != b'\t' {
            clean.push(b);
        }
    }
    // Quita padding existente para usar el engine NO_PAD, que tolera
    // longitudes no múltiplo de 4.
    while clean.last() == Some(&b'=') {
        clean.pop();
    }
    STANDARD_NO_PAD.decode(&clean)
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tres bloques AES sintéticos, base64 con padding y newline final.
    fn synthetic_with_padding() -> Vec<u8> {
        // 1616 bytes = 1010 hex digits * 1.6... no, manually:
        let mut binary = vec![0u8; TOTAL_BIN_LEN];
        for (i, b) in binary.iter_mut().enumerate() {
            *b = (i & 0xff) as u8;
        }
        let b64 = base64::engine::general_purpose::STANDARD.encode(&binary);
        let mut out = b64.into_bytes();
        out.push(b'\n');
        out
    }

    fn synthetic_no_padding_no_newline() -> Vec<u8> {
        let mut binary = vec![0u8; TOTAL_BIN_LEN];
        for (i, b) in binary.iter_mut().enumerate() {
            *b = ((i * 31) & 0xff) as u8;
        }
        STANDARD_NO_PAD.encode(&binary).into_bytes()
    }

    fn write_tmp(name: &str, content: &[u8]) -> PathBuf {
        let dir = std::env::temp_dir().join("quattro-crack-tests");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn loads_with_padding_and_newline() {
        let p = write_tmp("padded.txt", &synthetic_with_padding());
        let ct = Ciphertext::load(&p).unwrap();
        assert_eq!(ct.raw.len(), TOTAL_BIN_LEN);
        assert_eq!(ct.iv()[0], 0);
        assert_eq!(ct.iv()[15], 15);
    }

    #[test]
    fn loads_without_padding_or_newline() {
        let p = write_tmp("nopad.txt", &synthetic_no_padding_no_newline());
        let ct = Ciphertext::load(&p).unwrap();
        assert_eq!(ct.raw.len(), TOTAL_BIN_LEN);
    }

    #[test]
    fn rejects_wrong_size() {
        // 1610 bytes binarios (un bloque corto) → tras base64 no será 1616.
        let mut bin = vec![0u8; 1610];
        for (i, b) in bin.iter_mut().enumerate() {
            *b = (i & 0xff) as u8;
        }
        let b64 = base64::engine::general_purpose::STANDARD.encode(&bin);
        let p = write_tmp("short.txt", b64.as_bytes());
        let err = Ciphertext::load(&p).unwrap_err();
        match err {
            CiphertextError::WrongSize { actual, .. } => assert_eq!(actual, 1610),
            other => panic!("expected WrongSize, got {other:?}"),
        }
    }

    #[test]
    fn iv_and_ct_split_correctly() {
        let p = write_tmp("split.txt", &synthetic_with_padding());
        let ct = Ciphertext::load(&p).unwrap();
        assert_eq!(ct.iv().len(), IV_LEN);
        assert_eq!(ct.ct().len(), CT_LEN);
        assert_eq!(ct.ct().len() % 16, 0);
        assert_eq!(ct.ct().len() / 16, CT_BLOCKS);
        // El primer bloque CT debe arrancar en byte 16 del binario.
        assert_eq!(ct.ct_first_block()[0], 16);
    }

    #[test]
    fn sha256_is_over_source_file_bytes_not_decoded() {
        // SHA-256 cubre el fichero original (incluido el newline final si existe).
        // Verificamos que dos ficheros con el mismo binario decodificado pero
        // distinto whitespace dan distinto sha256, y que el binario es el mismo.
        let with_nl = synthetic_with_padding();
        let mut without_nl = with_nl.clone();
        if without_nl.last() == Some(&b'\n') {
            without_nl.pop();
        }
        let p1 = write_tmp("withnl.txt", &with_nl);
        let p2 = write_tmp("withoutnl.txt", &without_nl);
        let c1 = Ciphertext::load(&p1).unwrap();
        let c2 = Ciphertext::load(&p2).unwrap();
        assert_eq!(c1.raw, c2.raw, "el binario decodificado debe coincidir");
        assert_ne!(
            c1.source_sha256, c2.source_sha256,
            "el sha256 cubre el fichero, no el decodificado"
        );
    }
}
