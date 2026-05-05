//! Las 14 funciones de derivación de clave (Fase 2 + Fase 3.5).
//!
//! Todas operan sobre `pw_utf8: &[u8]`, los bytes UTF-8 del password
//! candidato (que en este reto siempre es ASCII de 14 bytes).
//!
//! **Vectores de validación**: ver `tests/kdf.rs`. Todos los outputs
//! están comparados byte a byte contra `hashlib` de Python para tres
//! passwords muestra antes de pasar a CUDA.

use md5::{Digest, Md5};

use crate::config::Kdf;

/// Material de clave de longitud variable (16, 24 o 32 B).
///
/// **Decisión D-013**: pasamos de `enum K16/K24/K32` a un `struct(Vec<u8>)`
/// genérico al añadir AES-192 en Fase 3.5. Más simple que un enum con tres
/// variantes-array y la API pública (`as_slice`, `len`) queda idéntica.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct KeyMaterial(Vec<u8>);

impl KeyMaterial {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Aplica la KDF indicada al password en UTF-8.
pub fn derive(kdf: Kdf, pw_utf8: &[u8]) -> KeyMaterial {
    let bytes: Vec<u8> = match kdf {
        Kdf::Md5Utf8 => md5_digest(pw_utf8).to_vec(),
        Kdf::Md5Utf16Le => md5_digest(&utf16le(pw_utf8)).to_vec(),
        Kdf::Md5Utf16Be => md5_digest(&utf16be(pw_utf8)).to_vec(),
        Kdf::Md5x2Utf8 => {
            let h1 = md5_digest(pw_utf8);
            md5_digest(&h1).to_vec()
        }
        Kdf::Md5Dup => {
            let h = md5_digest(pw_utf8);
            let mut k = Vec::with_capacity(32);
            k.extend_from_slice(&h);
            k.extend_from_slice(&h);
            k
        }
        Kdf::Md5Md5Rev => {
            let h = md5_digest(pw_utf8);
            let mut k = Vec::with_capacity(32);
            k.extend_from_slice(&h);
            for i in 0..16 {
                k.push(h[15 - i]);
            }
            k
        }
        Kdf::Md5HexFull => hex::encode(md5_digest(pw_utf8)).into_bytes(),
        Kdf::Md5HexLo16 => {
            let hex_str = hex::encode(md5_digest(pw_utf8));
            hex_str.as_bytes()[..16].to_vec()
        }
        Kdf::PwPadded => {
            let mut k = vec![0u8; 16];
            let take = pw_utf8.len().min(16);
            k[..take].copy_from_slice(&pw_utf8[..take]);
            k
        }
        // ----- Fase 3.5 -----
        Kdf::EvpMd5Aes256Nosalt => evp_bytes_to_key_md5_nosalt(pw_utf8, 32),
        Kdf::EvpMd5Aes192Nosalt => evp_bytes_to_key_md5_nosalt(pw_utf8, 24),
        Kdf::Md5Trunc24 => {
            let h = md5_digest(pw_utf8);
            let mut k = Vec::with_capacity(24);
            k.extend_from_slice(&h);
            k.extend_from_slice(&h[..8]);
            k
        }
        Kdf::Md5Md5x2_24 => {
            let h1 = md5_digest(pw_utf8);
            let h2 = md5_digest(&h1);
            let mut k = Vec::with_capacity(24);
            k.extend_from_slice(&h1);
            k.extend_from_slice(&h2[..8]);
            k
        }
        Kdf::Md5HexLo24 => {
            let hex_str = hex::encode(md5_digest(pw_utf8));
            hex_str.as_bytes()[..24].to_vec()
        }
    };
    debug_assert_eq!(
        bytes.len(),
        kdf.key_len_bytes(),
        "kdf {} declara klen {} pero produjo {}",
        kdf.as_str(),
        kdf.key_len_bytes(),
        bytes.len()
    );
    KeyMaterial::from_bytes(bytes)
}

fn md5_digest(data: &[u8]) -> [u8; 16] {
    let mut h = Md5::new();
    h.update(data);
    h.finalize().into()
}

fn utf16le(ascii: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ascii.len() * 2);
    for &b in ascii {
        out.push(b);
        out.push(0);
    }
    out
}

fn utf16be(ascii: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ascii.len() * 2);
    for &b in ascii {
        out.push(0);
        out.push(b);
    }
    out
}

/// `EVP_BytesToKey(MD5, password, salt=None, iter=1)` truncado a `n` bytes.
///
/// Algoritmo:
///   `D_0 = b""`,  `D_i = MD5(D_{i-1} ‖ password)`
///   output = primeros `n` bytes de `D_1 ‖ D_2 ‖ ...`
///
/// Coincide con el comportamiento de OpenSSL `EVP_BytesToKey` cuando
/// se pide solo material de clave (key_len = n) sin sal.
fn evp_bytes_to_key_md5_nosalt(pw: &[u8], n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n.div_ceil(16) * 16);
    let mut prev: Vec<u8> = Vec::new();
    while out.len() < n {
        let mut h = Md5::new();
        h.update(&prev);
        h.update(pw);
        prev = h.finalize().to_vec();
        out.extend_from_slice(&prev);
    }
    out.truncate(n);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lengths_match_advertised_klen() {
        let pw = b".aAaabbbb1000.";
        for &kdf in Kdf::all() {
            let k = derive(kdf, pw);
            assert_eq!(
                k.len(),
                kdf.key_len_bytes(),
                "kdf={} debe producir {} B, produjo {}",
                kdf.as_str(),
                kdf.key_len_bytes(),
                k.len()
            );
        }
    }

    #[test]
    fn evp_first_block_matches_md5_utf8() {
        // EVP_BytesToKey nosalt iter=1: D_1 = MD5(pw). Por tanto, los primeros
        // 16 bytes de evp_md5_aes256_nosalt deben coincidir con md5_utf8.
        for pw in [b".aAaabbbb1000.", b".zzzzuuuU1999."] {
            let evp = derive(Kdf::EvpMd5Aes256Nosalt, pw);
            let md5 = derive(Kdf::Md5Utf8, pw);
            assert_eq!(&evp.as_slice()[..16], md5.as_slice());
        }
    }

    #[test]
    fn evp_192_is_first_24_bytes_of_evp_256() {
        for pw in [b".aAaabbbb1000.", b".bAioembl1452."] {
            let evp32 = derive(Kdf::EvpMd5Aes256Nosalt, pw);
            let evp24 = derive(Kdf::EvpMd5Aes192Nosalt, pw);
            assert_eq!(&evp32.as_slice()[..24], evp24.as_slice());
        }
    }
}
