//! Las 9 funciones de derivación de clave (§3.1 de la spec).
//!
//! Todas operan sobre `pw_utf8: &[u8]`, los bytes UTF-8 del password
//! candidato (que en este reto siempre es ASCII de 14 bytes).
//!
//! **Vectores de validación**: ver `tests/kdf.rs`. Todos los outputs aquí
//! están comparados byte a byte contra `hashlib` de Python para tres
//! passwords muestra antes de pasar a Fase 3.

use md5::{Digest, Md5};

use crate::config::Kdf;

/// Material de clave: 16 ó 32 bytes según la KDF.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum KeyMaterial {
    K16([u8; 16]),
    K32([u8; 32]),
}

impl KeyMaterial {
    pub fn as_slice(&self) -> &[u8] {
        match self {
            Self::K16(k) => k,
            Self::K32(k) => k,
        }
    }
    pub fn len(&self) -> usize {
        self.as_slice().len()
    }
    pub fn is_empty(&self) -> bool {
        false
    }
}

/// Aplica la KDF indicada al password en UTF-8.
pub fn derive(kdf: Kdf, pw_utf8: &[u8]) -> KeyMaterial {
    match kdf {
        Kdf::Md5Utf8 => KeyMaterial::K16(md5_digest(pw_utf8)),
        Kdf::Md5Utf16Le => KeyMaterial::K16(md5_digest(&utf16le(pw_utf8))),
        Kdf::Md5Utf16Be => KeyMaterial::K16(md5_digest(&utf16be(pw_utf8))),
        Kdf::Md5x2Utf8 => {
            let h1 = md5_digest(pw_utf8);
            KeyMaterial::K16(md5_digest(&h1))
        }
        Kdf::Md5Dup => {
            let h = md5_digest(pw_utf8);
            let mut k = [0u8; 32];
            k[..16].copy_from_slice(&h);
            k[16..].copy_from_slice(&h);
            KeyMaterial::K32(k)
        }
        Kdf::Md5Md5Rev => {
            let h = md5_digest(pw_utf8);
            let mut k = [0u8; 32];
            k[..16].copy_from_slice(&h);
            for i in 0..16 {
                k[16 + i] = h[15 - i];
            }
            KeyMaterial::K32(k)
        }
        Kdf::Md5HexFull => {
            let h = md5_digest(pw_utf8);
            let hex = hex::encode(h); // 32 ASCII chars, lowercase
            let mut k = [0u8; 32];
            k.copy_from_slice(hex.as_bytes());
            KeyMaterial::K32(k)
        }
        Kdf::Md5HexLo16 => {
            let h = md5_digest(pw_utf8);
            let hex = hex::encode(h);
            let mut k = [0u8; 16];
            k.copy_from_slice(&hex.as_bytes()[..16]);
            KeyMaterial::K16(k)
        }
        Kdf::PwPadded => {
            let mut k = [0u8; 16];
            let take = pw_utf8.len().min(16);
            k[..take].copy_from_slice(&pw_utf8[..take]);
            KeyMaterial::K16(k)
        }
    }
}

fn md5_digest(data: &[u8]) -> [u8; 16] {
    let mut h = Md5::new();
    h.update(data);
    h.finalize().into()
}

fn utf16le(ascii: &[u8]) -> Vec<u8> {
    // Para texto ASCII, utf-16-le es cada byte seguido de 0x00.
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
}
