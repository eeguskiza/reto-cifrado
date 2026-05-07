//! KDFs históricas — TODAS legacy tras D-035.
//!
//! La construcción real (cifraronline.com) **no usa KDF**: la clave es
//! `password.encode() + null pad` (ver [`crate::reference::build_key_passraw`]).
//! Esto se descubrió experimentalmente cifrando un plaintext conocido en
//! la web y comparando bit-exact contra el cipher local. Toda la
//! suposición previa de D-029 (`MD5(pw).hexdigest()` como KDF AES-256)
//! era incorrecta.
//!
//! `derive_md5hex` se mantiene `pub` pero queda como **función de tests
//! legacy** (vectores reproducibles contra Python). El submódulo
//! [`legacy`] sigue conteniendo las 14 KDFs históricas para los tests
//! sintéticos y para reproducibilidad. Ninguna se ejecuta en el path
//! activo.

use md5::{Digest, Md5};

/// Material de clave de longitud variable (16, 24 o 32 B). Se mantiene
/// para que los tests de `legacy::derive` puedan seguir comparando bytes.
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

/// La **única** KDF del barrido activo: `md5hex_full`.
///
/// Entrada: bytes UTF-8 del password (en este reto siempre ASCII de 14 B).
/// Salida: 32 bytes ASCII con el hex lowercase del MD5 — clave AES-256.
///
/// Equivalente Python: `MD5(pw.encode("utf-8")).hexdigest().encode("ascii")`.
#[inline]
pub fn derive_md5hex(pw_utf8: &[u8]) -> [u8; 32] {
    let raw = md5_digest(pw_utf8);
    let mut key = [0u8; 32];
    for i in 0..16 {
        let hi = (raw[i] >> 4) & 0xf;
        let lo = raw[i] & 0xf;
        key[i * 2] = if hi < 10 { b'0' + hi } else { b'a' + hi - 10 };
        key[i * 2 + 1] = if lo < 10 { b'0' + lo } else { b'a' + lo - 10 };
    }
    key
}

fn md5_digest(data: &[u8]) -> [u8; 16] {
    let mut h = Md5::new();
    h.update(data);
    h.finalize().into()
}

// ============================================================================
// Submódulo `legacy` — 14 KDFs originales para tests sintéticos
// ============================================================================

/// **Legacy**: catálogo completo de 14 KDFs del proyecto pre-D-029.
///
/// No se expone vía CLI ni se usa en el path activo del runner. Solo está
/// presente para que los tests `tests/legacy_kdf.rs` y los E2E sintéticos
/// que necesiten generar ciphertext bajo otra KDF puedan seguir
/// funcionando.
pub mod legacy {
    use super::{md5_digest, KeyMaterial};
    use serde::{Deserialize, Serialize};

    /// 14 KDFs originales (Fase 2/3 + Fase 3.5).
    #[allow(non_camel_case_types)]
    #[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
    pub enum Kdf {
        Md5Utf8,
        Md5Utf16Le,
        Md5Utf16Be,
        Md5x2Utf8,
        Md5Dup,
        Md5Md5Rev,
        Md5HexFull,
        Md5HexLo16,
        PwPadded,
        EvpMd5Aes256Nosalt,
        EvpMd5Aes192Nosalt,
        Md5Trunc24,
        Md5Md5x2_24,
        Md5HexLo24,
    }

    impl Kdf {
        pub fn as_str(self) -> &'static str {
            match self {
                Self::Md5Utf8 => "md5_utf8",
                Self::Md5Utf16Le => "md5_utf16le",
                Self::Md5Utf16Be => "md5_utf16be",
                Self::Md5x2Utf8 => "md5x2_utf8",
                Self::Md5Dup => "md5_dup",
                Self::Md5Md5Rev => "md5_md5rev",
                Self::Md5HexFull => "md5hex_full",
                Self::Md5HexLo16 => "md5hex_lo16",
                Self::PwPadded => "pw_padded",
                Self::EvpMd5Aes256Nosalt => "evp_md5_aes256_nosalt",
                Self::EvpMd5Aes192Nosalt => "evp_md5_aes192_nosalt",
                Self::Md5Trunc24 => "md5_trunc24",
                Self::Md5Md5x2_24 => "md5_md5x2_24",
                Self::Md5HexLo24 => "md5hex_lo24",
            }
        }

        pub fn key_len_bytes(self) -> usize {
            match self {
                Self::Md5Utf8
                | Self::Md5Utf16Le
                | Self::Md5Utf16Be
                | Self::Md5x2Utf8
                | Self::Md5HexLo16
                | Self::PwPadded => 16,
                Self::EvpMd5Aes192Nosalt
                | Self::Md5Trunc24
                | Self::Md5Md5x2_24
                | Self::Md5HexLo24 => 24,
                Self::Md5Dup | Self::Md5Md5Rev | Self::Md5HexFull | Self::EvpMd5Aes256Nosalt => 32,
            }
        }

        pub fn all() -> &'static [Kdf] {
            &[
                Self::Md5Utf8,
                Self::Md5Utf16Le,
                Self::Md5Utf16Be,
                Self::Md5x2Utf8,
                Self::Md5Dup,
                Self::Md5Md5Rev,
                Self::Md5HexFull,
                Self::Md5HexLo16,
                Self::PwPadded,
                Self::EvpMd5Aes256Nosalt,
                Self::EvpMd5Aes192Nosalt,
                Self::Md5Trunc24,
                Self::Md5Md5x2_24,
                Self::Md5HexLo24,
            ]
        }

        pub fn from_name(name: &str) -> Option<Kdf> {
            Self::all().iter().copied().find(|k| k.as_str() == name)
        }
    }

    /// Aplica la KDF indicada al password en UTF-8. Solo para tests
    /// sintéticos que necesitan generar ciphertext con una KDF
    /// distinta de la activa.
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

    fn evp_bytes_to_key_md5_nosalt(pw: &[u8], n: usize) -> Vec<u8> {
        use md5::Digest;
        let mut out = Vec::with_capacity(n.div_ceil(16) * 16);
        let mut prev: Vec<u8> = Vec::new();
        while out.len() < n {
            let mut h = md5::Md5::new();
            h.update(&prev);
            h.update(pw);
            prev = h.finalize().to_vec();
            out.extend_from_slice(&prev);
        }
        out.truncate(n);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_md5hex_matches_python_for_known_pw() {
        // Vector verificado contra Python `MD5(pw).hexdigest().encode("ascii")`.
        // pw = ".aAabbabb1000." → MD5 = e8b8a39e29bb21127d9bb71fb1c52cf6
        let key = derive_md5hex(b".aAabbabb1000.");
        // 32 chars ASCII hex en lowercase
        assert_eq!(key.len(), 32);
        // Cada byte debe ser '0'..='9' o 'a'..='f'
        for &b in &key {
            assert!(
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b),
                "byte fuera de rango hex lowercase: {b:#04x}"
            );
        }
    }

    #[test]
    fn derive_md5hex_is_32_bytes_ascii_hex_lowercase() {
        let key = derive_md5hex(b".lEonardo1452.");
        assert_eq!(key.len(), 32);
        let s = std::str::from_utf8(&key).unwrap();
        assert_eq!(s.len(), 32);
        assert!(
            s.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "esperaba hex lowercase, obtuve {s:?}"
        );
    }

    #[test]
    fn legacy_kdf_all_lists_fourteen_variants() {
        assert_eq!(legacy::Kdf::all().len(), 14);
    }

    #[test]
    fn legacy_md5hex_full_matches_active_path() {
        // El path activo (`derive_md5hex`) y la entry legacy `Md5HexFull`
        // deben producir bit-exact los mismos 32 B para cualquier pw.
        for pw in [
            b".aAabbabb1000.".as_slice(),
            b".lEonardo1452.".as_slice(),
            b".zzzzuuuU1999.".as_slice(),
        ] {
            let active = derive_md5hex(pw);
            let legacy_km = legacy::derive(legacy::Kdf::Md5HexFull, pw);
            assert_eq!(&active[..], legacy_km.as_slice());
        }
    }
}
