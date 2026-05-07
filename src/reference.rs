//! Descifrado AES en CPU + validación de hits con tres pasos.
//!
//! Path activo (post-D-029): **AES-256-ECB + PKCS7**. Una clave candidata
//! da un **hit confirmado** solo si pasa:
//!
//!   1. los primeros 16 bytes del plaintext coinciden con `KNOWN_PREFIX_16`
//!   2. los primeros 32 bytes coinciden con `KNOWN_PREFIX_32`
//!   3. el último bloque tiene padding PKCS7 válido
//!
//! El kernel valida (1) en GPU. La CPU valida (2) y (3). Si (1)+(2)
//! pasan pero (3) falla, eso es **estadísticamente imposible** (~2⁻¹³⁰)
//! bajo ECB con padding PKCS7 real, así que indica casi seguro un bug
//! en el kernel o en la KDF: se devuelve `HitVerdict::Pkcs7Mismatch`
//! para que el runner lo trate como evento crítico (abort + warning).
//!
//! Los helpers `decrypt_cbc_raw` / `encrypt_cbc_pkcs7` se mantienen como
//! `pub(crate)` exclusivamente para los tests sintéticos legacy
//! (`tests/legacy_kdf.rs` y similares). NO se usan en el path activo.
//!
//! Ver `DECISIONS.md` D-007 y D-029.

use aes::{Aes128, Aes192, Aes256};
use cbc::Decryptor as CbcDecryptor;
use cipher::{block_padding::NoPadding, BlockDecryptMut, BlockEncryptMut, KeyInit, KeyIvInit};
use thiserror::Error;

/// Primeros 16 bytes del plaintext (lo que valida el kernel).
pub const KNOWN_PREFIX_16: &[u8; 16] = b"Leonardo da Vinc";
/// Primeros 32 bytes del plaintext (lo que valida la CPU sobre los hits).
///
/// El layout son 17 B (`Leonardo da Vinci`) + 4 B de doble CRLF
/// (`\r\n\r\n` — línea en blanco intermedia) + 11 B (`Leonardo da`),
/// total 32 B. La constante anterior tenía un único CRLF entre los dos
/// "Leonardo da Vinci", lo que provocó que el barrido de 8 h del
/// 2026-05-07 descartara silenciosamente cualquier match real (D-034).
pub const KNOWN_PREFIX_32: &[u8; 32] = b"Leonardo da Vinci\r\n\r\nLeonardo da";

/// Resultado de validar una candidata frente al ciphertext objetivo.
///
/// `PrefixMismatch32` lleva los primeros 32 B del plaintext descifrado
/// para que el runner pueda registrarlos en el log con `info!` sin
/// recalcular el descifrado (D-034).
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum HitVerdict {
    PrefixMismatch32 { plaintext_first_32: [u8; 32] },
    Pkcs7Mismatch { plaintext: Vec<u8> },
    Confirmed { plaintext: Vec<u8> },
}

#[derive(Debug, Error)]
pub enum DecryptError {
    #[error("longitud de clave no soportada: {0} (esperado 16, 24 o 32)")]
    BadKeyLen(usize),
    #[error("ciphertext no alineado a 16 B: {0}")]
    Unaligned(usize),
}

// ============================================================================
// AES-256-ECB — path activo post-D-029
// ============================================================================

/// Descifra `ct` con AES-256-ECB sin desempaquetar el padding (raw).
/// `ct.len()` debe ser múltiplo de 16. La clave tiene exactamente 32 B.
pub fn decrypt_ecb_raw(key: &[u8; 32], ct: &[u8]) -> Result<Vec<u8>, DecryptError> {
    if ct.len() % 16 != 0 {
        return Err(DecryptError::Unaligned(ct.len()));
    }
    type Dec = ecb::Decryptor<Aes256>;
    let mut buf = ct.to_vec();
    let dec = <Dec as KeyInit>::new(key.into());
    dec.decrypt_padded_mut::<NoPadding>(&mut buf)
        .expect("longitud múltiplo de 16, NoPadding nunca falla");
    Ok(buf)
}

/// Cifra `pt` con AES-256-ECB + PKCS7. Para fixtures sintéticos.
pub fn encrypt_ecb_pkcs7(key: &[u8; 32], pt: &[u8]) -> Vec<u8> {
    use cipher::block_padding::Pkcs7;
    type Enc = ecb::Encryptor<Aes256>;

    let pad_len = 16 - (pt.len() % 16);
    let mut buf = vec![0u8; pt.len() + pad_len];
    buf[..pt.len()].copy_from_slice(pt);

    let enc = <Enc as KeyInit>::new(key.into());
    let n = pt.len();
    enc.encrypt_padded_mut::<Pkcs7>(&mut buf, n)
        .expect("buffer suficiente");
    buf
}

/// Aplica los tres pasos de validación de hit sobre el ciphertext
/// completo en ECB.
pub fn validate_hit(key: &[u8; 32], ct: &[u8]) -> Result<HitVerdict, DecryptError> {
    let pt = decrypt_ecb_raw(key, ct)?;

    if pt.len() < 32 || pt[..32] != KNOWN_PREFIX_32[..] {
        let mut first_32 = [0u8; 32];
        let take = pt.len().min(32);
        first_32[..take].copy_from_slice(&pt[..take]);
        return Ok(HitVerdict::PrefixMismatch32 {
            plaintext_first_32: first_32,
        });
    }
    if !is_pkcs7_valid(&pt) {
        return Ok(HitVerdict::Pkcs7Mismatch { plaintext: pt });
    }
    Ok(HitVerdict::Confirmed { plaintext: pt })
}

/// Verifica si `plaintext` termina en padding PKCS7 válido para bloque 16.
pub fn is_pkcs7_valid(plaintext: &[u8]) -> bool {
    if plaintext.is_empty() || plaintext.len() % 16 != 0 {
        return false;
    }
    let last = *plaintext.last().expect("plaintext no vacío");
    if last == 0 || last > 16 {
        return false;
    }
    let pad_n = last as usize;
    let n = plaintext.len();
    plaintext[n - pad_n..].iter().all(|&b| b == last)
}

// ============================================================================
// CBC + PKCS7 — código LEGACY, solo para tests sintéticos
// ============================================================================

/// **Legacy**: AES-CBC raw decrypt para tests sintéticos pre-D-029.
/// Acepta claves de 16/24/32 B (AES-128/192/256). `#[doc(hidden)]`
/// porque NO es path activo, pero tiene que ser `pub` para que los
/// tests `tests/legacy_kdf.rs` y similares puedan importarlo.
#[doc(hidden)]
pub fn decrypt_cbc_raw(
    key: &[u8],
    iv: &[u8; 16],
    ct: &[u8],
) -> Result<Vec<u8>, DecryptError> {
    if ct.len() % 16 != 0 {
        return Err(DecryptError::Unaligned(ct.len()));
    }
    let mut buf = ct.to_vec();
    match key.len() {
        16 => {
            type Dec = CbcDecryptor<Aes128>;
            let dec = Dec::new(key.into(), iv.into());
            dec.decrypt_padded_mut::<NoPadding>(&mut buf)
                .expect("longitud múltiplo de 16, NoPadding nunca falla");
        }
        24 => {
            type Dec = CbcDecryptor<Aes192>;
            let dec = Dec::new(key.into(), iv.into());
            dec.decrypt_padded_mut::<NoPadding>(&mut buf)
                .expect("longitud múltiplo de 16, NoPadding nunca falla");
        }
        32 => {
            type Dec = CbcDecryptor<Aes256>;
            let dec = Dec::new(key.into(), iv.into());
            dec.decrypt_padded_mut::<NoPadding>(&mut buf)
                .expect("longitud múltiplo de 16, NoPadding nunca falla");
        }
        other => return Err(DecryptError::BadKeyLen(other)),
    }
    Ok(buf)
}

/// **Legacy**: cifra `pt` con AES-CBC + PKCS7 para tests sintéticos
/// pre-D-029. `#[doc(hidden)]` para no aparecer en la API documentada.
#[doc(hidden)]
pub fn encrypt_cbc_pkcs7(
    key: &[u8],
    iv: &[u8; 16],
    pt: &[u8],
) -> Result<Vec<u8>, DecryptError> {
    use cbc::Encryptor as CbcEncryptor;
    use cipher::block_padding::Pkcs7;

    let pad_len = 16 - (pt.len() % 16);
    let mut buf = vec![0u8; pt.len() + pad_len];
    buf[..pt.len()].copy_from_slice(pt);

    match key.len() {
        16 => {
            type Enc = CbcEncryptor<Aes128>;
            let enc = Enc::new(key.into(), iv.into());
            let n = pt.len();
            enc.encrypt_padded_mut::<Pkcs7>(&mut buf, n)
                .expect("buffer suficiente");
        }
        24 => {
            type Enc = CbcEncryptor<Aes192>;
            let enc = Enc::new(key.into(), iv.into());
            let n = pt.len();
            enc.encrypt_padded_mut::<Pkcs7>(&mut buf, n)
                .expect("buffer suficiente");
        }
        32 => {
            type Enc = CbcEncryptor<Aes256>;
            let enc = Enc::new(key.into(), iv.into());
            let n = pt.len();
            enc.encrypt_padded_mut::<Pkcs7>(&mut buf, n)
                .expect("buffer suficiente");
        }
        other => return Err(DecryptError::BadKeyLen(other)),
    }
    Ok(buf)
}

/// **Legacy**: re-exports controlados para que tests externos puedan
/// generar fixtures CBC sintéticos. NO se usa en el path activo.
pub mod legacy {
    pub use super::{decrypt_cbc_raw, encrypt_cbc_pkcs7};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkcs7_validates_simple_cases() {
        let mut buf = vec![0u8; 16];
        for b in buf.iter_mut() {
            *b = 0x10;
        }
        assert!(is_pkcs7_valid(&buf));

        let mut buf = vec![0u8; 16];
        buf[15] = 0x01;
        assert!(is_pkcs7_valid(&buf));

        let buf = vec![0u8; 16];
        assert!(!is_pkcs7_valid(&buf));

        let mut buf = vec![0u8; 16];
        buf[15] = 0x11;
        assert!(!is_pkcs7_valid(&buf));

        assert!(!is_pkcs7_valid(&[0u8; 15]));

        let mut buf = vec![0u8; 16];
        buf[14] = 0x02;
        buf[15] = 0x02;
        assert!(is_pkcs7_valid(&buf));

        let mut buf = vec![0u8; 16];
        buf[14] = 0x05;
        buf[15] = 0x02;
        assert!(!is_pkcs7_valid(&buf));
    }

    #[test]
    fn round_trip_aes256_ecb_pkcs7() {
        let key = [9u8; 32];
        let pt = b"Leonardo da Vinci\r\n\r\nLeonardo da Vinci plus more bytes.";
        let ct = encrypt_ecb_pkcs7(&key, pt);
        let decrypted = decrypt_ecb_raw(&key, &ct).unwrap();
        assert!(is_pkcs7_valid(&decrypted));
        assert!(decrypted.starts_with(pt));
    }

    #[test]
    fn validate_hit_confirmed_path_ecb() {
        let key = [42u8; 32];
        let mut pt = Vec::with_capacity(64);
        pt.extend_from_slice(KNOWN_PREFIX_32);
        pt.extend_from_slice(b"resto del mensaje hasta aqui.");
        let ct = encrypt_ecb_pkcs7(&key, &pt);

        match validate_hit(&key, &ct).unwrap() {
            HitVerdict::Confirmed { plaintext } => {
                assert!(plaintext.starts_with(KNOWN_PREFIX_32));
                assert!(is_pkcs7_valid(&plaintext));
            }
            other => panic!("esperaba Confirmed, obtenido {other:?}"),
        }
    }

    #[test]
    fn validate_hit_prefix_mismatch_32_ecb() {
        let key = [42u8; 32];
        let mut pt = Vec::with_capacity(64);
        pt.extend_from_slice(KNOWN_PREFIX_16);
        pt.extend_from_slice(b"NO COINCIDE EL R");
        pt.extend_from_slice(b"sigue el plaintext que sea para llenar bloques.");
        let ct = encrypt_ecb_pkcs7(&key, &pt);

        match validate_hit(&key, &ct).unwrap() {
            HitVerdict::PrefixMismatch32 { plaintext_first_32 } => {
                assert_eq!(&plaintext_first_32[..16], KNOWN_PREFIX_16);
                assert_ne!(&plaintext_first_32[16..32], &KNOWN_PREFIX_32[16..32]);
            }
            other => panic!("esperaba PrefixMismatch32, obtenido {other:?}"),
        }
    }

    // Sanity legacy: el path CBC sigue funcionando para tests externos.
    // Plaintext sintético arbitrario; no se valida contra `KNOWN_PREFIX_32`.
    // Lo dejamos con doble CRLF para que refleje el plaintext real (D-034).
    #[test]
    fn legacy_cbc_aes128_round_trip() {
        let key = [7u8; 16];
        let iv = [3u8; 16];
        let pt = b"Leonardo da Vinci\r\n\r\nLeonardo da Vinci es muy crack 1452.";
        let ct = encrypt_cbc_pkcs7(&key, &iv, pt).unwrap();
        let decrypted = decrypt_cbc_raw(&key, &iv, &ct).unwrap();
        assert!(is_pkcs7_valid(&decrypted));
        assert!(decrypted.starts_with(pt));
    }
}
