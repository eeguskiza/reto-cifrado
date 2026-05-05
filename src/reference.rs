//! Descifrado AES-CBC en CPU + validación de hits con tres pasos.
//!
//! Una clave candidata da un **hit confirmado** solo si pasa:
//!
//!   1. los primeros 16 bytes del plaintext coinciden con `KNOWN_PREFIX_16`
//!   2. los primeros 32 bytes coinciden con `KNOWN_PREFIX_32`
//!   3. el último bloque tiene padding PKCS7 válido
//!
//! El kernel valida (1) en GPU. La CPU valida (2) y (3). Si (1)+(2)
//! pasan pero (3) falla, eso es **estadísticamente imposible** (~2⁻¹³⁰)
//! bajo CBC con padding PKCS7 real, así que indica casi seguro un bug
//! en el kernel o en la KDF: se devuelve `HitVerdict::Pkcs7Mismatch`
//! para que el runner lo trate como evento crítico (abort + warning).
//!
//! Ver `DECISIONS.md` D-007.

use aes::{Aes128, Aes192, Aes256};
use cbc::Decryptor;
use cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};
use thiserror::Error;

/// Primeros 16 bytes del plaintext (lo que valida el kernel).
pub const KNOWN_PREFIX_16: &[u8; 16] = b"Leonardo da Vinc";
/// Primeros 32 bytes del plaintext (lo que valida la CPU sobre los hits).
pub const KNOWN_PREFIX_32: &[u8; 32] = b"Leonardo da Vinci\r\nLeonardo da V";

/// Resultado de validar una candidata frente al ciphertext objetivo.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum HitVerdict {
    /// El kernel reportó match en los 16 B, pero la CPU descarta en los 32 B.
    /// Falso positivo esperado en proporción ~2⁻¹²⁸: ignorar y seguir.
    PrefixMismatch32,
    /// 32 B del prefijo coinciden pero el padding PKCS7 del último bloque
    /// es inválido. Estadísticamente imposible bajo CBC+PKCS7 real:
    /// indica bug. El runner debe abortar y avisar.
    Pkcs7Mismatch { plaintext: Vec<u8> },
    /// Triple validación pasa: clave correcta del reto.
    Confirmed { plaintext: Vec<u8> },
}

#[derive(Debug, Error)]
pub enum DecryptError {
    #[error("longitud de clave no soportada: {0} (esperado 16, 24 o 32)")]
    BadKeyLen(usize),
    #[error("ciphertext no alineado a 16 B: {0}")]
    Unaligned(usize),
}

/// Descifra `ct` con AES-CBC sin desempaquetar el padding (raw).
///
/// El caller decide después si el padding es válido. `key.len()` debe ser
/// 16 (AES-128) o 32 (AES-256). `ct.len()` debe ser múltiplo de 16.
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
            type Dec = Decryptor<Aes128>;
            let dec = Dec::new(key.into(), iv.into());
            dec.decrypt_padded_mut::<NoPadding>(&mut buf)
                .expect("longitud múltiplo de 16, NoPadding nunca falla");
        }
        24 => {
            type Dec = Decryptor<Aes192>;
            let dec = Dec::new(key.into(), iv.into());
            dec.decrypt_padded_mut::<NoPadding>(&mut buf)
                .expect("longitud múltiplo de 16, NoPadding nunca falla");
        }
        32 => {
            type Dec = Decryptor<Aes256>;
            let dec = Dec::new(key.into(), iv.into());
            dec.decrypt_padded_mut::<NoPadding>(&mut buf)
                .expect("longitud múltiplo de 16, NoPadding nunca falla");
        }
        other => return Err(DecryptError::BadKeyLen(other)),
    }
    Ok(buf)
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

/// Aplica los tres pasos de validación de hit.
pub fn validate_hit(key: &[u8], iv: &[u8; 16], ct: &[u8]) -> Result<HitVerdict, DecryptError> {
    let pt = decrypt_cbc_raw(key, iv, ct)?;

    // 1+2. Prefijo. El paso (1) ya lo hizo el kernel; aquí lo replicamos
    // cómodamente como parte del check de 32 B (si los 32 fallan, los 16
    // pueden seguir coincidiendo y aún así descartamos).
    if pt.len() < 32 || pt[..32] != KNOWN_PREFIX_32[..] {
        return Ok(HitVerdict::PrefixMismatch32);
    }
    // 3. PKCS7
    if !is_pkcs7_valid(&pt) {
        return Ok(HitVerdict::Pkcs7Mismatch { plaintext: pt });
    }
    Ok(HitVerdict::Confirmed { plaintext: pt })
}

/// Helper de tests / dev: cifra `pt` con AES-CBC + PKCS7.
///
/// Disponible como `pub` para que la fixture de fase 4 (ciphertext sintético
/// con clave conocida) lo use desde tests de integración.
pub fn encrypt_cbc_pkcs7(key: &[u8], iv: &[u8; 16], pt: &[u8]) -> Result<Vec<u8>, DecryptError> {
    use aes::cipher::BlockEncryptMut;
    use cbc::Encryptor;
    use cipher::block_padding::Pkcs7;

    let pad_len = 16 - (pt.len() % 16);
    let mut buf = vec![0u8; pt.len() + pad_len];
    buf[..pt.len()].copy_from_slice(pt);

    match key.len() {
        16 => {
            type Enc = Encryptor<Aes128>;
            let enc = Enc::new(key.into(), iv.into());
            let n = pt.len();
            enc.encrypt_padded_mut::<Pkcs7>(&mut buf, n)
                .expect("buffer suficiente");
        }
        24 => {
            type Enc = Encryptor<Aes192>;
            let enc = Enc::new(key.into(), iv.into());
            let n = pt.len();
            enc.encrypt_padded_mut::<Pkcs7>(&mut buf, n)
                .expect("buffer suficiente");
        }
        32 => {
            type Enc = Encryptor<Aes256>;
            let enc = Enc::new(key.into(), iv.into());
            let n = pt.len();
            enc.encrypt_padded_mut::<Pkcs7>(&mut buf, n)
                .expect("buffer suficiente");
        }
        other => return Err(DecryptError::BadKeyLen(other)),
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkcs7_validates_simple_cases() {
        // Bloque entero de relleno (PT vacío, todo padding 0x10).
        let mut buf = vec![0u8; 16];
        for b in buf.iter_mut() {
            *b = 0x10;
        }
        assert!(is_pkcs7_valid(&buf));

        // Padding 0x01: último byte es 0x01, lo demás cualquier cosa.
        let mut buf = vec![0u8; 16];
        buf[15] = 0x01;
        assert!(is_pkcs7_valid(&buf));

        // Padding inválido: 0x00.
        let buf = vec![0u8; 16];
        assert!(!is_pkcs7_valid(&buf));

        // Padding inválido: > 16.
        let mut buf = vec![0u8; 16];
        buf[15] = 0x11;
        assert!(!is_pkcs7_valid(&buf));

        // Tamaño no múltiplo de 16.
        assert!(!is_pkcs7_valid(&[0u8; 15]));

        // Bytes intermedios no coinciden con el contador.
        let mut buf = vec![0u8; 16];
        buf[14] = 0x02; // mal: debería ser 0x02 también el 13
        buf[15] = 0x02;
        // buf[14]=0x02, buf[15]=0x02 -> n=2, los últimos 2 bytes son [0x02,0x02] ✓
        assert!(is_pkcs7_valid(&buf));

        let mut buf = vec![0u8; 16];
        buf[14] = 0x05;
        buf[15] = 0x02;
        // n=2, los últimos 2 son [0x05, 0x02] ≠ 0x02
        assert!(!is_pkcs7_valid(&buf));
    }

    #[test]
    fn round_trip_aes128_cbc_pkcs7() {
        let key = [7u8; 16];
        let iv = [3u8; 16];
        let pt = b"Leonardo da Vinci\r\nLeonardo da Vinci es muy crack 1452.";
        let ct = encrypt_cbc_pkcs7(&key, &iv, pt).unwrap();
        let decrypted = decrypt_cbc_raw(&key, &iv, &ct).unwrap();
        assert!(is_pkcs7_valid(&decrypted));
        assert!(decrypted.starts_with(pt));
    }

    #[test]
    fn round_trip_aes256_cbc_pkcs7() {
        let key = [9u8; 32];
        let iv = [4u8; 16];
        let pt = b"Leonardo da Vinci\r\nLeonardo da V plus more bytes here.";
        let ct = encrypt_cbc_pkcs7(&key, &iv, pt).unwrap();
        let decrypted = decrypt_cbc_raw(&key, &iv, &ct).unwrap();
        assert!(is_pkcs7_valid(&decrypted));
        assert!(decrypted.starts_with(pt));
    }

    #[test]
    fn validate_hit_confirmed_path() {
        let key = [42u8; 16];
        let iv = [1u8; 16];
        // Plaintext que empieza con KNOWN_PREFIX_32.
        let mut pt = Vec::with_capacity(64);
        pt.extend_from_slice(KNOWN_PREFIX_32);
        pt.extend_from_slice(b"resto del mensaje hasta aqui.");
        let ct = encrypt_cbc_pkcs7(&key, &iv, &pt).unwrap();

        match validate_hit(&key, &iv, &ct).unwrap() {
            HitVerdict::Confirmed { plaintext } => {
                assert!(plaintext.starts_with(KNOWN_PREFIX_32));
                assert!(is_pkcs7_valid(&plaintext));
            }
            other => panic!("esperaba Confirmed, obtenido {other:?}"),
        }
    }

    #[test]
    fn validate_hit_prefix_mismatch_32() {
        let key = [42u8; 16];
        let iv = [1u8; 16];
        // 16 B coinciden, 32 B no.
        let mut pt = Vec::with_capacity(64);
        pt.extend_from_slice(KNOWN_PREFIX_16); // 16 B coincidentes
        pt.extend_from_slice(b"NO COINCIDE EL R"); // 16 B distintos al esperado
        pt.extend_from_slice(b"sigue el plaintext que sea para llenar bloques.");
        let ct = encrypt_cbc_pkcs7(&key, &iv, &pt).unwrap();

        match validate_hit(&key, &iv, &ct).unwrap() {
            HitVerdict::PrefixMismatch32 => {}
            other => panic!("esperaba PrefixMismatch32, obtenido {other:?}"),
        }
    }
}
