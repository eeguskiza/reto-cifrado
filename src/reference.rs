//! Descifrado AES en CPU + validación de hits con la construcción
//! cifraronline.com (D-035).
//!
//! Construcción real verificada bit-exact contra pycryptodome:
//!
//! ```text
//! key       = password_bytes + b'\x00' * (16 - len(password_bytes))
//!             passraw + null pad. NUNCA MD5.
//! message   = plaintext_bytes + MD5(plaintext_bytes).hexdigest().encode()
//! padded    = message + b'\x00' * ((16 - len(message) % 16) % 16)
//! ciphertext = AES-128-ECB.encrypt(padded, key)
//! ```
//!
//! Validación de hit (path activo post-D-035):
//!   1. los primeros 16 B del plaintext coinciden con `KNOWN_PREFIX_16`
//!      (lo valida el kernel CUDA).
//!   2. los primeros 32 B coinciden con `KNOWN_PREFIX_32_LF` o
//!      `KNOWN_PREFIX_32_CRLF` (la línea en blanco intermedia puede ser
//!      `\n\n` o `\r\n\r\n` — la pizarra y el Notepad apuntaban a CRLF
//!      pero la prueba experimental desde el navegador dio `\n`; ambas
//!      hipótesis se validan).
//!   3. eliminados los bytes nulos finales (NULL padding), los últimos
//!      32 chars del plaintext recuperado son el MD5(hex) del resto.
//!      Si pasa (1)+(2) pero falla (3) → estadísticamente imposible
//!      bajo AES-128 con plaintext real (~2⁻¹²⁸): casi seguro un bug.
//!
//! Los helpers `decrypt_cbc_raw` / `encrypt_cbc_pkcs7` siguen `pub`
//! ocultos para los tests sintéticos legacy. NO se usan en el path
//! activo. Igual con `decrypt_ecb_raw` / `encrypt_ecb_pkcs7` (D-029
//! kernel legacy).

use aes::{Aes128, Aes192, Aes256};
use cbc::Decryptor as CbcDecryptor;
use cipher::{block_padding::NoPadding, BlockDecryptMut, BlockEncryptMut, KeyInit, KeyIvInit};
use md5::{Digest, Md5};
use thiserror::Error;

/// Primeros 16 bytes del plaintext (lo que valida el kernel CUDA).
pub const KNOWN_PREFIX_16: &[u8; 16] = b"Leonardo da Vinc";

/// Primeros 32 bytes del plaintext bajo la hipótesis de **LF simple**
/// (`\n\n` como salto entre líneas — observado en la prueba experimental
/// desde el navegador del usuario).
///
/// Layout: `Leonardo da Vinci` (17 B) + `\n\n` (2 B) + `Leonardo da V`
/// (13 B) = 32 B exactos.
pub const KNOWN_PREFIX_32_LF: &[u8; 32] = b"Leonardo da Vinci\n\nLeonardo da V";

/// Primeros 32 bytes del plaintext bajo la hipótesis de **CRLF**
/// (`\r\n\r\n` como salto entre líneas — observado en la pizarra del
/// autor y en la barra de estado del Notepad).
///
/// Layout: `Leonardo da Vinci` (17 B) + `\r\n\r\n` (4 B) + `Leonardo da`
/// (11 B) = 32 B exactos.
pub const KNOWN_PREFIX_32_CRLF: &[u8; 32] = b"Leonardo da Vinci\r\n\r\nLeonardo da";

/// Salto de línea detectado al validar un hit. Se reporta en el evento
/// `HitConfirmed` para diagnóstico (la pizarra dice CRLF, la prueba dio
/// LF — saber cuál cuadra es información real).
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum LineEnding {
    Lf,
    Crlf,
}

impl LineEnding {
    pub fn as_str(self) -> &'static str {
        match self {
            LineEnding::Lf => "LF",
            LineEnding::Crlf => "CRLF",
        }
    }
}

/// Resultado de validar una candidata frente al ciphertext objetivo.
///
/// `PrefixMismatch32` lleva los primeros 32 B del plaintext descifrado
/// para que el runner pueda registrarlos en el log con `info!` sin
/// recalcular el descifrado (D-034 vigente bajo D-035).
///
/// `Md5MismatchCritical` aparece cuando los primeros 32 B coinciden
/// con una de las dos variantes de prefijo pero el MD5(plaintext_clean)
/// final NO coincide con los 32 chars finales del plaintext: es
/// estadísticamente imposible bajo AES real, casi seguro indica un bug.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum HitVerdict {
    PrefixMismatch32 {
        plaintext_first_32: [u8; 32],
    },
    Md5MismatchCritical {
        plaintext: Vec<u8>,
        embedded_md5_hex: Vec<u8>,
        computed_md5_hex: Vec<u8>,
        line_ending: LineEnding,
    },
    Confirmed {
        plaintext: Vec<u8>,
        line_ending: LineEnding,
    },
}

/// Errores del path AES.
#[derive(Debug, Error)]
pub enum DecryptError {
    /// Solo aplica a los helpers legacy CBC; el path activo D-035
    /// requiere clave de 16 B exactos (AES-128).
    #[error("longitud de clave no soportada: {0} (esperado 16, 24 o 32)")]
    BadKeyLen(usize),
    /// El ciphertext no es múltiplo de 16 B, no se puede dividir en
    /// bloques AES.
    #[error("ciphertext no alineado a 16 B: {0}")]
    Unaligned(usize),
}

// ============================================================================
// AES-128-ECB — path activo post-D-035 (cifraronline.com construction)
// ============================================================================

/// Construye la clave AES-128 a partir del password ASCII vía la regla
/// de cifraronline: `password.encode() + b'\x00' * (16 - len)`.
/// Para passwords del espacio (14 B siempre) los últimos 2 B son ceros.
///
/// # Panics
/// Si `password.len() > 16`. El espacio del reto siempre da 14 B.
pub fn build_key_passraw(password: &[u8]) -> [u8; 16] {
    assert!(
        password.len() <= 16,
        "password de {} B no cabe en clave AES-128 de 16 B",
        password.len()
    );
    let mut key = [0u8; 16];
    key[..password.len()].copy_from_slice(password);
    key
}

/// Construye el `message` cifraronline a partir del plaintext:
/// `plaintext + MD5(plaintext).hexdigest().encode()`. El resultado tiene
/// longitud `plaintext.len() + 32` (sin padding aún).
pub fn build_message(plaintext: &[u8]) -> Vec<u8> {
    let raw = md5_digest(plaintext);
    let hex_str = hex::encode(raw);
    let mut msg = Vec::with_capacity(plaintext.len() + 32);
    msg.extend_from_slice(plaintext);
    msg.extend_from_slice(hex_str.as_bytes());
    msg
}

/// Aplica null padding hasta la siguiente frontera de 16 B.
/// Si la longitud ya es múltiplo de 16, no añade nada (consistente con
/// `(16 - len % 16) % 16`, NO con PKCS7).
pub fn null_pad_to_block(message: &[u8]) -> Vec<u8> {
    let pad = (16 - message.len() % 16) % 16;
    let mut out = Vec::with_capacity(message.len() + pad);
    out.extend_from_slice(message);
    out.extend(std::iter::repeat(0u8).take(pad));
    out
}

/// Descifra `ct` con AES-128-ECB sin desempaquetar el padding (raw).
/// `ct.len()` debe ser múltiplo de 16. La clave tiene exactamente 16 B.
pub fn decrypt_aes128_ecb_raw(key: &[u8; 16], ct: &[u8]) -> Result<Vec<u8>, DecryptError> {
    if ct.len() % 16 != 0 {
        return Err(DecryptError::Unaligned(ct.len()));
    }
    type Dec = ecb::Decryptor<Aes128>;
    let mut buf = ct.to_vec();
    let dec = <Dec as KeyInit>::new(key.into());
    dec.decrypt_padded_mut::<NoPadding>(&mut buf)
        .expect("longitud múltiplo de 16, NoPadding nunca falla");
    Ok(buf)
}

/// Cifra `padded_message` (debe ser múltiplo de 16 B; null pad ya
/// aplicado) con AES-128-ECB. Para fixtures sintéticos.
pub fn encrypt_aes128_ecb(key: &[u8; 16], padded_message: &[u8]) -> Vec<u8> {
    assert_eq!(
        padded_message.len() % 16,
        0,
        "padded_message debe ser múltiplo de 16 B antes de cifrar"
    );
    type Enc = ecb::Encryptor<Aes128>;
    let mut buf = padded_message.to_vec();
    let enc = <Enc as KeyInit>::new(key.into());
    let n = padded_message.len();
    enc.encrypt_padded_mut::<NoPadding>(&mut buf, n)
        .expect("buffer suficiente, alineado");
    buf
}

/// Helper end-to-end: cifra con la construcción cifraronline completa
/// (build_message + null_pad + encrypt). Devuelve el ciphertext.
pub fn encrypt_cifraronline(key: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    let msg = build_message(plaintext);
    let padded = null_pad_to_block(&msg);
    encrypt_aes128_ecb(key, &padded)
}

/// Aplica los tres pasos de validación de hit sobre el ciphertext
/// completo en AES-128-ECB con la construcción cifraronline.
pub fn validate_hit(key: &[u8; 16], ct: &[u8]) -> Result<HitVerdict, DecryptError> {
    let pt = decrypt_aes128_ecb_raw(key, ct)?;

    // Paso 2: prefijo-32 — probar LF y luego CRLF.
    let line_ending = if pt.len() >= 32 && pt[..32] == KNOWN_PREFIX_32_LF[..] {
        LineEnding::Lf
    } else if pt.len() >= 32 && pt[..32] == KNOWN_PREFIX_32_CRLF[..] {
        LineEnding::Crlf
    } else {
        let mut first_32 = [0u8; 32];
        let take = pt.len().min(32);
        first_32[..take].copy_from_slice(&pt[..take]);
        return Ok(HitVerdict::PrefixMismatch32 {
            plaintext_first_32: first_32,
        });
    };

    // Paso 3: separar plaintext + MD5(hex) tras strippear NULL padding.
    let trimmed_end = pt
        .iter()
        .rposition(|&b| b != 0u8)
        .map(|i| i + 1)
        .unwrap_or(0);
    let stripped = &pt[..trimmed_end];

    if stripped.len() < 32 {
        // No hay margen para los 32 chars de MD5 → mismatch crítico.
        return Ok(HitVerdict::Md5MismatchCritical {
            plaintext: pt.clone(),
            embedded_md5_hex: stripped.to_vec(),
            computed_md5_hex: Vec::new(),
            line_ending,
        });
    }

    let split = stripped.len() - 32;
    let plaintext_clean = &stripped[..split];
    let embedded_md5_hex = &stripped[split..];

    let raw = md5_digest(plaintext_clean);
    let computed = hex::encode(raw).into_bytes();

    if computed.as_slice() == embedded_md5_hex {
        Ok(HitVerdict::Confirmed {
            plaintext: pt,
            line_ending,
        })
    } else {
        Ok(HitVerdict::Md5MismatchCritical {
            plaintext: pt.clone(),
            embedded_md5_hex: embedded_md5_hex.to_vec(),
            computed_md5_hex: computed,
            line_ending,
        })
    }
}

fn md5_digest(data: &[u8]) -> [u8; 16] {
    let mut h = Md5::new();
    h.update(data);
    h.finalize().into()
}

// ============================================================================
// LEGACY — código de tests sintéticos pre-D-035
// ============================================================================
// `decrypt_ecb_raw` / `encrypt_ecb_pkcs7` (AES-256, kernel D-029) y
// `decrypt_cbc_raw` / `encrypt_cbc_pkcs7` (AES-128/192/256 CBC, KDFs
// pre-D-029) se conservan ocultos para que los tests legacy puedan
// seguir generando fixtures sintéticos. NO se usan en el path activo.

/// **Legacy D-029**: AES-256-ECB raw decrypt. `#[doc(hidden)]` para que
/// no aparezca en la API documentada del path activo.
#[doc(hidden)]
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

/// **Legacy D-029**: AES-256-ECB + PKCS7 encrypt para fixtures sintéticos.
#[doc(hidden)]
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

/// **Legacy pre-D-029**: AES-CBC raw decrypt para tests sintéticos.
#[doc(hidden)]
pub fn decrypt_cbc_raw(key: &[u8], iv: &[u8; 16], ct: &[u8]) -> Result<Vec<u8>, DecryptError> {
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

/// **Legacy pre-D-029**: AES-CBC + PKCS7 encrypt para tests sintéticos.
#[doc(hidden)]
pub fn encrypt_cbc_pkcs7(key: &[u8], iv: &[u8; 16], pt: &[u8]) -> Result<Vec<u8>, DecryptError> {
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

/// **Legacy**: re-exports controlados para tests sintéticos.
pub mod legacy {
    pub use super::{decrypt_cbc_raw, decrypt_ecb_raw, encrypt_cbc_pkcs7, encrypt_ecb_pkcs7};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_prefixes_have_expected_layout() {
        assert_eq!(KNOWN_PREFIX_32_LF.len(), 32);
        assert_eq!(KNOWN_PREFIX_32_CRLF.len(), 32);
        assert_eq!(&KNOWN_PREFIX_32_LF[..16], KNOWN_PREFIX_16);
        assert_eq!(&KNOWN_PREFIX_32_CRLF[..16], KNOWN_PREFIX_16);
        assert_eq!(&KNOWN_PREFIX_32_LF[..17], b"Leonardo da Vinci");
        assert_eq!(&KNOWN_PREFIX_32_LF[17..19], b"\n\n");
        assert_eq!(&KNOWN_PREFIX_32_LF[19..32], b"Leonardo da V");
        assert_eq!(&KNOWN_PREFIX_32_CRLF[..17], b"Leonardo da Vinci");
        assert_eq!(&KNOWN_PREFIX_32_CRLF[17..21], b"\r\n\r\n");
        assert_eq!(&KNOWN_PREFIX_32_CRLF[21..32], b"Leonardo da");
    }

    #[test]
    fn passraw_key_pads_with_nulls() {
        let key = build_key_passraw(b".aAaaeeii1452.");
        assert_eq!(key.len(), 16);
        assert_eq!(&key[..14], b".aAaaeeii1452.");
        assert_eq!(key[14], 0);
        assert_eq!(key[15], 0);
    }

    #[test]
    fn round_trip_aes128_passraw_with_md5_check() {
        let key = build_key_passraw(b".aAaaeeii1452.");
        let pt = b"Leonardo da Vinci\n\nLeonardo da V test";
        let ct = encrypt_cifraronline(&key, pt);
        assert_eq!(ct.len() % 16, 0);
        match validate_hit(&key, &ct).unwrap() {
            HitVerdict::Confirmed {
                plaintext,
                line_ending,
            } => {
                assert_eq!(line_ending, LineEnding::Lf);
                // El plaintext recuperado contiene el original + md5_hex + null pad.
                assert!(plaintext.starts_with(pt));
            }
            other => panic!("esperaba Confirmed, obtuve {other:?}"),
        }
    }

    #[test]
    fn validate_hit_detects_lf_variant() {
        let key = build_key_passraw(b".aAabbabb1000.");
        let mut pt = Vec::new();
        pt.extend_from_slice(KNOWN_PREFIX_32_LF);
        pt.extend_from_slice(b" rest of the message");
        let ct = encrypt_cifraronline(&key, &pt);
        match validate_hit(&key, &ct).unwrap() {
            HitVerdict::Confirmed { line_ending, .. } => {
                assert_eq!(line_ending, LineEnding::Lf);
            }
            other => panic!("esperaba Confirmed (LF), obtuve {other:?}"),
        }
    }

    #[test]
    fn validate_hit_detects_crlf_variant() {
        let key = build_key_passraw(b".aAabbabb1000.");
        let mut pt = Vec::new();
        pt.extend_from_slice(KNOWN_PREFIX_32_CRLF);
        pt.extend_from_slice(b" rest of the message");
        let ct = encrypt_cifraronline(&key, &pt);
        match validate_hit(&key, &ct).unwrap() {
            HitVerdict::Confirmed { line_ending, .. } => {
                assert_eq!(line_ending, LineEnding::Crlf);
            }
            other => panic!("esperaba Confirmed (CRLF), obtuve {other:?}"),
        }
    }

    #[test]
    fn validate_hit_prefix_mismatch_when_first_32_diverges() {
        let key = build_key_passraw(b".aAabbabb1000.");
        let mut pt = Vec::new();
        pt.extend_from_slice(KNOWN_PREFIX_16);
        pt.extend_from_slice(b"NO_COINCIDE_32B!"); // 16 B distintos al prefijo-32
        pt.extend_from_slice(b" rest of message");
        let ct = encrypt_cifraronline(&key, &pt);
        match validate_hit(&key, &ct).unwrap() {
            HitVerdict::PrefixMismatch32 { plaintext_first_32 } => {
                assert_eq!(&plaintext_first_32[..16], KNOWN_PREFIX_16);
                assert_ne!(&plaintext_first_32[16..32], &KNOWN_PREFIX_32_LF[16..32]);
                assert_ne!(&plaintext_first_32[16..32], &KNOWN_PREFIX_32_CRLF[16..32]);
            }
            other => panic!("esperaba PrefixMismatch32, obtuve {other:?}"),
        }
    }

    #[test]
    fn validate_hit_md5_mismatch_when_integrity_corrupted() {
        let key = build_key_passraw(b".aAabbabb1000.");
        let mut pt = Vec::new();
        pt.extend_from_slice(KNOWN_PREFIX_32_LF);
        pt.extend_from_slice(b" message body for md5 corruption");
        // Construye message + md5_hex + null pad MANUALMENTE y corrompe los
        // últimos chars del MD5 hex (antes del padding) para forzar mismatch.
        let mut msg = build_message(&pt);
        // Corrompe el último byte del md5_hex (indices [-32..]). El último
        // byte del message está en msg.len()-1.
        let last = msg.len() - 1;
        msg[last] = if msg[last] == b'a' { b'b' } else { b'a' };
        let padded = null_pad_to_block(&msg);
        let ct = encrypt_aes128_ecb(&key, &padded);

        match validate_hit(&key, &ct).unwrap() {
            HitVerdict::Md5MismatchCritical {
                embedded_md5_hex,
                computed_md5_hex,
                line_ending,
                ..
            } => {
                assert_eq!(line_ending, LineEnding::Lf);
                assert_ne!(embedded_md5_hex, computed_md5_hex);
                assert_eq!(embedded_md5_hex.len(), 32);
                assert_eq!(computed_md5_hex.len(), 32);
            }
            other => panic!("esperaba Md5MismatchCritical, obtuve {other:?}"),
        }
    }

    // Sanity legacy: el path CBC sigue funcionando para tests externos.
    #[test]
    fn legacy_cbc_aes128_round_trip() {
        let key = [7u8; 16];
        let iv = [3u8; 16];
        let pt = b"Leonardo da Vinci\r\n\r\nLeonardo da Vinci es muy crack 1452.";
        let ct = encrypt_cbc_pkcs7(&key, &iv, pt).unwrap();
        let decrypted = decrypt_cbc_raw(&key, &iv, &ct).unwrap();
        assert!(decrypted.starts_with(pt));
    }
}
