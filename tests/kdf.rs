//! Vectores de validación de la **única KDF activa** (`md5hex_full`)
//! contra `hashlib` de Python.
//!
//! Tras D-029 esta es la única KDF que importa para el barrido. Los
//! vectores de las otras 13 KDFs viven en `tests/legacy_kdf.rs`.

use quattro_crack::kdf::derive_md5hex;

/// Triplas `(password, hex_lowercase_de_python)`.
/// Generado con:
///   python3 -c 'import hashlib; \
///     [print(p, hashlib.md5(p.encode()).hexdigest()) \
///      for p in (".aAaabbbb1000.", ".zzzzuuuU1999.", ".bAioembl1452.")]'
const VECTORS_MD5HEX: &[(&str, &str)] = &[
    (".aAaabbbb1000.", "9ac15f8d5a92b3bc03a949212e6a6aed"),
    (".zzzzuuuU1999.", "9a3fbdba108501ac3f19bb7bee982974"),
    (".bAioembl1452.", "1289f8d7072cdede4f758cf77461c80a"),
];

#[test]
fn test_md5hex_active_kdf_matches_python() {
    for (pw, expected_md5_hex_lower) in VECTORS_MD5HEX {
        // `derive_md5hex` produce los 32 B ASCII del hex lowercase del MD5.
        // Esos 32 B, leídos como string ASCII, deben coincidir byte-a-byte
        // con el hexdigest de Python.
        let got = derive_md5hex(pw.as_bytes());
        assert_eq!(got.len(), 32);
        let got_str = std::str::from_utf8(&got).unwrap();
        assert_eq!(
            got_str, *expected_md5_hex_lower,
            "md5hex_full discrepa con Python para pw={pw:?}"
        );
    }
}

#[test]
fn test_md5hex_output_is_aes256_compatible() {
    // 32 B = exactamente la longitud que pide AES-256.
    let key = derive_md5hex(b".aAabbabb1000.");
    assert_eq!(key.len(), 32, "AES-256 requiere clave de 32 B");
    // Cada byte debe estar en el rango ASCII de hex lowercase.
    for &b in &key {
        assert!(
            b.is_ascii_digit() || (b'a'..=b'f').contains(&b),
            "byte {b:#04x} fuera del rango ASCII hex lowercase"
        );
    }
}
