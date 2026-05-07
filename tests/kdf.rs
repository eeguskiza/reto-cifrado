//! Tras D-035 el barrido **NO usa KDF activa**: la clave se construye
//! como `password.encode() + null pad` (passraw). Estos tests blindan
//! que el helper `build_key_passraw` produce las claves correctas.
//!
//! Los vectores de las 14 KDFs históricas (md5_utf8, md5hex_full, etc.)
//! viven en `tests/legacy_kdf.rs` para reproducibilidad y por si en el
//! futuro hay que volver a comparar.

use quattro_crack::reference::build_key_passraw;

#[test]
fn passraw_key_is_password_plus_null_padding() {
    let cases: &[(&[u8], &str)] = &[
        // Vector experimental D-035.
        (b".aAaaeeii1452.", "2e6141616165656969313435322e0000"),
        // Endpoints del espacio.
        (b".aAaabbbb1000.", "2e6141616162626262313030302e0000"),
        (b".zzzzuuuU1999.", "2e7a7a7a7a75757555313939392e0000"),
        // Mid-space.
        (b".bAioembl1452.", "2e6241696f656d626c313435322e0000"),
    ];
    for (pw, expected_hex) in cases {
        let key = build_key_passraw(pw);
        assert_eq!(key.len(), 16);
        assert_eq!(
            &key[..pw.len()],
            *pw,
            "primeros bytes deben ser el password"
        );
        for &b in &key[pw.len()..] {
            assert_eq!(b, 0u8, "bytes restantes deben ser null");
        }
        assert_eq!(hex::encode(key), *expected_hex);
    }
}

#[test]
fn passraw_key_is_aes128_compatible() {
    let key = build_key_passraw(b".aAabbabb1000.");
    assert_eq!(key.len(), 16, "AES-128 requiere clave de 16 B");
}
