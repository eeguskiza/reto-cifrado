//! `test_pkcs7_validation_required` y compañía: la validación en 3 pasos
//! del hit (prefijo-16 → prefijo-32 → PKCS7).

use quattro_crack::reference::{
    decrypt_cbc_raw, encrypt_cbc_pkcs7, validate_hit, HitVerdict, KNOWN_PREFIX_16,
    KNOWN_PREFIX_32,
};

const KEY128: [u8; 16] = [42u8; 16];
const KEY256: [u8; 32] = [9u8; 32];
const IV: [u8; 16] = [1u8; 16];

/// Construye un plaintext válido (1600 B) que empieza con `KNOWN_PREFIX_32`.
fn build_valid_plaintext() -> Vec<u8> {
    let mut pt = Vec::with_capacity(1600);
    pt.extend_from_slice(KNOWN_PREFIX_32);
    while pt.len() < 1584 {
        pt.push(b'X');
    }
    // 1584 bytes para que con padding PKCS7 lleguemos a 1600 (= 16 bytes de
    // padding 0x10).
    pt
}

#[test]
fn test_pkcs7_validation_required_aes128_correct_padding_yields_hit() {
    let pt = build_valid_plaintext();
    let ct = encrypt_cbc_pkcs7(&KEY128, &IV, &pt).unwrap();
    assert_eq!(ct.len() % 16, 0);

    match validate_hit(&KEY128, &IV, &ct).unwrap() {
        HitVerdict::Confirmed { plaintext } => {
            assert!(plaintext.starts_with(KNOWN_PREFIX_32));
            // Último byte debe ser 0x10 (16 bytes de padding).
            assert_eq!(*plaintext.last().unwrap(), 0x10);
        }
        other => panic!("esperaba Confirmed, obtenido {other:?}"),
    }
}

#[test]
fn test_pkcs7_validation_required_altered_padding_is_rejected() {
    // Cifra con padding correcto, luego *manipula* el último bloque para
    // romper el padding sin tocar los primeros 32 bytes del PT recuperado.
    //
    // Truco: descifrar manualmente el último bloque, alterar su PT y
    // re-cifrar el último bloque solo. Más simple: alteramos directamente
    // el último bloque del CT y luego comprobamos que la validación lo
    // rechaza.
    //
    // En CBC, alterar el último bloque del CT corrompe el último bloque
    // del PT (y no afecta a los anteriores). Como el padding está al final,
    // el primer prefijo de 32 B sigue intacto pero PKCS7 falla casi seguro.
    let pt = build_valid_plaintext();
    let mut ct = encrypt_cbc_pkcs7(&KEY128, &IV, &pt).unwrap();
    let n = ct.len();
    // Toggle un bit en el último bloque cifrado.
    ct[n - 1] ^= 0x80;

    let verdict = validate_hit(&KEY128, &IV, &ct).unwrap();
    match &verdict {
        HitVerdict::Pkcs7Mismatch { plaintext } => {
            // El prefijo de 32 B sigue intacto (alterar el último bloque
            // del CT no toca los anteriores en CBC).
            assert!(
                plaintext.starts_with(KNOWN_PREFIX_32),
                "el prefijo intacto demuestra el aislamiento del último bloque"
            );
        }
        HitVerdict::PrefixMismatch32 => {
            // Caso aceptable también si el bit-flip cae en una zona que
            // afecta al prefijo (no debería con esta semilla, pero es
            // defensivamente válido).
            panic!(
                "alterar el último bloque del CT NO debería afectar al prefijo \
                 de 32 B en CBC; algo está mal"
            );
        }
        other => panic!("esperaba Pkcs7Mismatch, obtenido {other:?}"),
    }
}

#[test]
fn test_pkcs7_validation_required_aes256_works() {
    let pt = build_valid_plaintext();
    let ct = encrypt_cbc_pkcs7(&KEY256, &IV, &pt).unwrap();
    match validate_hit(&KEY256, &IV, &ct).unwrap() {
        HitVerdict::Confirmed { plaintext } => {
            assert!(plaintext.starts_with(KNOWN_PREFIX_32));
        }
        other => panic!("esperaba Confirmed (AES-256), obtenido {other:?}"),
    }
}

#[test]
fn test_validate_hit_rejects_wrong_key() {
    // Cifra con K1, descifra con K2: el plaintext recuperado es ruido.
    let pt = build_valid_plaintext();
    let ct = encrypt_cbc_pkcs7(&KEY128, &IV, &pt).unwrap();

    let wrong_key = [0xAAu8; 16];
    let verdict = validate_hit(&wrong_key, &IV, &ct).unwrap();
    // Casi seguro PrefixMismatch32: el plaintext con clave equivocada
    // es ruido y muy difícilmente arranca con KNOWN_PREFIX_32.
    assert_eq!(verdict, HitVerdict::PrefixMismatch32);
}

#[test]
fn test_known_prefix_constants_are_consistent() {
    // El prefijo de 16 es exactamente los primeros 16 B del de 32.
    assert_eq!(&KNOWN_PREFIX_32[..16], &KNOWN_PREFIX_16[..]);
    // Y el prefijo de 32 es el documentado en la spec §2.2.
    assert_eq!(KNOWN_PREFIX_32, b"Leonardo da Vinci\r\nLeonardo da V");
}

#[test]
fn test_decrypt_cbc_raw_aligned_lengths() {
    // 1600 B alineado a 16 → OK.
    let pt = vec![0u8; 1600];
    let ct = encrypt_cbc_pkcs7(&KEY128, &IV, &pt).unwrap();
    // PT 1600 + PKCS7(16) = 1616 (un bloque entero de padding).
    assert_eq!(ct.len(), 1616);
    let recovered = decrypt_cbc_raw(&KEY128, &IV, &ct).unwrap();
    assert_eq!(recovered.len(), 1616);
    assert_eq!(&recovered[..1600], &pt[..]);
    // Los últimos 16 B son padding PKCS7 = 0x10 × 16.
    for b in &recovered[1600..] {
        assert_eq!(*b, 0x10);
    }
}
